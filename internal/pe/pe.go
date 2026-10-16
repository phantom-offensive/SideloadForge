package pe

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

// ImportedLibraries returns the unique lowercase DLL names imported by a PE file,
// including delay-loaded DLLs.
func ImportedLibraries(path string) ([]string, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[string]bool{}
	var out []string

	// ImportedSymbols is more reliable than ImportedLibraries for some PEs
	// (ImportedLibraries can return an empty slice). Each entry is "Symbol:DLL".
	if syms, err := f.ImportedSymbols(); err == nil && len(syms) > 0 {
		for _, s := range syms {
			i := strings.LastIndex(s, ":")
			if i < 0 || i+1 >= len(s) {
				continue
			}
			dll := strings.ToLower(s[i+1:])
			if !seen[dll] {
				seen[dll] = true
				out = append(out, dll)
			}
		}
	} else {
		libs, err := f.ImportedLibraries()
		if err != nil {
			return nil, err
		}
		for _, l := range libs {
			l = strings.ToLower(l)
			if !seen[l] {
				seen[l] = true
				out = append(out, l)
			}
		}
	}

	// Delay-loaded DLLs are also sideload candidates.
	if delay, err := DelayImportedLibraries(path); err == nil {
		for _, d := range delay {
			if !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}

	return out, nil
}

// DelayImportedLibraries returns the lowercase DLL names referenced by the PE
// delay-load import directory (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT).
func DelayImportedLibraries(path string) ([]string, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var dataDir [16]pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dataDir = oh.DataDirectory
	case *pe.OptionalHeader64:
		dataDir = oh.DataDirectory
	default:
		return nil, fmt.Errorf("unsupported PE optional header")
	}

	delayDir := dataDir[13] // IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
	if delayDir.VirtualAddress == 0 || delayDir.Size == 0 {
		return nil, nil
	}

	off, err := rvaToOffset(f, delayDir.VirtualAddress)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var out []string

	// ImgDelayDescr is 32 bytes (0x20). Iterate until the all-zero terminator.
	for i := 0; ; i++ {
		descOff := uint32(int(off) + i*0x20)
		if int(descOff)+0x20 > len(raw) {
			break
		}
		attrs := binary.LittleEndian.Uint32(raw[descOff : descOff+4])
		nameRVA := binary.LittleEndian.Uint32(raw[descOff+4 : descOff+8])
		if attrs == 0 && nameRVA == 0 {
			break
		}
		name, err := readCString(raw, nameRVA, f)
		if err != nil || name == "" {
			continue
		}
		name = strings.ToLower(name)
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out, nil
}

// AuthenticodeSignature reports whether the PE has a certificate table
// (IMAGE_DIRECTORY_ENTRY_SECURITY) and its size in bytes.
func AuthenticodeSignature(path string) (signed bool, size int, err error) {
	f, err := pe.Open(path)
	if err != nil {
		return false, 0, err
	}
	defer f.Close()

	var dataDir [16]pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dataDir = oh.DataDirectory
	case *pe.OptionalHeader64:
		dataDir = oh.DataDirectory
	default:
		return false, 0, fmt.Errorf("unsupported PE optional header")
	}

	sec := dataDir[4] // IMAGE_DIRECTORY_ENTRY_SECURITY
	if sec.VirtualAddress == 0 && sec.Size == 0 {
		return false, 0, nil
	}
	return true, int(sec.Size), nil
}

// Export is a single export from a DLL. If ByOrdinal is true, the export has
// no name and is identified by Ordinal.
type Export struct {
	Name      string
	Ordinal   uint32
	ByOrdinal bool
}

// Exports parses the PE export table and returns the named exports.
func Exports(path string) ([]Export, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var dataDir [16]pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dataDir = oh.DataDirectory
	case *pe.OptionalHeader64:
		dataDir = oh.DataDirectory
	default:
		return nil, fmt.Errorf("unsupported PE optional header")
	}

	exportDir := dataDir[0] // IMAGE_DIRECTORY_ENTRY_EXPORT
	if exportDir.VirtualAddress == 0 || exportDir.Size == 0 {
		return nil, fmt.Errorf("no export table")
	}

	off, err := rvaToOffset(f, exportDir.VirtualAddress)
	if err != nil {
		return nil, err
	}
	if int(off)+0x28 > len(raw) {
		return nil, fmt.Errorf("export directory out of file bounds")
	}

	dir := raw[off : off+0x28]
	base := binary.LittleEndian.Uint32(dir[0x10:0x14])
	numberOfFunctions := binary.LittleEndian.Uint32(dir[0x14:0x18])
	numberOfNames := binary.LittleEndian.Uint32(dir[0x18:0x1C])
	addrOfFunctions := binary.LittleEndian.Uint32(dir[0x1C:0x20])
	addrOfNames := binary.LittleEndian.Uint32(dir[0x20:0x24])
	addrOfNameOrdinals := binary.LittleEndian.Uint32(dir[0x24:0x28])

	nameOff, err := rvaToOffset(f, addrOfNames)
	if err != nil {
		return nil, err
	}
	ordOff, err := rvaToOffset(f, addrOfNameOrdinals)
	if err != nil {
		return nil, err
	}

	// First pass: mark which function indices are referenced by a name.
	named := map[uint32]bool{}
	for i := uint32(0); i < numberOfNames; i++ {
		if ordIdx, err := readUint16(raw, ordOff+i*2); err == nil {
			named[uint32(ordIdx)] = true
		}
	}

	var exports []Export
	for i := uint32(0); i < numberOfNames; i++ {
		nameRVA, err := readUint32(raw, nameOff+i*4)
		if err != nil {
			continue
		}
		ordIdx, err := readUint16(raw, ordOff+i*2)
		if err != nil {
			continue
		}
		name, err := readCString(raw, nameRVA, f)
		if err != nil || name == "" {
			continue
		}
		exports = append(exports, Export{Name: name, Ordinal: base + uint32(ordIdx)})
	}

	// Second pass: ordinal-only exports (functions with no name).
	if numberOfFunctions > 0 {
		funcOff, err := rvaToOffset(f, addrOfFunctions)
		if err == nil {
			for i := uint32(0); i < numberOfFunctions; i++ {
				if named[i] {
					continue
				}
				funcRVA, err := readUint32(raw, funcOff+i*4)
				if err != nil || funcRVA == 0 {
					continue
				}
				// Skip forwarders: their RVA points into the export directory.
				if funcRVA >= exportDir.VirtualAddress && funcRVA < exportDir.VirtualAddress+exportDir.Size {
					continue
				}
				exports = append(exports, Export{Ordinal: base + i, ByOrdinal: true})
			}
		}
	}

	return exports, nil
}

func rvaToOffset(f *pe.File, rva uint32) (uint32, error) {
	for _, s := range f.Sections {
		start := s.VirtualAddress
		size := s.VirtualSize
		if size == 0 {
			size = s.Size
		}
		if rva >= start && rva < start+size {
			return s.Offset + (rva - start), nil
		}
	}
	return 0, fmt.Errorf("RVA 0x%x not mapped to any section", rva)
}

func readUint32(raw []byte, off uint32) (uint32, error) {
	if int(off)+4 > len(raw) {
		return 0, fmt.Errorf("read uint32 out of bounds")
	}
	return binary.LittleEndian.Uint32(raw[off : off+4]), nil
}

func readUint16(raw []byte, off uint32) (uint16, error) {
	if int(off)+2 > len(raw) {
		return 0, fmt.Errorf("read uint16 out of bounds")
	}
	return binary.LittleEndian.Uint16(raw[off : off+2]), nil
}

func readCString(raw []byte, rva uint32, f *pe.File) (string, error) {
	off, err := rvaToOffset(f, rva)
	if err != nil {
		return "", err
	}
	if int(off) >= len(raw) {
		return "", fmt.Errorf("string out of bounds")
	}
	end := int(off)
	for end < len(raw) && raw[end] != 0 {
		end++
	}
	return string(raw[off:end]), nil
}
