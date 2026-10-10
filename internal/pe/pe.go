package pe

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

// ImportedLibraries returns the unique lowercase DLL names imported by a PE file.
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
		return out, nil
	}

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
	return out, nil
}

// Export is a single named export from a DLL.
type Export struct {
	Name    string
	Ordinal uint16
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
	numberOfNames := binary.LittleEndian.Uint32(dir[0x18:0x1C])
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
		if err != nil {
			continue
		}
		if name == "" {
			continue
		}
		exports = append(exports, Export{Name: name, Ordinal: uint16(base) + ordIdx})
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
