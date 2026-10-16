# SideloadForge

A **C2-agnostic** signed-app DLL sideload generator. Give it a signed
application's DLL and raw shellcode from *any* C2 (Cobalt Strike, Sliver,
Mythic, Brute Ratel, Havoc, …), and it generates a proxy DLL that:

1. Runs your shellcode from `DllMain`
2. Forwards every original export to the renamed legitimate DLL so the app keeps working
3. Leaves the signed EXE untouched (its Authenticode signature stays valid)

## How it works

1. `forge scan` parses the target EXE's PE import table and lists DLLs that are
   neither Windows system DLLs nor API-set virtual DLLs (`api-ms-win-*` /
   `ext-ms-win-*`). Delay-loaded imports are included too.
2. `forge generate` parses the chosen DLL's export table and emits:
   - `proxy.c` — proxy DLL source (decodes + runs shellcode, forwards exports)
   - `<name>.def` — export forwarders to the renamed original DLL
   - `build.bat` — mingw build command
3. You rename the real DLL to `<name>_orig.dll`, build the proxy with mingw,
   and drop it next to the signed EXE. The app loads your proxy via the Windows
   DLL search order; exports forward to the renamed original, so the app still
   works.

## Why sideloading

Modifying a signed binary breaks its signature. Sideloading keeps the signed
EXE byte-for-byte intact — a malicious DLL is dropped next to it and loaded by
the app at startup via the Windows DLL search order.

## Usage

```bash
# 1) Find sideload candidates in a signed app
forge scan /path/to/app.exe

# 2) Generate a proxy DLL for a chosen DLL, embedding your C2 shellcode
forge generate version.dll --shellcode beacon.bin --out payload
```

### `forge scan`

```bash
forge scan <signed.exe>
```

- Lists non-system, non-API-set DLL candidates (`[*]` marker).
- Also shows all imports, marking API-set DLLs with `~` and candidates with `!`.
- Reports whether the EXE has an Authenticode signature (certificate table).

### `forge generate`

```bash
forge generate <original.dll> --shellcode payload.bin [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--shellcode` | *(required)* | Raw shellcode file from any C2 |
| `--rename` | `<name>_orig` | Renamed module base (no `.dll`) |
| `--out` | `.` | Output directory |
| `--arch` | `x64` | Target arch: `x64` or `x86` |
| `--xor` | false | XOR-encode the embedded shellcode with a random 16-byte key |
| `--rc4` | false | RC4-encrypt the embedded shellcode with a random 16-byte key (stronger than `--xor`) |
| `--build` | false | Compile the proxy DLL with mingw immediately |
| `--compiler` | auto | mingw compiler (default `x86_64-w64-mingw32-gcc` / `i686-w64-mingw32-gcc`) |
| `--sleep` | `0` | Sleep (ms) before running shellcode |

Example:

```bash
forge generate version.dll --shellcode beacon.bin --out payload --xor --build
```

## C2-agnostic by design

The tool never inspects the shellcode — it just embeds it as a byte array. Use
whatever your C2 emits as raw position-independent shellcode.

## Build

```bash
make build              # host binary
make build-windows      # Windows amd64 (CGO_ENABLED=0)
make build-linux        # Linux amd64
```

## Limitations

- **Ordinal-only exports are skipped** — mingw `ld` does not support ordinal
  forwarders, so exports with no name are not proxied (typically unused
  legacy/internal functions). Named exports are forwarded by name.
- **Shellcode is embedded as a byte array** — `--xor` raises the bar but is not
  strong encryption. Treat generated DLLs as detectable; combine with your own
  C2 shellcode's encoding.
- **`version.dll` is a KnownDLL** on Windows, so it resolves from System32 and
  is *not* sideloadable from an app directory — pick a non-KnownDLL import
  (which `scan` surfaces).

## Disclaimer

Authorized security testing and red team operations only.

## License

MIT — see [LICENSE](LICENSE).
