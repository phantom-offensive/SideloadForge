# SideloadForge

A **C2-agnostic** signed-app DLL sideload generator. Give it a signed
application's DLL and raw shellcode from *any* C2 (Cobalt Strike, Sliver,
Mythic, Brute Ratel, Havoc, …), and it generates a proxy DLL that:

1. Runs your shellcode from `DllMain`
2. Forwards every original export to the renamed legitimate DLL so the app keeps working
3. Leaves the signed EXE untouched (its Authenticode signature stays valid)

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

The generator emits:

- `proxy.c` — the proxy DLL source (runs shellcode, forwards exports)
- `<name>.def` — export forwarders to `<name>_orig.dll`
- `build.bat` — mingw build command

Then:

```bash
# rename the real DLL
ren version.dll version_orig.dll

# build the proxy (cross-compile from Linux with mingw-w64, or on Windows)
x86_64-w64-mingw32-gcc -shared -o version.dll proxy.c version.def
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

## Disclaimer

Authorized security testing and red team operations only.
