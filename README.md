# ⚙️ WinAPI Loader

This project demonstrates a **minimal x64 Windows loader** that dynamically resolves DLLs and functions **without using the C runtime or static imports**. It shows how to:

- Access the Windows **PEB (Process Environment Block)** to enumerate loaded modules.
- Implement custom versions of `GetModuleHandle*` and `GetProcAddress`.
- Load additional DLLs (`LdrLoadDll`) at runtime.
- Call functions (like `CreateProcess*`) dynamically.

---

## 🔹 Features

- Manual module resolution through the PEB.
- Manual export resolution from PE export tables.
- Dynamic `LoadLibrary*` / `GetProcAddress` usage without static imports.
- Freestanding (no CRT / no standard startup files).
- Minimal, lightweight shellcode.

## 🔹 Build Instructions

Requires `gcc` targeting 64-bit Windows

Build the MessageBox example:
```bash
compile.py examples/msgbox.c msgbox.bin
```

Build the shellcode loader:
```bash
x86_64-w64-mingw32-gcc utils/loadshc.c -o loadshc.exe
```

## 🔹 Usage
Run the loader and pass the shellcode as an argument:
```bash
loadshc.exe msgbox.bin
```
This will load the shellcode into memory and execute it.

## ⚠️ Disclaimer
This tool is provided for educational and research purposes only. The author is not responsible for any misuse.

## 📜 License

This project is released under the [MIT License](LICENSE).
