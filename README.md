# ⚙️ WinAPI Loader

This project demonstrates a **minimal Windows loader** that dynamically resolves DLLs and functions **without using the C runtime or static imports**. It shows how to:

- Access the Windows **PEB (Process Environment Block)** to enumerate loaded modules.
- Implement custom versions of `GetModuleHandleA` and `GetProcAddress`.
- Load additional DLLs (`LdrLoadDll`) at runtime.
- Call functions (like `CreateProcess`) dynamically.

---

## 🔹 Features

- Manual module resolution through the PEB.
- Manual export resolution from PE export tables.
- Dynamic `LoadLibrary` / `GetProcAddress` usage without static imports.
- Freestanding (no CRT / no standard startup files).
- Minimal, lightweight shellcode.

## 🔹 Build Instructions

Requires `gcc` targeting 64-bit Windows

Build the demo:
```bash
x86_64-w64-mingw32-gcc -s calc.c -nostdlib -nostartfiles -ffreestanding -fno-ident -Wl,-subsystem,windows -e _start -Os -fPIC -fno-asynchronous-unwind-tables -T linker.ld -o temp_calc.exe
```

Extract shellcode from .text:
```bash
objcopy -O binary --only-section=.text temp_calc.exe shellcode.bin
```

Build the shellcode loader:
```bash
x86_64-w64-mingw32-gcc loader.c -o loader.exe
```

## 🔹 Usage
Run the loader and pass the shellcode as an argument:
```bash
loader.exe shellcode.bin
```
This will load the shellcode into memory and execute it.

## ⚠️ Disclaimer
This tool is provided for educational and research purposes only. The author is not responsible for any misuse.

## 📜 License

This project is released under the [MIT License](LICENSE).
