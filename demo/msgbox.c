#include "winapi_loader.h"

// -------------------- Function pointer types --------------------
typedef int (WINAPI *MessageBoxW_t)(HWND, LPCWSTR, LPCWSTR, UINT);

// -------------------- Strings --------------------
STRINGW(user32_dll, "user32.dll")
STRINGA(messageboxw, "MessageBoxW")
STRINGW(hello_msg, "Hello from shellcode!")
STRINGW(title_msg, "C Shellcode Demo")

// -------------------- Entry point --------------------
__attribute__((section(".text.start")))
int _start(void) {
    HMODULE hUser32 = myLoadLibraryW(user32_dll);
    MessageBoxW_t pMessageBoxW = (MessageBoxW_t)myGetProcAddress(hUser32, messageboxw);
    pMessageBoxW(NULL, hello_msg, title_msg, MB_OK | MB_ICONINFORMATION);
}
