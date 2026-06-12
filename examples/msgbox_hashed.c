#if __has_include("../winapi_loader.h")
#include "../winapi_loader.h"
#else
#include "winapi_loader.h"
#endif

// -------------------- Function pointer types --------------------
typedef int (WINAPI *MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);

// -------------------- Strings --------------------
#define messageboxa HASH("MessageBoxA")

STRINGW(user32_dll, "user32.dll")
STRINGA(hello_msg, "Hello from shellcode!")
STRINGA(title_msg, "C Shellcode Demo")

// -------------------- Entry point --------------------
__attribute__((section(".text.start")))
int _start(void)
{
    HMODULE hUser32 = myLoadLibraryW(user32_dll);
    MessageBoxA_t MessageBoxA = (MessageBoxA_t)myGetProcAddressH(hUser32, messageboxa);

    MessageBoxA(NULL, hello_msg, title_msg, MB_OK | MB_ICONINFORMATION);
    myExitProcess(0);
}
