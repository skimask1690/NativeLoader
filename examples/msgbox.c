#include "winapi_loader.h"

// -------------------- Function pointer types --------------------
typedef int (WINAPI *MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
typedef VOID (WINAPI *ExitProcess_t)(UINT uExitCode);

// -------------------- Strings --------------------
STRINGW(user32_dll, "user32.dll")
STRINGA(kernel32_dll, "kernel32.dll")
STRINGA(messageboxa, "MessageBoxA")
STRINGA(hello_msg, "Hello from shellcode!")
STRINGA(title_msg, "C Shellcode Demo")
STRINGA(exitprocess, "ExitProcess")

// -------------------- Entry point --------------------
__attribute__((section(".text.start")))
int _start(void) {
    HMODULE hUser32 = myLoadLibraryW(user32_dll);
    HMODULE hKernel32 = myGetModuleHandleA(kernel32_dll);

    MessageBoxA_t pMessageBoxA = (MessageBoxA_t)myGetProcAddress(hUser32, messageboxa);
    ExitProcess_t pExitProcess = (ExitProcess_t)myGetProcAddress(hKernel32, exitprocess);
	
    pMessageBoxA(NULL, hello_msg, title_msg, MB_OK | MB_ICONINFORMATION);
    pExitProcess(0);
}
