#include "winapi_loader.h"

// -------------------- Function pointer types --------------------
typedef BOOL (WINAPI* CreateProcessW_t)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

// -------------------- Strings --------------------
STRINGA(kernel32_dll, "kernel32.dll")
STRINGA(createprocessw, "CreateProcessW")
STRINGW(path, "C:\\Windows\\System32\\calc.exe")

// -------------------- Entry point --------------------
__attribute__((section(".text.start")))
void _start(void) {
    HMODULE hKernel32 = myGetModuleHandleA(kernel32_dll);
    CreateProcessW_t pCreateProcessW = (CreateProcessW_t)myGetProcAddress(hKernel32, createprocessw);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    *(STARTUPINFOW*)&si = (STARTUPINFOW){0}; si.cb = sizeof(STARTUPINFOW);
    *(PROCESS_INFORMATION*)&pi = (PROCESS_INFORMATION){0};

    pCreateProcessW(path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

