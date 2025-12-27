#include "winapi_loader.h"

// -------------------- Function pointer types --------------------
typedef BOOL (WINAPI *CreateProcessA_t)(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

// -------------------- Strings --------------------
STRINGA(kernel32_dll, "kernel32.dll")
STRINGA(createprocessa, "CreateProcessA")
STRINGA(command, "calc.exe")

// -------------------- Entry point --------------------
__attribute__((section(".text.start")))
void _start(void) {
    HMODULE hKernel32 = myGetModuleHandleA(kernel32_dll);
    CreateProcessA_t pCreateProcessA = (CreateProcessA_t)myGetProcAddress(hKernel32, createprocessa);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
	
    pCreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}
