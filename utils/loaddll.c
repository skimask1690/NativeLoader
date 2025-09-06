#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <stdio.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("[*] Usage: %s <input.dll>\n", argv[0]);
        return 1;
    }

    HMODULE h = LoadLibraryA(argv[1]);  // Executes DLL_PROCESS_ATTACH
    if (!h) {
        printf("[-] Error: Failed to load DLL '%s'\n", argv[1]);
        return 1;
    }

    TerminateProcess(GetCurrentProcess(), 0); // Skips DLL_PROCESS_DETACH
}
