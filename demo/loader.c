#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("[*] Usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }
    
    // Open shellcode file
    FILE *shellcodeFile = fopen(argv[1], "rb");

    // Get file size
    fseek(shellcodeFile, 0, SEEK_END);
    long shellcodeSize = ftell(shellcodeFile);
    fseek(shellcodeFile, 0, SEEK_SET);

    // Allocate memory
    void *execMemory = VirtualAlloc(NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Load shellcode into memory
    fread(execMemory, 1, shellcodeSize, shellcodeFile);
    fclose(shellcodeFile);

    // Make memory executable
    DWORD oldProtect;
    VirtualProtect(execMemory, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);

    // Run shellcode
    ((void(*)())execMemory)();

    return 0;
}
