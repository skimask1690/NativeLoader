#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    // Check for input file argument
    if (argc < 2) {
        printf("Usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }

    // Open the shellcode file
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Error: Cannot open file '%s'\n", argv[1]);
        return 1;
    }

    // Get file size
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Allocate memory for shellcode
    void *mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Read shellcode into memory
    fread(mem, 1, size, f);
    fclose(f);

    // Make memory executable
    DWORD old;
    VirtualProtect(mem, size, PAGE_EXECUTE_READ, &old);

    // Execute shellcode
    ((void(*)())mem)();

    return 0;
}
