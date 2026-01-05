#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

// Type for DLL entry point
typedef BOOL(WINAPI *DllEntryProc)(HINSTANCE, DWORD, LPVOID);

DWORD GetProtection(DWORD characteristics) {
    if (characteristics & IMAGE_SCN_MEM_EXECUTE)
        return (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    if (characteristics & IMAGE_SCN_MEM_READ)
        return (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
    return PAGE_NOACCESS;
}

HMODULE ReflectiveLoadDLL(BYTE* dllBuffer) {
    // Parse headers
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)dllBuffer;
    IMAGE_NT_HEADERS64* ntHeaders = (IMAGE_NT_HEADERS64*)(dllBuffer + dosHeader->e_lfanew);

    // Allocate memory for DLL image
    BYTE* imageBase = (BYTE*)VirtualAlloc(
        (LPVOID)ntHeaders->OptionalHeader.ImageBase,
        ntHeaders->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    if (!imageBase)
        imageBase = (BYTE*)VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    // Copy headers
    memcpy(imageBase, dllBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);

    // Copy sections
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
    for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        BYTE* dest = imageBase + section->VirtualAddress;
        BYTE* src = dllBuffer + section->PointerToRawData;
        size_t copySize = section->SizeOfRawData;
        size_t totalSize = section->Misc.VirtualSize;

        memcpy(dest, src, copySize);
        if (totalSize > copySize)
            memset(dest + copySize, 0, totalSize - copySize);
    }

    // Resolve imports
    IMAGE_DATA_DIRECTORY importsDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importsDir.Size) {
        IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(imageBase + importsDir.VirtualAddress);
        while (importDesc->Name) {
            HMODULE hDep = LoadLibraryA((char*)(imageBase + importDesc->Name));
            IMAGE_THUNK_DATA64* thunk = (IMAGE_THUNK_DATA64*)(imageBase + importDesc->FirstThunk);
            while (thunk->u1.Function) {
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                    thunk->u1.Function = (SIZE_T)GetProcAddress(hDep, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));
                else
                    thunk->u1.Function = (SIZE_T)GetProcAddress(hDep, ((IMAGE_IMPORT_BY_NAME*)(imageBase + thunk->u1.AddressOfData))->Name);
                thunk++;
            }
            importDesc++;
        }
    }

    // Protect headers + first section
    section = IMAGE_FIRST_SECTION(ntHeaders);
    DWORD oldProtect;
    SIZE_T firstSize = (section->VirtualAddress + section->Misc.VirtualSize);
    VirtualProtect(imageBase, firstSize, PAGE_READONLY, &oldProtect);

    // Protect remaining sections
    BYTE* regionStart = imageBase + section->VirtualAddress + section->Misc.VirtualSize;
    SIZE_T regionSize = 0;
    DWORD currentProtect = 0;
    for (size_t i = 1; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        DWORD protect = GetProtection(section->Characteristics);
        BYTE* secStart = imageBase + section->VirtualAddress;
        SIZE_T secSize = section->Misc.VirtualSize;
    
        if (regionSize && protect == currentProtect && regionStart + regionSize == secStart)
            regionSize += secSize; // merge with previous
        else {
            if (regionSize)
                VirtualProtect(regionStart, regionSize, currentProtect, &oldProtect);
            regionStart = secStart;
            regionSize = secSize;
            currentProtect = protect;
        }
    
        // Free discardable sections
        if (section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
            VirtualFree(secStart, secSize, MEM_DECOMMIT);
        }
    }
    if (regionSize)
        VirtualProtect(regionStart, regionSize, currentProtect, &oldProtect);
    
    // Call DLL entry point
    DllEntryProc DllMain = (DllEntryProc)(imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    if (!DllMain((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, NULL)) {
        VirtualFree(imageBase, 0, MEM_RELEASE);
        return NULL;
    }

    return (HMODULE)imageBase;
}

BYTE* ReadDLL(const char* path, SIZE_T* outSize) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    SIZE_T size = ftell(f);
    fseek(f, 0, SEEK_SET);
    BYTE* buffer = (BYTE*)malloc(size);
    fread(buffer, size, 1, f);
    fclose(f);
    *outSize = size;
    return buffer;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("[*] Usage: %s <input.dll>\n", argv[0]);
        return 1;
    }

    SIZE_T dllSize;
    BYTE* dllBuffer = ReadDLL(argv[1], &dllSize);
    if (!dllBuffer) {
        printf("[-] Failed to read DLL '%s'\n", argv[1]);
        return 1;
    }

    if (!ReflectiveLoadDLL(dllBuffer))
        printf("[-] Failed to load DLL '%s'\n", argv[1]);

    free(dllBuffer);
    return 0;
}
