#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

// DLL entry point type
typedef BOOL(WINAPI *DllEntryProc)(HINSTANCE, DWORD, LPVOID);

// Determine memory protection from section characteristics
DWORD GetProtection(DWORD characteristics) {
    if (characteristics & IMAGE_SCN_MEM_EXECUTE)
        return (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    if (characteristics & IMAGE_SCN_MEM_READ)
        return (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
    return PAGE_NOACCESS;
}

// Reflectively load DLL from memory
HMODULE ReflectiveLoadDLL(BYTE* dllBuffer) {
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)dllBuffer;
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(dllBuffer + dosHeader->e_lfanew);

    // Allocate memory for DLL image
    BYTE* imageBase = (BYTE*)VirtualAlloc(
        (LPVOID)ntHeaders->OptionalHeader.ImageBase,
        ntHeaders->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    if (!imageBase)
        imageBase = (BYTE*)VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!imageBase) return NULL;

    // Copy headers and sections
    memcpy(imageBase, dllBuffer, ntHeaders->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++)
        memcpy(imageBase + section->VirtualAddress, dllBuffer + section->PointerToRawData, section->SizeOfRawData);

    // Apply relocations
    SIZE_T delta = (SIZE_T)(imageBase - ntHeaders->OptionalHeader.ImageBase);
    IMAGE_DATA_DIRECTORY relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (delta && relocDir.Size) {
        IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(imageBase + relocDir.VirtualAddress);
        SIZE_T offset = 0;
        while (offset < relocDir.Size) {
            WORD* entry = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
            int count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (int i = 0; i < count; i++) {
                WORD type = entry[i] >> 12;
                WORD rva = entry[i] & 0x0FFF;
                if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64)
                    *(SIZE_T*)(imageBase + reloc->VirtualAddress + rva) += delta;
            }
            offset += reloc->SizeOfBlock;
            reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
        }
    }

    // Resolve imports
    IMAGE_DATA_DIRECTORY importsDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importsDir.Size) {
        IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)(imageBase + importsDir.VirtualAddress);
        while (importDesc->Name) {
            HMODULE hDep = LoadLibraryA((char*)(imageBase + importDesc->Name));
            IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(imageBase + importDesc->FirstThunk);
            while (thunk->u1.Function) {
                thunk->u1.Function = (SIZE_T)(
                    (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                        ? GetProcAddress(hDep, (LPCSTR)(thunk->u1.Ordinal & 0xFFFF))
                        : GetProcAddress(hDep, ((IMAGE_IMPORT_BY_NAME*)(imageBase + thunk->u1.AddressOfData))->Name)
                );
                thunk++;
            }
            importDesc++;
        }
    }

    // Set memory protection for sections
    section = IMAGE_FIRST_SECTION(ntHeaders);
    BYTE* regionStart = imageBase + section->VirtualAddress;
    SIZE_T regionSize = section->Misc.VirtualSize;
    DWORD currentProtect = GetProtection(section->Characteristics);
    for (int i = 1; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        DWORD protect = GetProtection(section->Characteristics);
        BYTE* secStart = imageBase + section->VirtualAddress;
        SIZE_T secSize = section->Misc.VirtualSize;

        if (protect == currentProtect && regionStart + regionSize == secStart)
            regionSize += secSize;
        else {
            DWORD oldProtect;
            VirtualProtect(regionStart, regionSize, currentProtect, &oldProtect);
            regionStart = secStart;
            regionSize = secSize;
            currentProtect = protect;
        }
    }
    DWORD oldProtect;
    VirtualProtect(regionStart, regionSize, currentProtect, &oldProtect);

    // Call DLL entry point
    DllEntryProc DllMain = (DllEntryProc)(imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    if (!DllMain((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, NULL)) {
        VirtualFree(imageBase, 0, MEM_RELEASE);
        return NULL;
    }

    return (HMODULE)imageBase;
}

// Read DLL file into memory
BYTE* ReadDLL(const char* path, SIZE_T* outSize) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    SIZE_T size = ftell(f);
    fseek(f, 0, SEEK_SET);
    BYTE* buffer = (BYTE*)malloc(size);
    fread(buffer, 1, size, f);
    fclose(f);
    *outSize = size;
    return buffer;
}

// Minimal main function for single DLL
int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <input.dll>\n", argv[0]);
        return 1;
    }

    SIZE_T dllSize;
    BYTE* dllBuffer = ReadDLL(argv[1], &dllSize);
    if (!dllBuffer) {
        printf("Failed to read DLL '%s'\n", argv[1]);
        return 1;
    }

    if (!ReflectiveLoadDLL(dllBuffer))
        printf("Failed to load DLL '%s'\n", argv[1]);

    free(dllBuffer);
    return 0;
}
