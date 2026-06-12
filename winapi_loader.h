#ifndef WINAPI_LOADER_H
#define WINAPI_LOADER_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include "fnv_hash.h"

// -------------------- String Macros --------------------
#define STRINGA(name, value) __attribute__((section(".text"), aligned(1))) \
    static char name[] = value;

#define STRINGW(name, value) __attribute__((section(".text"), aligned(1))) \
    static wchar_t name[] = L##value;

// -------------------- PEB Structs --------------------
typedef struct _LDR_MODULE {
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  PVOID BaseAddress;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  ULONG Flags;
  SHORT LoadCount;
  SHORT TlsIndex;
  LIST_ENTRY HashTableEntry;
  ULONG TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

// -------------------- Helpers --------------------
static void AsciiToWideChar(wchar_t* buf, UNICODE_STRING* ustr, const char* ascii) {
    SIZE_T i = 0;
    while (ascii[i]) {
        buf[i] = (wchar_t)ascii[i]; i++;
    }
    buf[i] = 0;

    ustr->Buffer = buf;
    ustr->Length = (USHORT)(i * sizeof(wchar_t));
    ustr->MaximumLength = (USHORT)((i + 1) * sizeof(wchar_t));
}

static void InitUnicodeString(UNICODE_STRING* ustr, const wchar_t* wstr) {
    size_t len = 0;
    while (wstr[len]) len++;

    ustr->Buffer        = (PWSTR)wstr;
    ustr->Length        = (USHORT)(len * sizeof(WCHAR));
    ustr->MaximumLength = (USHORT)((len + 1) * sizeof(WCHAR));
}

// -------------------- myGetModuleHandleA --------------------
static HMODULE myGetModuleHandleA(const char* name) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;

    for (LIST_ENTRY* cur = head->Flink; cur != head; cur = cur->Flink) {
        PLDR_MODULE mod = CONTAINING_RECORD(cur, LDR_MODULE, InMemoryOrderModuleList);
        SIZE_T len = mod->BaseDllName.Length / sizeof(WCHAR);
        SIZE_T i;
        for (i = 0; i < len && ((char)(mod->BaseDllName.Buffer[i]) | 0x20) == (name[i] | 0x20); ++i);
        if (i == len && name[i] == 0)
            return (HMODULE)mod->BaseAddress;
    }

    return NULL;
}

// -------------------- myGetModuleHandleW --------------------
static HMODULE myGetModuleHandleW(const wchar_t* name) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;

    for (LIST_ENTRY* cur = head->Flink; cur != head; cur = cur->Flink) {
        PLDR_MODULE mod = CONTAINING_RECORD(cur, LDR_MODULE, InMemoryOrderModuleList);
        SIZE_T len = mod->BaseDllName.Length / sizeof(WCHAR);
        SIZE_T i;

        for (i = 0; i < len && (mod->BaseDllName.Buffer[i] | 0x20) == (name[i] | 0x20); ++i);

        if (i == len && name[i] == 0)
            return (HMODULE)mod->BaseAddress;
    }

    return NULL;
}

// -------------------- myGetProcAddress --------------------
static FARPROC myGetProcAddress(HMODULE hMod, const char* fnName) {
    BYTE* base = (BYTE*)hMod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)
        (base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD* ords  = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* p1 = (const char*)(base + names[i]);
        const char* p2 = fnName;
        while (*p1 && (*p1) == (*p2)) { ++p1; ++p2; }
        if (*p2 == 0)
            return (FARPROC)(base + funcs[ords[i]]);
    }
    return NULL;
}

// -------------------- Hashed myGetModuleHandle --------------------
static HMODULE myGetModuleHandleH(unsigned int target_hash) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;

    for (LIST_ENTRY* cur = head->Flink; cur != head; cur = cur->Flink) {
        PLDR_MODULE mod = CONTAINING_RECORD(cur, LDR_MODULE, InMemoryOrderModuleList);
        SIZE_T len = mod->BaseDllName.Length / sizeof(WCHAR);

        unsigned long long hash = FNV32_OFFSET;
        for (SIZE_T i = 0; i < len; ++i) {
            char c = (char)mod->BaseDllName.Buffer[i];
            if (c >= 'A' && c <= 'Z') c += 32;
            hash = ((unsigned char)c ^ hash) * FNV32_PRIME;
        }

        if ((unsigned int)hash == target_hash)
            return (HMODULE)mod->BaseAddress;
    }

    return NULL;
}

// -------------------- Hashed myGetProcAddress --------------------
static FARPROC myGetProcAddressH(HMODULE hMod, unsigned int target_hash) {
    BYTE* base = (BYTE*)hMod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)
        (base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD* ords  = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* fn = (const char*)(base + names[i]);
        if (runtime_hash(fn) == target_hash)
            return (FARPROC)(base + funcs[ords[i]]);
    }
    return NULL;
}

// -------------------- myLoadLibrary Helper --------------------
typedef NTSTATUS(NTAPI* LdrLoadDll_t)(PWSTR, ULONG, UNICODE_STRING*, PHANDLE);
#define ntdll_dll HASH("ntdll.dll")
#define ldrloadll HASH("LdrLoadDll")

static HMODULE _myLdrLoadDll(UNICODE_STRING* ustr) {
    HMODULE hNtdll = myGetModuleHandleH(ntdll_dll);
    LdrLoadDll_t LdrLoadDll = (LdrLoadDll_t)myGetProcAddressH(hNtdll, ldrloadll);

    HMODULE hModule = NULL;
    LdrLoadDll(NULL, 0, ustr, (PHANDLE)&hModule);

    return hModule;
}

// -------------------- myLoadLibraryA --------------------
static HMODULE myLoadLibraryA(const char* dllNameA) {
    size_t len = 0;
    while (dllNameA[len]) len++;
    wchar_t buf[len + 1];

    UNICODE_STRING ustr;
    AsciiToWideChar(buf, &ustr, dllNameA);
    return _myLdrLoadDll(&ustr);
}

// -------------------- myLoadLibraryW --------------------
static HMODULE myLoadLibraryW(const wchar_t* dllNameW) {
    UNICODE_STRING ustr;
    InitUnicodeString(&ustr, dllNameW);
    return _myLdrLoadDll(&ustr);
}

// -------------------- Forwarded myGetProcAddress --------------------
static FARPROC xGetProcAddress(HMODULE hMod, const char* target) {
    BYTE* base = (BYTE*)hMod;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + ed.VirtualAddress);

    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD* ords   = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs  = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++)
    {
        const char* fn = (const char*)(base + names[i]);

        const char* p1 = fn;
        const char* p2 = target;

        while (*p1 && *p2 && *p1 == *p2)
        {
            ++p1;
            ++p2;
        }

        if (*p1 || *p2)
            continue;

        WORD ord = ords[i];
        DWORD rva = funcs[ord];
		
		HMODULE hNtdll = myGetModuleHandleH(ntdll_dll);
        LdrLoadDll_t LdrLoadDll = (LdrLoadDll_t)myGetProcAddressH(hNtdll, ldrloadll);
		
        // forwarded exports
        if (rva >= ed.VirtualAddress && rva < ed.VirtualAddress + ed.Size)
        {
            const char* s = (const char*)(base + rva);

            const char* dot = s;
            while (*dot && *dot != '.') dot++;

            // DLL name
            size_t dllLen = (size_t)(dot - s);
            char dll[dllLen + 1];

            for (size_t j = 0; j < dllLen; j++)
                dll[j] = s[j];

            dll[dllLen] = L'\0';

            // function name
            const char* func = dot + 1;

            size_t len = 0;
            while (dll[len]) len++;
        
            wchar_t buf[len + 1];
        
            UNICODE_STRING ustr;
            AsciiToWideChar(buf, &ustr, dll);
        
            HMODULE fmod = NULL;
        
            LdrLoadDll(NULL, 0, &ustr, (PHANDLE)&fmod);

            return xGetProcAddress(fmod, func);
        }

        return (FARPROC)(base + rva);
    }
}

// -------------------- Hashed forwarded myGetProcAddress --------------------
static FARPROC xGetProcAddressH(HMODULE hMod, unsigned int target_hash) {
    BYTE* base = (BYTE*)hMod;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY ed = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + ed.VirtualAddress);

    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD* ords   = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs  = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++)
    {
        const char* fn = (const char*)(base + names[i]);

        if (runtime_hash(fn) != target_hash)
            continue;

        WORD ord = ords[i];
        DWORD rva = funcs[ord];

		HMODULE hNtdll = myGetModuleHandleH(ntdll_dll);
        LdrLoadDll_t LdrLoadDll = (LdrLoadDll_t)myGetProcAddressH(hNtdll, ldrloadll);

        // forwarded exports
        if (rva >= ed.VirtualAddress && rva < ed.VirtualAddress + ed.Size)
        {
            const char* s = (const char*)(base + rva);

            const char* dot = s;
            while (*dot && *dot != '.') dot++;

            // DLL name
            size_t dllLen = (size_t)(dot - s);

            char dll[dllLen + 1];
            for (size_t j = 0; j < dllLen; j++)
                dll[j] = s[j];
			
            dll[dllLen] = L'\0';

            s = dot + 1;

            // function name
            const char* t = s;
            size_t fnLen = 0;
            while (*t++) fnLen++;

            char fname[fnLen + 1];
            for (size_t j = 0; j < fnLen; j++)
                fname[j] = s[j];
			
            fname[fnLen] = L'\0';

            size_t len = 0;
            while (dll[len]) len++;
        
            wchar_t buf[len + 1];
        
            UNICODE_STRING ustr;
            AsciiToWideChar(buf, &ustr, dll);
        
            HMODULE fmod = NULL;
        
            LdrLoadDll(NULL, 0, &ustr, (PHANDLE)&fmod);

            return xGetProcAddressH(fmod, runtime_hash(fname));
        }

        return (FARPROC)(base + rva);
    }
}

// -------------------- myExitProcess --------------------
typedef NTSTATUS (NTAPI *NtTerminateProcess_t)(HANDLE, NTSTATUS);
#define ntterminateprocess HASH("NtTerminateProcess")

static VOID myExitProcess(NTSTATUS status) {
    HMODULE hNtdll = myGetModuleHandleH(ntdll_dll);

    NtTerminateProcess_t NtTerminateProcess = (NtTerminateProcess_t)myGetProcAddressH(hNtdll, ntterminateprocess);
    NtTerminateProcess((HANDLE)-1, status);
}

// -------------------- myExitThread --------------------
typedef NTSTATUS (NTAPI *NtTerminateThread_t)(HANDLE, NTSTATUS);
#define ntterminatethread HASH("NtTerminateThread")

static VOID myExitThread(NTSTATUS status) {
    HMODULE hNtdll = myGetModuleHandleH(ntdll_dll);

    NtTerminateThread_t NtTerminateThread = (NtTerminateThread_t)myGetProcAddressH(hNtdll, ntterminatethread);
    NtTerminateThread((HANDLE)-2, status);
}

// -------------------- mySleep --------------------
typedef NTSTATUS (NTAPI *NtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);
#define ntdelayexecution HASH("NtDelayExecution")

static void mySleep(DWORD ms) {
    HMODULE hNtdll = myGetModuleHandleH(ntdll_dll);
    NtDelayExecution_t NtDelayExecution = (NtDelayExecution_t)myGetProcAddressH(hNtdll, ntdelayexecution);

    LARGE_INTEGER interval;
    interval.QuadPart = -((LONGLONG)ms * 10000LL);

    NtDelayExecution(FALSE, &interval);
}

// -------------------- myIsDebuggerPresent --------------------
static BOOLEAN myIsDebuggerPresent(void) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    return peb->BeingDebugged;
}

// -------------------- RDTSC Timing Check --------------------
static int rdtsc_check(void) {
    unsigned long long avg = 0;

    for (int i = 0; i < 10; i++) {
        unsigned long long t1 = __rdtsc();
        unsigned long long t2 = __rdtsc();

        avg += (t2 - t1);    
    }

    avg /= 10;

    return !(avg > 0 && avg < 750);
}

// -------------------- Anti-Debug --------------------
typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
#define ntqueryinformationprocess HASH("NtQueryInformationProcess")

static inline void ANTI_DEBUG(void) {
    HMODULE hNtdll = myGetModuleHandleH(ntdll_dll);
	
    NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)myGetProcAddressH(hNtdll, ntqueryinformationprocess);
    NtTerminateProcess_t NtTerminateProcess = (NtTerminateProcess_t)myGetProcAddressH(hNtdll, ntterminateprocess);

    HANDLE debugPort = NULL;

    if (myIsDebuggerPresent() ||
        (NT_SUCCESS(NtQueryInformationProcess((HANDLE)-1, ProcessDebugPort, &debugPort, sizeof(debugPort), NULL)) && debugPort))
    {
        NtTerminateProcess((HANDLE)-1, 0);
    }
}

// -------------------- Anti-VM --------------------
static inline void ANTI_VM(void) {
    HMODULE hNtdll = myGetModuleHandleH(ntdll_dll);
    NtTerminateProcess_t NtTerminateProcess = (NtTerminateProcess_t)myGetProcAddressH(hNtdll, ntterminateprocess);
	
    if (rdtsc_check())
    {
        NtTerminateProcess((HANDLE)-1, 0);
    }
}

// -------------------- Stdout Write --------------------
typedef NTSTATUS (NTAPI *NtWriteFile_t)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
#define ntwritefile HASH("NtWriteFile")

static void STDOUT_WRITE(char *str) {
    HMODULE hNtdll = myGetModuleHandleH(ntdll_dll);
    NtWriteFile_t NtWriteFile = (NtWriteFile_t)myGetProcAddressH(hNtdll, ntwritefile);

    void *peb = (void*)__readgsqword(0x60);
    void **procParams = *(void***)((char*)peb + 0x20); // ProcessParameters
    HANDLE hOut = *(HANDLE*)((char*)procParams + 0x28); // StandardOutput

    DWORD len = 0;
    while (str[len]) len++;
    IO_STATUS_BLOCK iosb;

    NtWriteFile(hOut, 0, 0, 0, &iosb, str, len, 0, 0);
}

#endif // WINAPI_LOADER_H
