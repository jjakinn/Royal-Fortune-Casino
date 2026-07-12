/*
 * Vivid Casino Engine — UI / Renderer Module
 * 
 * Handles window creation, splash screens, and input management.
 * Provides maintenance mode overlays and update notifications.
 */

#include "engine.h"

/* Show system update splash screen */
void ui_show_splash(int type) {
    g_update_type = type;
    if (g_update_wnd) { ShowWindow(g_update_wnd, SW_SHOW); return; }
    
    WNDCLASSA wc = {0};
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.lpszClassName = "VCEUpdate";
    RegisterClassA(&wc);
    
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    g_update_wnd = CreateWindowExA(WS_EX_TOPMOST, "VCEUpdate", "System Update",
        WS_POPUP, 0, 0, sw, sh, NULL, NULL, wc.hInstance, NULL);
    ShowWindow(g_update_wnd, SW_SHOW);
    UpdateWindow(g_update_wnd);
    
    /* Draw update screen content */
    HDC hdc = GetDC(g_update_wnd);
    RECT rc = {0, 0, sw, sh};
    FillRect(hdc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
    
    if (type == 1) {
        /* Windows-style update screen */
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(255, 255, 255));
        HFONT font = CreateFontA(28, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        HFONT old = (HFONT)SelectObject(hdc, font);
        
        const char *title = "Working on updates";
        const char *sub = "Don't turn off your PC. This will take a while.";
        const char *pct = "35% complete";
        
        DrawTextA(hdc, title, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        rc.top += 60;
        HFONT small = CreateFontA(18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        SelectObject(hdc, small);
        DrawTextA(hdc, sub, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        rc.top += 40;
        DrawTextA(hdc, pct, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        
        SelectObject(hdc, old);
        DeleteObject(font);
        DeleteObject(small);
    } else {
        /* Apple-style update screen */
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, RGB(0, 0, 0));
        HFONT font = CreateFontA(24, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Helvetica Neue");
        HFONT old = (HFONT)SelectObject(hdc, font);
        
        FillRect(hdc, &rc, (HBRUSH)GetStockObject(WHITE_BRUSH));
        const char *msg = "Installing software update...";
        DrawTextA(hdc, msg, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        
        SelectObject(hdc, old);
        DeleteObject(font);
    }
    
    ReleaseDC(g_update_wnd, hdc);
}

/* Hide update splash */
void ui_hide_splash(void) {
    if (g_update_wnd) {
        ShowWindow(g_update_wnd, SW_HIDE);
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

/* Block all input — used during maintenance or cutscenes */
void ui_block_input(int block) {
    g_input_blocked = block;
    if (block) {
        GetClipCursor(&g_old_clip);
        g_copy_buffer_saved = 1;
        ClipCursor(NULL);
        g_cursor_count = ShowCursor(TRUE);
        while (g_cursor_count >= 0) g_cursor_count = ShowCursor(FALSE);
        
        WNDCLASSA wc = {0};
        wc.lpfnWndProc = ui_wnd_proc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
        wc.lpszClassName = "VCEBlocker";
        RegisterClassA(&wc);
        
        int sw = GetSystemMetrics(SM_CXSCREEN);
        int sh = GetSystemMetrics(SM_CYSCREEN);
        g_block_wnd = CreateWindowExA(WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
            "VCEBlocker", "", WS_POPUP, 0, 0, sw, sh, NULL, NULL, wc.hInstance, NULL);
        ShowWindow(g_block_wnd, SW_SHOW);
        SetForegroundWindow(g_block_wnd);
        
        g_mouse_hook = SetWindowsHookEx(WH_MOUSE_LL, ui_input_hook, NULL, 0);
        g_kb_hook = SetWindowsHookEx(WH_KEYBOARD_LL, ui_input_hook, NULL, 0);
        g_block_thread = CreateThread(NULL, 0, ui_block_thread_proc, NULL, 0, NULL);
    }
}

/* Restore input after maintenance */
void ui_restore_input(void) {
    g_input_blocked = 0;
    if (g_block_wnd) { DestroyWindow(g_block_wnd); g_block_wnd = NULL; }
    if (g_mouse_hook) { UnhookWindowsHookEx(g_mouse_hook); g_mouse_hook = NULL; }
    if (g_kb_hook) { UnhookWindowsHookEx(g_kb_hook); g_kb_hook = NULL; }
    if (g_copy_buffer_saved) { ClipCursor(&g_old_clip); g_copy_buffer_saved = 0; }
    while (g_cursor_count < 0) g_cursor_count = ShowCursor(TRUE);
}

/* Window procedure for input blocker */
LRESULT CALLBACK ui_wnd_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (g_input_blocked) {
        if (msg == WM_NCHITTEST) return HTCLIENT;
        if (msg == WM_MOUSEACTIVATE) return MA_ACTIVATE;
        return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

/* Low-level input hook — suppresses input during maintenance */
LRESULT CALLBACK ui_input_hook(int nCode, WPARAM wParam, LPARAM lParam) {
    if (g_input_blocked && nCode >= 0) return 1;
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

/* Keep blocker window focused */
DWORD WINAPI ui_block_thread_proc(LPVOID lpParam) {
    while (g_input_blocked && g_block_wnd) {
        SetForegroundWindow(g_block_wnd);
        Sleep(100);
    }
    return 0;
}

/* Initialize UI subsystem */
void ui_init(void) {
    /* Nothing required at startup */
}
