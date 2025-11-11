#pragma once

#include <windows.h>
#include <string>

// UI control IDs
#define IDC_HOST        1001
#define IDC_LPORT       1002
#define IDC_CPORT       1003
#define IDC_HMAC        1004
#define IDC_LISTENONLY  1005
#define IDC_CONNECTONLY 1006
#define IDC_AUTOMAP     1007
#define IDC_STUN        1008
#define IDC_START       1009
#define IDC_STOP        1010
#define IDC_LOG         1011
#define IDC_INPUT       1012
#define IDC_SEND        1013
#define IDC_STATUS      1014

// UI helper functions
static inline void SetCtlFont(HWND h) {
    SendMessage(h, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
}

static inline void AppendLogLine(HWND g_hLog, const std::string& line) {
    if (!g_hLog)
        return;
    int len = GetWindowTextLengthA(g_hLog);
    SendMessage(g_hLog, EM_SETSEL, len, len);
    std::string s = line + "\r\n";
    SendMessageA(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)s.c_str());
}
