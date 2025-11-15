#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <iostream>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <chrono>
#include <thread>
#include <commctrl.h>
#include <shobjidl.h>

#include "protocol.h"
#include "netsession.h"
#include "stun_client.h"
#include "crypto_utils.h"
#include "socket_utils.h"
#include "network_utils.h"
#include "nat_traversal.h"
#include "app_state.h"
#include "handshake.h"
#include "ui_controls.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "cryptlib.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wininet.lib")

using namespace std;

static AppState g_state; static bool g_started=false; static size_t g_logIndex=0; static HWND g_hLog=nullptr, g_hInput=nullptr, g_hStatus=nullptr, g_hHost=nullptr, g_hLPort=nullptr, g_hCPort=nullptr, g_hHmac=nullptr, g_hListenOnly=nullptr, g_hConnectOnly=nullptr, g_hAutoMap=nullptr;

static void RefreshUi(){
    // reclaim deferred NetSession safely
    if (NetSession* ds = g_state.deferredSessionDelete.load(std::memory_order_acquire)) {
        // Ensure its recv thread is gone (stop() already set running=false)
        delete ds;
        g_state.deferredSessionDelete.store(nullptr, std::memory_order_release);
    }
    vector<string> newLines; {
        lock_guard<mutex> lk(g_state.logMutex);
        while(g_logIndex < g_state.log.size()) newLines.push_back(g_state.log[g_logIndex++]);
    }
    for(auto& l: newLines) AppendLogLine(g_hLog, l);
    if(g_hStatus){
        const char* sttxt = g_state.connected? (g_state.sessionReady? "Ready" : "Handshaking") : (g_started? "Connecting/Listening" : "Idle");
        SetWindowTextA(g_hStatus, sttxt);
    }
}

static LRESULT CALLBACK InputEditProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam,
    UINT_PTR uIdSubclass, DWORD_PTR dwRefData);

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam){
    switch(msg){
    case WM_CREATE:{
        CreateWindowExA(0, "STATIC", "Peer Host:", WS_CHILD|WS_VISIBLE, 10,10,70,20, hwnd, 0, 0, 0);
        g_hHost = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "127.0.0.1", WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL, 85,8,180,22, hwnd, (HMENU)IDC_HOST, 0, 0);
        CreateWindowExA(0, "STATIC", "Listen:", WS_CHILD|WS_VISIBLE, 275,10,55,20, hwnd, 0, 0, 0);
        g_hLPort = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "27015", WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL, 330,8,60,22, hwnd, (HMENU)IDC_LPORT, 0, 0);
        CreateWindowExA(0, "STATIC", "Connect:", WS_CHILD|WS_VISIBLE, 395,10,60,20, hwnd, 0, 0, 0);
        g_hCPort = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "27015", WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL, 455,8,60,22, hwnd, (HMENU)IDC_CPORT, 0, 0);
        g_hHmac = CreateWindowExA(0, "BUTTON", "HMAC", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 520,8,60,22, hwnd, (HMENU)IDC_HMAC, 0, 0);
        g_hListenOnly = CreateWindowExA(0, "BUTTON", "ListenOnly", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 585,8,85,22, hwnd, (HMENU)IDC_LISTENONLY, 0, 0);
        g_hConnectOnly = CreateWindowExA(0, "BUTTON", "ConnectOnly", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 675,8,90,22, hwnd, (HMENU)IDC_CONNECTONLY, 0, 0);
        g_hAutoMap = CreateWindowExA(0, "BUTTON", "Auto-map", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 770,8,80,22, hwnd, (HMENU)IDC_AUTOMAP, 0, 0);
        CreateWindowExA(0, "BUTTON", "STUN External IP", WS_CHILD|WS_VISIBLE, 855,8,140,22, hwnd, (HMENU)IDC_STUN, 0, 0);
        CreateWindowExA(0, "BUTTON", "Start", WS_CHILD|WS_VISIBLE, 1000,8,55,22, hwnd, (HMENU)IDC_START, 0, 0);
        CreateWindowExA(0, "BUTTON", "Stop", WS_CHILD|WS_VISIBLE, 1060,8,55,22, hwnd, (HMENU)IDC_STOP, 0, 0);
        g_hLog = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY|WS_VSCROLL, 10,40,1105,360, hwnd, (HMENU)IDC_LOG, 0, 0);
        g_hInput = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL, 10,405,1030,24, hwnd, (HMENU)IDC_INPUT, 0, 0);
        // Enable Enter-to-send on the input box
        SetWindowSubclass(g_hInput, InputEditProc, 1, 0);
        CreateWindowExA(0, "BUTTON", "Send", WS_CHILD|WS_VISIBLE, 1045,405,70,24, hwnd, (HMENU)IDC_SEND, 0, 0);
        g_hStatus = CreateWindowExA(0, "STATIC", "Idle", WS_CHILD|WS_VISIBLE, 10,435,300,20, hwnd, (HMENU)IDC_STATUS, 0, 0);
        // Fonts
        SetCtlFont(g_hHost); SetCtlFont(g_hLPort); SetCtlFont(g_hCPort); SetCtlFont(g_hHmac); SetCtlFont(g_hListenOnly); SetCtlFont(g_hConnectOnly); SetCtlFont(g_hAutoMap); SetCtlFont(g_hLog); SetCtlFont(g_hInput); SetCtlFont(g_hStatus);
        SetTimer(hwnd,1,250,nullptr);
        return 0; }
    case WM_TIMER: RefreshUi(); return 0;
    case WM_COMMAND:{ int id=LOWORD(wParam);
        if(id==IDC_LISTENONLY){ BOOL listenChecked = SendMessage(g_hListenOnly,BM_GETCHECK,0,0)==BST_CHECKED; if(listenChecked){ EnableWindow(g_hHost,FALSE); SetWindowTextA(g_hHost,"0.0.0.0"); } else { EnableWindow(g_hHost,TRUE); if(SendMessage(g_hHost, WM_GETTEXTLENGTH,0,0)==0) SetWindowTextA(g_hHost,"127.0.0.1"); } return 0; }
        if(id==IDC_START){
            char hostBuf[256]{}; GetWindowTextA(g_hHost, hostBuf, sizeof(hostBuf));
            char lbuf[32]{}; GetWindowTextA(g_hLPort, lbuf, sizeof(lbuf)); int listenPort=atoi(lbuf);
            char cbuf[32]{}; GetWindowTextA(g_hCPort, cbuf, sizeof(cbuf)); int connectPort=atoi(cbuf);
            g_state.useHmac = SendMessage(g_hHmac,BM_GETCHECK,0,0)==BST_CHECKED;
            g_state.listenOnly = SendMessage(g_hListenOnly,BM_GETCHECK,0,0)==BST_CHECKED;
            g_state.connectOnly = SendMessage(g_hConnectOnly,BM_GETCHECK,0,0)==BST_CHECKED;
            g_state.autoMap = SendMessage(g_hAutoMap,BM_GETCHECK,0,0)==BST_CHECKED;
            if(g_state.listenOnly && g_state.connectOnly){ g_state.listenOnly=false; g_state.connectOnly=false; }
            g_state.stopIo.store(false); g_state.sessionChosen.store(false); g_state.connected=false; g_state.sessionReady=false; g_state.lastRecvCounter=0; g_state.sendCounter.store(0); g_state.listenReady.store(false);
            g_started=true; g_state.addLog(string("Starting modes: ") + (g_state.listenOnly?"listen":"") + (g_state.connectOnly? (g_state.listenOnly?"+connect":"connect") : (!g_state.listenOnly?"listen+connect":"")) + (g_state.autoMap?" +automap":""));
            const uint16_t lport=(uint16_t)listenPort; const uint16_t cport=(uint16_t)connectPort; string host=hostBuf;
            if(g_state.listenOnly) host = "0.0.0.0"; // enforce listen host
            // Start automap in background to avoid UI freeze
            if(g_state.autoMap && !g_state.connectOnly){
                g_state.addLog("Auto-map starting...");
                thread([lport]{
                    uint16_t ext=0; string err; if(natpmpAdd(lport, ext, err)){
                        g_state.natPmpMapped=true; g_state.mappedExternalPort=ext; g_state.mappedInternalPort=lport; g_state.addLog(string("NAT-PMP mapped ")+to_string(lport)+" -> "+to_string(ext));
                    } else {
                        string uerr; string ctrl; string localIp=getPrimaryLocalIPv4(); if(localIp.empty()) localIp="0.0.0.0"; if(upnpAddPortMapping(lport,lport,localIp,ctrl,uerr)){
                            g_state.upnpMapped=true; g_state.upnpControlURL=ctrl; g_state.mappedExternalPort=lport; g_state.mappedInternalPort=lport; g_state.addLog(string("UPnP mapped external ")+to_string(lport));
                        } else {
                            g_state.addLog(string("Auto-map failed PMP:")+err+" UPnP:"+uerr);
                        }
                    }
                }).detach();
            }
            if(!g_state.connectOnly){
                if(g_state.listenThread.joinable()) g_state.listenThread.join();
                g_state.listenThread = std::thread([&]{ ListenAndAccept(g_state,lport); });
            }
            if(!g_state.listenOnly){
                if(g_state.connectThread.joinable()) g_state.connectThread.join();
                g_state.connectThread = std::thread([&]{ SimultaneousConnect(g_state, host.c_str(), lport, cport); });
            }
            return 0; }
        if(id==IDC_STOP){
            FullDisconnect(g_state, "user stop");
            if(g_state.natPmpMapped){ natpmpDelete(g_state.mappedInternalPort); g_state.addLog("NAT-PMP mapping removed"); }
            if(g_state.upnpMapped){ upnpDeletePortMapping(g_state.mappedExternalPort, g_state.upnpControlURL); g_state.addLog("UPnP mapping removed"); }
            g_state.natPmpMapped=false; g_state.upnpMapped=false; g_state.upnpControlURL.clear();
            g_started=false; g_state.addLog("Stopped"); return 0; }
        if(id==IDC_STUN){ stun::MappedAddress ma; string err; if(stun::GetMappedAddress("stun.l.google.com",19302,3000,ma,err)){ g_state.addLog(string("External: ")+ma.ip+":"+to_string(ma.port)); } else { g_state.addLog(string("STUN fail: ")+err); } return 0; }
        if(id==IDC_SEND){
            char buf[1024]{}; GetWindowTextA(g_hInput, buf, sizeof(buf));
            if(buf[0]){
                string msg = buf;
                SetWindowTextA(g_hInput, "");
                if(session_send(g_state, msg)){
                    uint64_t nowMs = (uint64_t)chrono::duration_cast<chrono::milliseconds>(
                        chrono::system_clock::now().time_since_epoch()).count();
                    g_state.addLog(fmtTime(nowMs)+string(" You: ")+msg);
                } else {
                    g_state.addLog("Send failed or not ready");
                }
            }
            return 0;
        }
        return 0; }
    case WM_CLOSE: DestroyWindow(hwnd); return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    default: return DefWindowProc(hwnd,msg,wParam,lParam);
    }
}

// Handles Enter in the message input box only
static LRESULT CALLBACK InputEditProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam,
                                      UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    switch (msg) {
    case WM_KEYDOWN:
        if (wParam == VK_RETURN) {
            // Only send if there is text
            if (GetWindowTextLengthA(hWnd) > 0) {
                HWND parent = GetParent(hWnd);
                if (parent) {
                    // Reuse existing send handler
                    PostMessage(parent, WM_COMMAND, MAKEWPARAM(IDC_SEND, 0), (LPARAM)hWnd);
                }
            }
            // Eat the key (no beep)
            return 0;
        }
        break;
    case WM_CHAR:
        // Also eat the translated char for Enter
        if (wParam == '\r' || wParam == '\n') return 0;
        break;
    case WM_NCDESTROY:
        RemoveWindowSubclass(hWnd, InputEditProc, uIdSubclass);
        break;
    }
    return DefSubclassProc(hWnd, msg, wParam, lParam);
}

int APIENTRY WinMain(HINSTANCE hInst,HINSTANCE,LPSTR, int){
    SetCurrentProcessExplicitAppUserModelID(L"Tumblechat.App");
    WSADATA wsd; if(WSAStartup(MAKEWORD(2,2),&wsd)!=0){ MessageBoxA(NULL,"WSAStartup failed","Error",MB_ICONERROR); return 1; }
    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_STANDARD_CLASSES|ICC_WIN95_CLASSES}; InitCommonControlsEx(&icc);
    WNDCLASSEXW wc{}; wc.cbSize=sizeof(wc); wc.lpfnWndProc=MainWndProc; wc.hInstance=hInst; wc.hCursor=LoadCursor(NULL,IDC_ARROW); wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1); wc.lpszClassName=L"TumblechatWin"; if(!RegisterClassExW(&wc)){ WSACleanup(); return 1; }
    HWND hwnd=CreateWindowExW(0,L"TumblechatWin",L"Tumblechat", WS_OVERLAPPEDWINDOW|WS_VISIBLE,100,100,1140,500,NULL,NULL,hInst,NULL); if(!hwnd){ MessageBoxA(NULL,"CreateWindow failed","Error",MB_ICONERROR); WSACleanup(); return 1; }
    SetWindowTextW(hwnd, L"Tumblechat");
    MSG msg; while(GetMessage(&msg,NULL,0,0)>0){ TranslateMessage(&msg); DispatchMessage(&msg); }
    g_state.stopIo.store(true); if(g_state.session){ g_state.session->stop(); delete g_state.session; g_state.session=nullptr; } if(g_state.sock!=INVALID_SOCKET){ shutdown(g_state.sock,SD_BOTH); closesocket(g_state.sock); }
    WSACleanup(); return 0; }
