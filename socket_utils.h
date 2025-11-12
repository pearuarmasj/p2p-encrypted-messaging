#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <string>
#include <sstream>
#include <cstring>

// Socket helper functions
static inline void set_nodelay(SOCKET s) {
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&one, sizeof(one));
}

static inline void set_keepalive(SOCKET s, DWORD idleMs, DWORD intervalMs, DWORD count) {
    BOOL on = TRUE;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char*)&on, sizeof(on));
    tcp_keepalive ka{};
    ka.onoff = 1;
    ka.keepalivetime = idleMs;
    ka.keepaliveinterval = intervalMs;
    DWORD bytesRet = 0;
    WSAIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), nullptr, 0, &bytesRet, nullptr, nullptr);
}

static inline std::string sock_tuple_str(SOCKET s) {
    sockaddr_in a{}, b{};
    int al = sizeof(a), bl = sizeof(b);
    std::stringstream ss;
    if (getsockname(s, (sockaddr*)&a, &al) == 0) {
        char lip[64]{};
        inet_ntop(AF_INET, &a.sin_addr, lip, sizeof(lip));
        ss << lip << ":" << ntohs(a.sin_port);
    } else {
        ss << "?:?";
    }
    ss << " -> ";
    if (getpeername(s, (sockaddr*)&b, &bl) == 0) {
        char rip[64]{};
        inet_ntop(AF_INET, &b.sin_addr, rip, sizeof(rip));
        ss << rip << ":" << ntohs(b.sin_port);
    } else {
        ss << "?:?";
    }
    return ss.str();
}
