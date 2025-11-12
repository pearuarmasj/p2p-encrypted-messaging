#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <string>
#include <vector>
#include <cstring>

// String utility
static inline std::string trimCopy(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos)
        return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// IPv4 literal detection
static inline bool isLikelyIPv4Literal(const std::string& s) {
    int dots = 0;
    for (char c : s) {
        if (c == '.')
            ++dots;
        else if (c < '0' || c > '9')
            return false;
    }
    return dots == 3;
}

// Resolve hostname or IPv4 literal to in_addr
static inline bool resolveHostIPv4(const std::string& host, in_addr& out) {
    std::string h = trimCopy(host);
    if (isLikelyIPv4Literal(h)) {
        return InetPtonA(AF_INET, h.c_str(), &out) == 1;
    }
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    addrinfo* res = nullptr;
    if (getaddrinfo(h.c_str(), nullptr, &hints, &res) != 0)
        return false;
    bool ok = false;
    for (addrinfo* p = res; p; p = p->ai_next) {
        sockaddr_in* sin = (sockaddr_in*)p->ai_addr;
        if (sin) {
            out = sin->sin_addr;
            ok = true;
            break;
        }
    }
    if (res)
        freeaddrinfo(res);
    return ok;
}

// Get primary local IPv4 address
static inline std::string getPrimaryLocalIPv4() {
    ULONG bufLen = 15 * 1024;
    std::vector<char> buf(bufLen);
    IP_ADAPTER_ADDRESSES* addrs = (IP_ADAPTER_ADDRESSES*)buf.data();
    if (GetAdaptersAddresses(AF_INET,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        nullptr, addrs, &bufLen) != NO_ERROR)
        return {};
    std::string fallback;
    for (auto p = addrs; p; p = p->Next) {
        if (p->OperStatus != IfOperStatusUp)
            continue;
        for (auto u = p->FirstUnicastAddress; u; u = u->Next) {
            sockaddr_in* sin = (sockaddr_in*)u->Address.lpSockaddr;
            if (!sin)
                continue;
            char ip[64];
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
            std::string ipStr = ip;
            if (ipStr == "127.0.0.1")
                continue;
            if (ipStr.rfind("10.", 0) == 0 ||
                ipStr.rfind("192.168.", 0) == 0 ||
                (ipStr.rfind("172.", 0) == 0 && [&] {
                size_t dot = ipStr.find('.', 4);
                if (dot == std::string::npos)
                    return false;
                int second = atoi(ipStr.substr(4, dot - 4).c_str());
                return second >= 16 && second <= 31;
                    }()))
                return ipStr;
            if (fallback.empty())
                fallback = ipStr;
        }
    }
    return fallback;
}

// Check if an address is local
static inline bool isLocalAddress(in_addr addr) {
    char candidate[64];
    inet_ntop(AF_INET, &addr, candidate, sizeof(candidate));
    // Enumerate local adapter IPv4s
    ULONG bufLen = 15 * 1024;
    std::vector<char> buf(bufLen);
    IP_ADAPTER_ADDRESSES* addrs = (IP_ADAPTER_ADDRESSES*)buf.data();
    if (GetAdaptersAddresses(AF_INET, 0, nullptr, addrs, &bufLen) != NO_ERROR)
        return false;
    for (auto p = addrs; p; p = p->Next) {
        for (auto u = p->FirstUnicastAddress; u; u = u->Next) {
            sockaddr_in* sin = (sockaddr_in*)u->Address.lpSockaddr;
            if (!sin)
                continue;
            char ip[64];
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
            if (strcmp(ip, candidate) == 0)
                return true;
        }
    }
    return false;
}

// Determine if hairpin bind is needed
static inline bool shouldHairpinBind(bool connectOnly, const char* remoteHost, in_addr resolved) {
    if (connectOnly) {
        // For connect-only we normally skip bind; exception: hairpin/self
        return isLocalAddress(resolved);
    }
    // In simultaneous-open mode binding is expected anyway
    return true;
}
