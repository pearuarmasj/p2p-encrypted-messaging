#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <wininet.h>
#include <string>
#include <vector>
#include <cstring>

// NAT-PMP helper functions
static inline const char* natpmpResultDesc(uint16_t rc) {
    switch (rc) {
    case 0: return "success";
    case 1: return "unsupported version";
    case 2: return "not authorized/refused";
    case 3: return "network failure";
    case 4: return "out of resources";
    case 5: return "unsupported opcode";
    default: return "unknown";
    }
}

// Common gateway discovery function (eliminates duplication)
static inline bool discoverGateway(std::string& gwOut) {
    ULONG sz = 0;
    GetAdaptersInfo(nullptr, &sz);
    if (sz == 0) {
        return false;
    }
    std::vector<char> buf(sz);
    IP_ADAPTER_INFO* ai = (IP_ADAPTER_INFO*)buf.data();
    if (GetAdaptersInfo(ai, &sz) != NO_ERROR) {
        return false;
    }
    for (auto p = ai; p; p = p->Next) {
        if (strlen(p->GatewayList.IpAddress.String) > 0) {
            gwOut = p->GatewayList.IpAddress.String;
            return true;
        }
    }
    return false;
}

static inline bool natpmpAdd(uint16_t internalPort, uint16_t& externalPortOut, std::string& err) {
    // Request mapping TCP with desired external == internal
    sockaddr_in g{};
    std::string gw;
    if (!discoverGateway(gw)) {
        err = "no gw";
        return false;
    }
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) {
        err = "sock";
        return false;
    }
    g.sin_family = AF_INET;
    g.sin_port = htons(5351);
    if (InetPtonA(AF_INET, gw.c_str(), &g.sin_addr) != 1) {
        closesocket(s);
        err = "inet";
        return false;
    }
    unsigned char req[12]{};
    req[0] = 0;
    req[1] = 2; // TCP
    req[4] = (internalPort >> 8) & 0xFF;
    req[5] = internalPort & 0xFF; // internal port
    req[6] = (internalPort >> 8) & 0xFF;
    req[7] = internalPort & 0xFF; // request same external
    uint32_t lifetime = 3600;
    req[8] = (lifetime >> 24) & 0xFF;
    req[9] = (lifetime >> 16) & 0xFF;
    req[10] = (lifetime >> 8) & 0xFF;
    req[11] = lifetime & 0xFF;
    if (sendto(s, (char*)req, 12, 0, (sockaddr*)&g, sizeof(g)) != 12) {
        closesocket(s);
        err = "send";
        return false;
    }
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    timeval tv{ 2, 0 };
    if (select(0, &fds, nullptr, nullptr, &tv) <= 0) {
        closesocket(s);
        err = "timeout";
        return false;
    }
    unsigned char resp[32];
    int r = recv(s, (char*)resp, sizeof(resp), 0);
    closesocket(s);
    if (r < 16) {
        err = "short";
        return false;
    }
    if (resp[0] != 0 || resp[1] != (unsigned char)(2 | 0x80)) {
        err = "bad op";
        return false;
    }
    uint16_t rc = (resp[2] << 8) | resp[3];
    if (rc != 0) {
        err = std::string("rc ") + std::to_string(rc) + " (" + natpmpResultDesc(rc) + ")";
        return false;
    }
    externalPortOut = (uint16_t)((resp[10] << 8) | resp[11]); // correct external port position
    return true;
}

static inline bool natpmpDelete(uint16_t internalPort) {
    sockaddr_in g{};
    std::string gw;
    if (!discoverGateway(gw))
        return false;
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET)
        return false;
    g.sin_family = AF_INET;
    g.sin_port = htons(5351);
    if (InetPtonA(AF_INET, gw.c_str(), &g.sin_addr) != 1) {
        closesocket(s);
        return false;
    }
    unsigned char req[12]{};
    req[0] = 0;
    req[1] = 2;
    req[4] = (internalPort >> 8) & 0xFF;
    req[5] = internalPort & 0xFF;
    req[6] = (internalPort >> 8) & 0xFF;
    req[7] = internalPort & 0xFF; // ext same
    // lifetime 0 -> delete
    req[8] = 0;
    req[9] = 0;
    req[10] = 0;
    req[11] = 0;
    sendto(s, (char*)req, 12, 0, (sockaddr*)&g, sizeof(g));
    closesocket(s);
    return true;
}

// UPnP discovery and mapping
static inline bool upnpDiscoverControlURL(std::string& controlURL, std::string& hostPort, std::string& path) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET)
        return false;
    int ttl = 2;
    setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (char*)&ttl, sizeof(ttl));
    sockaddr_in m{};
    m.sin_family = AF_INET;
    m.sin_port = htons(1900);
    InetPtonA(AF_INET, "239.255.255.250", &m.sin_addr);
    std::string req1 = "M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:2\r\nST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
    std::string req2 = "M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:2\r\nST:upnp:rootdevice\r\n\r\n";
    sendto(s, req1.c_str(), (int)req1.size(), 0, (sockaddr*)&m, sizeof(m));
    sendto(s, req2.c_str(), (int)req2.size(), 0, (sockaddr*)&m, sizeof(m));
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    timeval tv{ 3, 0 };
    if (select(0, &fds, nullptr, nullptr, &tv) <= 0) {
        closesocket(s);
        return false;
    }
    char buf[4096];
    int r = recv(s, buf, sizeof(buf) - 1, 0);
    closesocket(s);
    if (r <= 0) {
        return false;
    }
    buf[r] = 0;
    std::string resp(buf);
    auto pos = resp.find("LOCATION:");
    if (pos == std::string::npos)
        return false;
    auto end = resp.find('\n', pos);
    std::string loc = resp.substr(pos + 9, end - pos - 9);
    while (!loc.empty() && (loc[0] == ' ' || loc[0] == '\r'))
        loc.erase(loc.begin());
    while (!loc.empty() && (loc.back() == '\r' || loc.back() == '\n'))
        loc.pop_back();
    HINTERNET hi = InternetOpenA("P2PChat", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hi)
        return false;
    HINTERNET hf = InternetOpenUrlA(hi, loc.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hf) {
        InternetCloseHandle(hi);
        return false;
    }
    std::string xml;
    char xbuf[2048];
    DWORD rd = 0;
    while (InternetReadFile(hf, xbuf, sizeof(xbuf), &rd) && rd > 0)
        xml.append(xbuf, rd);
    InternetCloseHandle(hf);
    InternetCloseHandle(hi);
    auto svc = xml.find("urn:schemas-upnp-org:service:WANIPConnection:1");
    if (svc == std::string::npos)
        svc = xml.find("urn:schemas-upnp-org:service:WANPPPConnection:1");
    if (svc == std::string::npos)
        return false;
    auto cp = xml.find("<controlURL>", svc);
    if (cp == std::string::npos)
        return false;
    auto ce = xml.find("</controlURL>", cp);
    if (ce == std::string::npos)
        return false;
    path = xml.substr(cp + 12, ce - (cp + 12));
    auto protoEnd = loc.find("://");
    if (protoEnd == std::string::npos)
        return false;
    auto hostStart = protoEnd + 3;
    auto slash = loc.find('/', hostStart);
    hostPort = loc.substr(hostStart, slash == std::string::npos ? std::string::npos : slash - hostStart);
    if (path.empty() || path[0] != '/')
        path = "/" + path;
    controlURL = loc.substr(0, hostStart) + hostPort + path;
    return true;
}

static inline bool upnpAddPortMapping(uint16_t externalPort, uint16_t internalPort,
    const std::string& internalClient, std::string& controlURL, std::string& err) {
    std::string hostPort, path;
    if (!upnpDiscoverControlURL(controlURL, hostPort, path)) {
        err = "discover";
        return false;
    }
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        err = "sock";
        return false;
    }
    std::string host = hostPort;
    std::string port = "80";
    auto colon = hostPort.find(':');
    if (colon != std::string::npos) {
        host = hostPort.substr(0, colon);
        port = hostPort.substr(colon + 1);
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)atoi(port.c_str()));
    if (InetPtonA(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        err = "inet";
        closesocket(s);
        return false;
    }
    if (connect(s, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        err = "connect";
        closesocket(s);
        return false;
    }
    std::string body = "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewExternalPort>" + std::to_string(externalPort) + "</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>" + std::to_string(internalPort) + "</NewInternalPort><NewInternalClient>" + internalClient + "</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>P2PChat</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>";
    std::string req = "POST " + path + " HTTP/1.1\r\nHOST: " + hostPort + "\r\nCONTENT-TYPE: text/xml; charset=\"utf-8\"\r\nCONTENT-LENGTH: " + std::to_string(body.size()) + "\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\n\r\n" + body;
    send(s, req.c_str(), (int)req.size(), 0);
    char resp[2048];
    int r = recv(s, resp, sizeof(resp) - 1, 0);
    closesocket(s);
    if (r <= 0) {
        err = "noresp";
        return false;
    }
    resp[r] = 0;
    if (std::string(resp).find("200 OK") == std::string::npos) {
        err = "http";
        return false;
    }
    return true;
}

static inline void upnpDeletePortMapping(uint16_t externalPort, const std::string& controlURL) {
    if (controlURL.empty())
        return;
    std::string hostPortPath = controlURL.substr(controlURL.find("://") + 3);
    auto slash = hostPortPath.find('/');
    if (slash == std::string::npos)
        return;
    std::string hostPort = hostPortPath.substr(0, slash);
    std::string path = hostPortPath.substr(slash);
    std::string host = hostPort;
    std::string port = "80";
    auto colon = hostPort.find(':');
    if (colon != std::string::npos) {
        host = hostPort.substr(0, colon);
        port = hostPort.substr(colon + 1);
    }
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        return;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)atoi(port.c_str()));
    if (InetPtonA(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        closesocket(s);
        return;
    }
    if (connect(s, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s);
        return;
    }
    std::string body = "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:DeletePortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewExternalPort>" + std::to_string(externalPort) + "</NewExternalPort><NewProtocol>TCP</NewProtocol></u:DeletePortMapping></s:Body></s:Envelope>";
    std::string req = "POST " + path + " HTTP/1.1\r\nHOST: " + hostPort + "\r\nCONTENT-TYPE: text/xml; charset=\"utf-8\"\r\nCONTENT-LENGTH: " + std::to_string(body.size()) + "\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping\"\r\n\r\n" + body;
    send(s, req.c_str(), (int)req.size(), 0);
    char buf[512];
    recv(s, buf, sizeof(buf), 0);
    closesocket(s);
}
