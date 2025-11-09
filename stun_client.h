#pragma once
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <cstring>
#include <string>
#include <vector>
#include <osrng.h>

namespace stun {
struct MappedAddress { std::string ip; uint16_t port; };

inline bool GetMappedAddress(const char* server, uint16_t port, int timeoutMs, MappedAddress& out, std::string& err){
    out.ip.clear(); out.port=0; err.clear();
    addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_DGRAM; addrinfo* res=nullptr;
    if(getaddrinfo(server, nullptr, &hints, &res)!=0 || !res){ err = "DNS"; return false; }
    sockaddr_in sin{}; sin.sin_family=AF_INET; sin.sin_port = htons(port); sin.sin_addr = ((sockaddr_in*)res->ai_addr)->sin_addr; freeaddrinfo(res);
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); if(s==INVALID_SOCKET){ err="socket"; return false; }
    struct StunHeader { uint16_t type; uint16_t length; uint32_t cookie; uint32_t id[3]; } hdr{};
    hdr.type = htons(0x0001); hdr.length = htons(0); hdr.cookie = htonl(0x2112A442); CryptoPP::AutoSeededRandomPool rng; rng.GenerateBlock((uint8_t*)hdr.id, sizeof(hdr.id));
    if(sendto(s,(const char*)&hdr,sizeof(hdr),0,(sockaddr*)&sin,sizeof(sin))==SOCKET_ERROR){ err="send"; closesocket(s); return false; }
    fd_set fds; FD_ZERO(&fds); FD_SET(s,&fds); timeval tv{ timeoutMs/1000, (timeoutMs%1000)*1000 }; int sel = select(0,&fds,nullptr,nullptr,&tv); if(sel<=0){ err="timeout"; closesocket(s); return false; }
    uint8_t buf[512]; sockaddr_in from{}; int fromLen = sizeof(from); int r = recvfrom(s,(char*)buf,sizeof(buf),0,(sockaddr*)&from,&fromLen); closesocket(s); if(r<20){ err="short"; return false; }
    if(r<(int)sizeof(StunHeader)){ err="hdrshort"; return false; }
    // parse attributes
    size_t idx = sizeof(StunHeader); while(idx + 4 <= (size_t)r){ uint16_t atype = (buf[idx]<<8)|buf[idx+1]; uint16_t alen = (buf[idx+2]<<8)|buf[idx+3]; idx+=4; if(idx + alen > (size_t)r) break; if(atype==0x0020 || atype==0x0001){ if(alen>=8){ uint8_t family = buf[idx+1]; uint16_t xport = (buf[idx+2]<<8)|buf[idx+3]; uint32_t xip = (buf[idx+4]<<24)|(buf[idx+5]<<16)|(buf[idx+6]<<8)|buf[idx+7]; if(atype==0x0020){ xport ^= 0x2112; xip ^= 0x2112A442; } if(family==0x01){ in_addr ia; ia.S_un.S_addr = htonl(xip); char ipstr[64]; inet_ntop(AF_INET,&ia,ipstr,sizeof(ipstr)); out.ip = ipstr; out.port = xport; return true; } } } idx += alen; if(alen % 4) idx += (4 - (alen % 4)); }
    err="nomap"; return false;
}
} // namespace stun
