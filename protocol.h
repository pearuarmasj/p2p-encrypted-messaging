#pragma once
#include <cstdint>
#include <vector>
#include <winsock2.h>

// Message types
enum class MsgType : uint8_t {
    PublicKey   = 0x01,  // RSA public key
    // One-time session AES key wrapped with RSA (client->server or server->client)
    SessionKey  = 0x02,
    // ACK for session setup
    SessionOk   = 0x03,
    // Error in session (e.g., decrypt/processing error)
    SessionError= 0x04,
    // PeerId/Version exchange
    PeerHello   = 0x05,
    // ECDH public key exchange (new for hybrid encryption)
    ECDHPublicKey = 0x06,
    // Application data encrypted with established session AES key
    Data        = 0x11
};

inline bool sendAll(SOCKET s, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = send(s, reinterpret_cast<const char*>(data + sent), (int)(len - sent), 0);
        if (n == SOCKET_ERROR) return false;
        sent += (size_t)n;
    }
    return true;
}

inline bool recvAll(SOCKET s, uint8_t* data, size_t len) {
    size_t recvd = 0;
    while (recvd < len) {
        int n = recv(s, reinterpret_cast<char*>(data + recvd), (int)(len - recvd), 0);
        if (n == 0) return false;
        if (n == SOCKET_ERROR) return false;
        recvd += (size_t)n;
    }
    return true;
}

inline bool writeFrame(SOCKET s, MsgType type, const std::vector<uint8_t>& payload) {
    uint32_t totalLen = 1u + (uint32_t)payload.size();
    uint8_t hdr[4];
    hdr[0] = (uint8_t)((totalLen >> 24) & 0xFF);
    hdr[1] = (uint8_t)((totalLen >> 16) & 0xFF);
    hdr[2] = (uint8_t)((totalLen >> 8) & 0xFF);
    hdr[3] = (uint8_t)(totalLen & 0xFF);

    if (!sendAll(s, hdr, 4)) return false;
    uint8_t t = static_cast<uint8_t>(type);
    if (!sendAll(s, &t, 1)) return false;
    if (!payload.empty()) {
        if (!sendAll(s, payload.data(), payload.size())) return false;
    }
    return true;
}

inline bool readFrame(SOCKET s, MsgType& type, std::vector<uint8_t>& payload) {
    uint8_t hdr[4];
    if (!recvAll(s, hdr, 4)) return false;
    uint32_t totalLen = (uint32_t)hdr[0] << 24 | (uint32_t)hdr[1] << 16 | (uint32_t)hdr[2] << 8 | (uint32_t)hdr[3];
    if (totalLen < 1) return false;
    uint8_t t;
    if (!recvAll(s, &t, 1)) return false;
    type = (MsgType)t;
    uint32_t payloadLen = totalLen - 1;
    payload.resize(payloadLen);
    if (payloadLen > 0) {
        if (!recvAll(s, payload.data(), payloadLen)) return false;
    }
    return true;
}
