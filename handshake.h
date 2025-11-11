#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <chrono>
#include <thread>

#include "app_state.h"
#include "crypto_utils.h"
#include "socket_utils.h"
#include "network_utils.h"
#include "protocol.h"

// Forward declaration
static void FullDisconnect(AppState& st, const char* reason);

// Session send function
static inline bool session_send(struct AppState& st, const std::string& msg) {
    if (!st.connected || !st.session || !st.sessionReady)
        return false;
    uint64_t ctr = ++st.sendCounter;
    std::vector<uint8_t> out;
    if (!makeDataPayload(st.sessionKey, ctr, msg, st.rng, out, st.useHmac))
        return false;
    return st.session->sendFrame(MsgType::Data, out);
}

// Outbound handshake logic
static inline bool DoOutboundHandshake(AppState& st, SOCKET s, const char* label) {
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(st.rng, 3072);
    st.priv = CryptoPP::RSA::PrivateKey(params);
    st.pub = CryptoPP::RSA::PublicKey(params);
    loadOrCreatePeerId(st.localPeerId);
    std::vector<uint8_t> mypub = serializePublicKey(st.pub);
    if (!writeFrame(s, MsgType::PublicKey, mypub)) {
        st.addLog(std::string(label) + " send PublicKey failed");
        return false;
    }
    MsgType t;
    std::vector<uint8_t> payload;
    if (!readFrame(s, t, payload) || t != MsgType::PublicKey) {
        st.addLog(std::string(label) + " expected PublicKey");
        return false;
    }
    if (!loadPublicKey(payload.data(), payload.size(), st.peerPub)) {
        st.addLog(std::string(label) + " bad PublicKey");
        return false;
    }
    std::vector<uint8_t> remoteId;
    uint8_t remoteRole = 1;
    if (!sendPeerHello(s, st.localPeerId, 0) || !recvPeerHello(s, remoteId, remoteRole)) {
        st.addLog(std::string(label) + " PeerHello fail");
        return false;
    }
    if (st.sessionChosen.load()) {
        st.addLog(std::string(label) + " loser (already chosen)");
        return false;
    }
    st.remotePeerId = remoteId;
    st.sock = s;
    st.connected = true;
    st.addLog(std::string(label) + " connected");
    st.session = new NetSession(st.sock);
    st.session->onMessage([&](MsgType mt, const std::vector<uint8_t>& data) {
        if (mt == MsgType::SessionOk) {
            if (st.pendingRekey) {
                st.sessionKey.Assign(st.pendingKey.data(), st.pendingKey.size());
                st.pendingRekey = false;
                st.lastRecvCounter = 0;
                st.sendCounter.store(0);
                st.addLog("Re-key complete");
            }
            st.sessionReady = true;
            st.addLog("Session ready");
            st.nextRekey = std::chrono::steady_clock::now() + std::chrono::seconds(60);
            st.sessionChosen.store(true);
            return;
        }
        if (mt == MsgType::Data) {
            if (!st.sessionReady) {
                st.addLog("Data before session ready");
                return;
            }
            uint64_t ctr, ts;
            std::string msg, err;
            if (!parseDataPayload(st.sessionKey, data, ctr, ts, msg, st.useHmac, err)) {
                st.addLog(std::string("Recv error: ") + err);
                return;
            }
            if (ctr <= st.lastRecvCounter) {
                st.addLog("Duplicate/out-of-order");
                return;
            }
            st.lastRecvCounter = ctr;
            st.addLog(fmtTime(ts) + std::string(" Peer: ") + msg);
            return;
        }
        });
    st.session->onClosed([&] { FullDisconnect(st, "peer closed"); });
    st.session->onError([&] { FullDisconnect(st, "session error"); });
    st.session->start();
    st.sessionKey.CleanNew(32);
    st.rng.GenerateBlock(st.sessionKey, st.sessionKey.size());
    std::vector<uint8_t> wrapped = rsaWrapAesKey(st.peerPub, st.sessionKey);
    std::vector<uint8_t> skPayload;
    uint16_t klen = (uint16_t)wrapped.size();
    st.addLog(std::string(label) + " preparing SessionKey frame (" + std::to_string(klen) + " bytes wrapped)");
    skPayload.push_back((uint8_t)((klen >> 8) & 0xFF));
    skPayload.push_back((uint8_t)(klen & 0xFF));
    skPayload.insert(skPayload.end(), wrapped.begin(), wrapped.end());
    if (!st.session->sendFrame(MsgType::SessionKey, skPayload)) {
        st.addLog(std::string(label) + " SessionKey send failed");
        FullDisconnect(st, "sessionkey send fail");
        return false;
    }
    st.addLog(std::string(label) + " SessionKey sent, waiting for SessionOk");
    return true;
}

// Simultaneous connect logic
static inline void SimultaneousConnect(AppState& st, const char* remoteHost, uint16_t listenPort, uint16_t remotePort) {
    if (st.listenOnly)
        return;

    if (remoteHost && strcmp(remoteHost, "0.0.0.0") == 0) {
        st.addLog("[connect] remote 0.0.0.0 invalid");
        return;
    }

    in_addr resolved{};
    if (!resolveHostIPv4(remoteHost, resolved)) {
        st.addLog(std::string("[connect] cannot resolve host: ") + remoteHost);
        return;
    }

    char iptxt[64];
    inet_ntop(AF_INET, &resolved, iptxt, sizeof(iptxt));
    st.addLog(std::string("[connect] input host '") + remoteHost + "' -> resolved " + iptxt);

    bool hairpin = shouldHairpinBind(st.connectOnly, remoteHost, resolved);
    if (hairpin)
        st.addLog("[connect] hairpin/self detected -> binding source port");

    sockaddr_in raddr{};
    raddr.sin_family = AF_INET;
    raddr.sin_addr = resolved;
    raddr.sin_port = htons(remotePort);

    SOCKET cs = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (cs == INVALID_SOCKET) {
        st.addLog("[connect] socket failed");
        return;
    }
    BOOL yes = 1;
    setsockopt(cs, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));

    if (hairpin) {
        sockaddr_in laddr{};
        laddr.sin_family = AF_INET;
        laddr.sin_addr.s_addr = htonl(INADDR_ANY);
        laddr.sin_port = htons(listenPort);
        if (::bind(cs, (SOCKADDR*)&laddr, sizeof(laddr)) == SOCKET_ERROR) {
            st.addLog("[connect] bind failed");
            closesocket(cs);
            return;
        }
    }

    u_long nb = 1;
    ioctlsocket(cs, FIONBIO, &nb);
    int cr = ::connect(cs, (SOCKADDR*)&raddr, sizeof(raddr));
    if (cr == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e != WSAEWOULDBLOCK && e != WSAEINPROGRESS) {
            st.addLog(std::string("[connect] connect fail to ") + iptxt + ":" + std::to_string(remotePort) + " err=" + std::to_string(e));
            closesocket(cs);
            return;
        }
    }

    st.addLog(std::string("[connect] pending to ") + iptxt + ":" + std::to_string(remotePort) + (hairpin ? " (hairpin)" : ""));
    auto start = std::chrono::steady_clock::now();
    while (!st.stopIo.load() && !st.sessionChosen.load()) {
        if (std::chrono::steady_clock::now() - start > std::chrono::seconds(15)) {
            st.addLog("[connect] timeout");
            break;
        }
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(cs, &wfds);
        timeval tv{ 0, 200 * 1000 };
        int sel = select(0, nullptr, &wfds, nullptr, &tv);
        if (sel > 0 && FD_ISSET(cs, &wfds)) {
            int soerr = 0;
            int slen = sizeof(soerr);
            getsockopt(cs, SOL_SOCKET, SO_ERROR, (char*)&soerr, &slen);
            if (soerr == 0) {
                nb = 0;
                ioctlsocket(cs, FIONBIO, &nb);
                SOCKET s = cs;
                cs = INVALID_SOCKET;
                set_nodelay(s);
                st.addLog(std::string("[connect] tuple ") + sock_tuple_str(s));
                if (!DoOutboundHandshake(st, s, "[connect]")) {
                    st.addLog("[connect] handshake failed");
                }
                return;
            } else {
                st.addLog(std::string("[connect] so_error=") + std::to_string(soerr));
                closesocket(cs);
                return;
            }
        }
    }
    if (cs != INVALID_SOCKET)
        closesocket(cs);
}

// Listen and accept logic
static inline void ListenAndAccept(AppState& st, uint16_t port) {
    if (st.connectOnly)
        return;
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ls == INVALID_SOCKET) {
        st.addLog("[listen] socket failed");
        return;
    }
    BOOL yes = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
    sockaddr_in svc{};
    svc.sin_family = AF_INET;
    svc.sin_addr.s_addr = htonl(INADDR_ANY);
    svc.sin_port = htons(port);
    if (::bind(ls, (SOCKADDR*)&svc, sizeof(svc)) == SOCKET_ERROR) {
        st.addLog("[listen] bind failed");
        closesocket(ls);
        return;
    }
    if (::listen(ls, 1) == SOCKET_ERROR) {
        st.addLog("[listen] listen failed");
        closesocket(ls);
        return;
    }
    st.listenReady.store(true);
    st.addLog(std::string("[listen] listening on ") + std::to_string(port));
    while (!st.stopIo.load() && !st.sessionChosen.load()) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(ls, &fds);
        timeval tv{ 1, 0 };
        int r = select(0, &fds, nullptr, nullptr, &tv);
        if (r <= 0)
            continue;
        SOCKET s = accept(ls, nullptr, nullptr);
        if (s == INVALID_SOCKET)
            continue;
        if (st.sessionChosen.load()) {
            closesocket(s);
            break;
        }
        set_nodelay(s);
        st.addLog(std::string("[listen] accepted tuple ") + sock_tuple_str(s));

        CryptoPP::InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(st.rng, 3072);
        st.priv = CryptoPP::RSA::PrivateKey(params);
        st.pub = CryptoPP::RSA::PublicKey(params);
        loadOrCreatePeerId(st.localPeerId);
        std::vector<uint8_t> hostPubSer = serializePublicKey(st.pub);
        if (!writeFrame(s, MsgType::PublicKey, hostPubSer)) {
            closesocket(s);
            continue;
        }

        MsgType t;
        std::vector<uint8_t> pl;
        if (!readFrame(s, t, pl) || t != MsgType::PublicKey) {
            closesocket(s);
            continue;
        }
        if (!loadPublicKey(pl.data(), pl.size(), st.peerPub)) {
            closesocket(s);
            continue;
        }

        std::vector<uint8_t> remoteId;
        uint8_t roleDummy = 0;
        if (!recvPeerHello(s, remoteId, roleDummy) || !sendPeerHello(s, st.localPeerId, 1)) {
            closesocket(s);
            continue;
        }

        st.remotePeerId = remoteId;
        st.sock = s;
        st.connected = true;
        st.addLog("Accepted (inbound)");

        st.session = new NetSession(st.sock);
        st.session->onMessage([&](MsgType mt, const std::vector<uint8_t>& data) {
            if (mt == MsgType::SessionKey) {
                if (data.size() < 2) {
                    st.addLog("[listen] malformed SessionKey");
                    return;
                }
                uint16_t rklen = ((uint16_t)data[0] << 8) | (uint16_t)data[1];
                if (data.size() < 2 + rklen) {
                    st.addLog("[listen] SessionKey len mismatch");
                    return;
                }
                const uint8_t* rkptr = data.data() + 2;
                CryptoPP::SecByteBlock key;
                try {
                    CryptoPP::AutoSeededRandomPool rng;
                    CryptoPP::RSAES_OAEP_SHA_Decryptor dec(st.priv);
                    std::string unwrapped;
                    CryptoPP::StringSource ss(rkptr, rklen, true,
                        new CryptoPP::PK_DecryptorFilter(rng, dec, new CryptoPP::StringSink(unwrapped)));
                    key.Assign(reinterpret_cast<const CryptoPP::byte*>(unwrapped.data()), unwrapped.size());
                } catch (...) {
                    st.addLog("[listen] RSA unwrap fail");
                    return;
                }
                st.sessionKey.Assign(key.data(), key.size());
                st.session->sendFrame(MsgType::SessionOk, {});
                st.sessionReady = true;
                st.addLog("[listen] Session ready");
                st.nextRekey = std::chrono::steady_clock::now() + std::chrono::seconds(60);
                st.sessionChosen.store(true);
                return;
            }
            if (mt == MsgType::Data) {
                if (!st.sessionReady) {
                    st.addLog("[listen] data before ready");
                    return;
                }
                uint64_t ctr, ts;
                std::string msg, err;
                if (!parseDataPayload(st.sessionKey, data, ctr, ts, msg, st.useHmac, err)) {
                    st.addLog(std::string("[listen] recv error: ") + err);
                    return;
                }
                if (ctr <= st.lastRecvCounter) {
                    st.addLog("[listen] duplicate/out-of-order");
                    return;
                }
                st.lastRecvCounter = ctr;
                st.addLog(fmtTime(ts) + std::string(" Peer: ") + msg);
                return;
            }
            });
        st.session->onClosed([&] { FullDisconnect(st, "[listen] peer closed"); });
        st.session->onError([&] { FullDisconnect(st, "[listen] session error"); });
        st.session->start();
        break;
    }
    st.listenReady.store(false);
    closesocket(ls);
}

// Full disconnect function
static inline void FullDisconnect(AppState& st, const char* reason) {
    st.stopIo.store(true);
    if (reason && *reason)
        st.addLog(std::string("[close] ") + reason);

    // join worker threads (avoid Stop crash)
    if (st.listenThread.joinable())
        st.listenThread.join();
    if (st.connectThread.joinable())
        st.connectThread.join();

    if (st.session) {
        NetSession* s = st.session;
        st.session = nullptr;
        s->stop();
        delete s;
    }
    if (st.sock != INVALID_SOCKET) {
        shutdown(st.sock, SD_BOTH);
        closesocket(st.sock);
        st.sock = INVALID_SOCKET;
    }
    st.connected = false;
    st.sessionReady = false;
    st.sessionChosen.store(false);
    st.listenReady.store(false);
}
