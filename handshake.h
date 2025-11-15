#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <atomic> // added for reentrancy guard

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

// Common data message handler (eliminates duplication)
static inline void handleDataMessage(AppState& st, const std::vector<uint8_t>& data, const char* label) {
    if (!st.sessionReady) {
        st.addLog(std::string(label) + " Data before session ready");
        return;
    }

    uint64_t ctr, ts;
    std::string msg, err;
    if (!parseDataPayload(st.sessionKey, data, ctr, ts, msg, st.useHmac, err)) {
        st.addLog(std::string(label) + " Recv error: " + err);
        return;
    }
    if (ctr <= st.lastRecvCounter) {
        st.addLog(std::string(label) + " Duplicate/out-of-order");
        return;
    }
    st.lastRecvCounter = ctr;

    st.addLog(fmtTime(ts) + std::string(" Peer: ") + msg);
}

// Outbound handshake logic with hybrid encryption (RSA + ECDH)
static inline bool DoOutboundHandshake(AppState& st, SOCKET s, const char* label) {
    // Generate RSA keypair (4096-bit)
    generateRSAKeyPair(st.rng, st.priv, st.pub);
    
    // Generate ECDH keypair (P-521 curve)
    generateECDHKeyPair(st.rng, st.ecdhDomain, st.ecdhPrivKey, st.ecdhPubKey);
    
    loadOrCreatePeerId(st.localPeerId);
    
    // Send RSA public key
    std::vector<uint8_t> mypub = serializePublicKey(st.pub);
    st.addLog(std::string(label) + " sending RSA PublicKey (" + std::to_string(mypub.size()) + " bytes)");
    if (!writeFrame(s, MsgType::PublicKey, mypub)) {
        st.addLog(std::string(label) + " send PublicKey failed");
        return false;
    }
    
    // Receive peer's RSA public key
    MsgType t;
    std::vector<uint8_t> payload;
    if (!readFrame(s, t, payload) || t != MsgType::PublicKey) {
        st.addLog(std::string(label) + " expected PublicKey");
        return false;
    }
    st.addLog(std::string(label) + " received peer RSA PublicKey (" + std::to_string(payload.size()) + " bytes)");
    if (!loadPublicKey(payload.data(), payload.size(), st.peerPub)) {
        st.addLog(std::string(label) + " bad PublicKey");
        return false;
    }
    
    // Send ECDH public key
    std::vector<uint8_t> myEcdhPub = serializeECDHPublicKey(st.ecdhPubKey);
    st.addLog(std::string(label) + " sending ECDH PublicKey (" + std::to_string(myEcdhPub.size()) + " bytes)");
    if (!writeFrame(s, MsgType::ECDHPublicKey, myEcdhPub)) {
        st.addLog(std::string(label) + " send ECDHPublicKey failed");
        return false;
    }
    
    // Receive peer's ECDH public key
    if (!readFrame(s, t, payload) || t != MsgType::ECDHPublicKey) {
        st.addLog(std::string(label) + " expected ECDHPublicKey");
        return false;
    }
    st.addLog(std::string(label) + " received peer ECDH PublicKey (" + std::to_string(payload.size()) + " bytes)");
    if (!loadECDHPublicKey(payload.data(), payload.size(), st.peerEcdhPubKey)) {
        st.addLog(std::string(label) + " bad ECDHPublicKey");
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
    
    // Derive hybrid session key using both RSA and ECDH
    std::vector<uint8_t> rsaWrapped;
    if (!deriveHybridSessionKey(st.rng, st.peerPub, st.peerEcdhPubKey, 
                                 st.ecdhPrivKey, st.ecdhDomain, st.sessionKey, rsaWrapped)) {
        st.addLog(std::string(label) + " hybrid key derivation failed");
        return false;
    }
    
    // Create NetSession and set up message handlers BEFORE sending any frames
    st.session = new NetSession(st.sock);
    st.session->onMessage([&st, label](MsgType mt, const std::vector<uint8_t>& data) {
        if (mt == MsgType::SessionOk) {
            st.sessionReady = true;
            st.addLog(std::string(label) + " Session ready (Hybrid RSA-4096 + ECDH-P521 encryption)");
            st.nextRekey = std::chrono::steady_clock::now() + std::chrono::seconds(60);
            st.sessionChosen.store(true);
            return;
        }
        if (mt == MsgType::Data) {
            handleDataMessage(st, data, label);
            return;
        }
    });
    st.session->onClosed([&st, label] { FullDisconnect(st, (std::string(label) + " peer closed").c_str()); });
    st.session->onError([&st, label] { FullDisconnect(st, (std::string(label) + " session error").c_str()); });
    st.session->start();
    
    std::vector<uint8_t> skPayload;
    uint16_t klen = (uint16_t)rsaWrapped.size();
    st.addLog(std::string(label) + " preparing Hybrid SessionKey frame (" + std::to_string(klen) + " bytes)");
    skPayload.push_back((uint8_t)((klen >> 8) & 0xFF));
    skPayload.push_back((uint8_t)(klen & 0xFF));
    skPayload.insert(skPayload.end(), rsaWrapped.begin(), rsaWrapped.end());
    if (!st.session->sendFrame(MsgType::SessionKey, skPayload)) {
        st.addLog(std::string(label) + " SessionKey send failed");
        FullDisconnect(st, "sessionkey send fail");
        return false;
    }
    st.addLog(std::string(label) + " Hybrid SessionKey sent, waiting for SessionOk");
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

    // Create event for connect notification
    WSAEVENT hEvent = WSACreateEvent();
    if (hEvent == WSA_INVALID_EVENT) {
        st.addLog("[connect] WSACreateEvent failed");
        closesocket(cs);
        return;
    }

    // Request FD_CONNECT event notification
    if (WSAEventSelect(cs, hEvent, FD_CONNECT) == SOCKET_ERROR) {
        st.addLog("[connect] WSAEventSelect failed");
        WSACloseEvent(hEvent);
        closesocket(cs);
        return;
    }

    int cr = ::connect(cs, (SOCKADDR*)&raddr, sizeof(raddr));
    // connect will return SOCKET_ERROR with WSAEWOULDBLOCK because of WSAEventSelect
    if (cr == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e != WSAEWOULDBLOCK) {
            st.addLog(std::string("[connect] connect fail to ") + iptxt + ":" + std::to_string(remotePort) + " err=" + std::to_string(e));
            WSACloseEvent(hEvent);
            closesocket(cs);
            return;
        }
    }

    st.addLog(std::string("[connect] pending to ") + iptxt + ":" + std::to_string(remotePort) + (hairpin ? " (hairpin)" : ""));
    auto start = std::chrono::steady_clock::now();
    
    // Wait for connect event or timeout/cancellation
    while (!st.stopIo.load(std::memory_order_acquire) && !st.sessionChosen.load(std::memory_order_acquire)) {
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed > std::chrono::seconds(15)) {
            st.addLog("[connect] timeout");
            break;
        }
        
        // Wait up to 200ms for event (allows periodic cancellation check)
        DWORD waitResult = WSAWaitForMultipleEvents(1, &hEvent, FALSE, 200, FALSE);
        
        if (waitResult == WSA_WAIT_EVENT_0) {
            // Event signaled - check network events
            WSANETWORKEVENTS netEvents{};
            if (WSAEnumNetworkEvents(cs, hEvent, &netEvents) == SOCKET_ERROR) {
                st.addLog("[connect] WSAEnumNetworkEvents failed");
                break;
            }
            
            if (netEvents.lNetworkEvents & FD_CONNECT) {
                int connectError = netEvents.iErrorCode[FD_CONNECT_BIT];
                if (connectError == 0) {
                    // Success - restore blocking mode and disable event notifications
                    if (WSAEventSelect(cs, hEvent, 0) == SOCKET_ERROR) {
                        st.addLog("[connect] WSAEventSelect failed when disabling event notifications");
                        break;
                    }
                    u_long nb = 0;
                    ioctlsocket(cs, FIONBIO, &nb);
                    
                    WSACloseEvent(hEvent);
                    SOCKET s = cs;
                    cs = INVALID_SOCKET;
                    set_nodelay(s);
                    st.addLog(std::string("[connect] tuple ") + sock_tuple_str(s));
                    if (!DoOutboundHandshake(st, s, "[connect]")) {
                        st.addLog("[connect] handshake failed");
                    }
                    return;
                } else {
                    st.addLog(std::string("[connect] connect error=") + std::to_string(connectError));
                    break;
                }
            }
        } else if (waitResult == WSA_WAIT_TIMEOUT) {
            // Timeout - loop continues to check stopIo/sessionChosen
            continue;
        } else {
            // Error
            st.addLog("[connect] WSAWaitForMultipleEvents failed");
            break;
        }
    }
    
    WSACloseEvent(hEvent);
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

        // Generate RSA keypair (4096-bit)
        generateRSAKeyPair(st.rng, st.priv, st.pub);

        // RSA keypair generated (logging keys removed for security)
        
        // Generate ECDH keypair (P-521 curve)
        generateECDHKeyPair(st.rng, st.ecdhDomain, st.ecdhPrivKey, st.ecdhPubKey);

        // ECDH keypair generated (logging keys removed for security)
        
        loadOrCreatePeerId(st.localPeerId);
        
        // Send RSA public key
        std::vector<uint8_t> hostPubSer = serializePublicKey(st.pub);
        st.addLog(std::string("[listen] sending RSA PublicKey (") + std::to_string(hostPubSer.size()) + " bytes)");
        if (!writeFrame(s, MsgType::PublicKey, hostPubSer)) {
            closesocket(s);
            continue;
        }

        // Receive peer's RSA public key
        MsgType t;
        std::vector<uint8_t> pl;
        if (!readFrame(s, t, pl) || t != MsgType::PublicKey) {
            closesocket(s);
            continue;
        }
        st.addLog(std::string("[listen] received peer RSA PublicKey (") + std::to_string(pl.size()) + " bytes)");
        if (!loadPublicKey(pl.data(), pl.size(), st.peerPub)) {
            closesocket(s);
            continue;
        }
        
        // Send ECDH public key
        std::vector<uint8_t> myEcdhPub = serializeECDHPublicKey(st.ecdhPubKey);
        st.addLog(std::string("[listen] sending ECDH PublicKey (") + std::to_string(myEcdhPub.size()) + " bytes)");
        if (!writeFrame(s, MsgType::ECDHPublicKey, myEcdhPub)) {
            closesocket(s);
            continue;
        }
        
        // Receive peer's ECDH public key
        if (!readFrame(s, t, pl) || t != MsgType::ECDHPublicKey) {
            closesocket(s);
            continue;
        }
        st.addLog(std::string("[listen] received peer ECDH PublicKey (") + std::to_string(pl.size()) + " bytes)");
        if (!loadECDHPublicKey(pl.data(), pl.size(), st.peerEcdhPubKey)) {
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

                // Unwrap hybrid session key using both RSA and ECDH (details not logged for security)
                if (!unwrapHybridSessionKey(st.priv, rkptr, rklen,
                                           st.ecdhPrivKey, st.peerEcdhPubKey,
                                           st.ecdhDomain, st.sessionKey)) {
                    st.addLog("[listen] Hybrid key unwrap fail");
                    return;
                }

                st.session->sendFrame(MsgType::SessionOk, {});
                st.sessionReady = true;
                st.addLog("[listen] Session ready (Hybrid RSA-4096 + ECDH-P521 encryption)");
                st.nextRekey = std::chrono::steady_clock::now() + std::chrono::seconds(60);
                st.sessionChosen.store(true);
                return;
            }
            if (mt == MsgType::Data) {
                handleDataMessage(st, data, "[listen]");
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

    // join worker threads (avoid Stop crash) - BUT NOT FROM WITHIN THEMSELVES
    std::thread::id currentThreadId = std::this_thread::get_id();
    if (st.listenThread.joinable() && st.listenThread.get_id() != currentThreadId)
        st.listenThread.join();
    if (st.connectThread.joinable() && st.connectThread.get_id() != currentThreadId)
        st.connectThread.join();

    if (st.session) {
        NetSession* s = st.session;
        st.session = nullptr;
        s->stop();
        
        // Defer deletion if we're being called from the session's recv thread
        if (s->isRecvThread()) {
            st.deferredSessionDelete.store(s, std::memory_order_release);
        } else {
            delete s;
        }
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
