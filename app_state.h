#pragma once

#include <winsock2.h>
#include <vector>
#include <string>
#include <mutex>
#include <atomic>
#include <chrono>
#include <thread>
#include <fstream>
#include <iomanip>
#include <sstream>

#include <osrng.h>
#include <rsa.h>
#include <secblock.h>

#include "protocol.h"
#include "netsession.h"

// Application state structure
struct AppState {
    SOCKET sock = INVALID_SOCKET;
    NetSession* session = nullptr;
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey priv;
    CryptoPP::RSA::PublicKey pub;
    CryptoPP::RSA::PublicKey peerPub;
    CryptoPP::SecByteBlock sessionKey;
    bool sessionReady = false;
    bool connected = false;
    std::vector<std::string> log;
    std::mutex logMutex;
    uint64_t lastRecvCounter = 0;
    std::atomic<uint64_t> sendCounter{ 0 };
    bool pendingRekey = false;
    CryptoPP::SecByteBlock pendingKey;
    std::chrono::steady_clock::time_point nextRekey = std::chrono::steady_clock::now() + std::chrono::seconds(60);
    std::vector<uint8_t> localPeerId;
    std::vector<uint8_t> remotePeerId;
    std::atomic<bool> sessionChosen{ false };
    std::atomic<bool> stopIo{ false };
    bool useHmac = true;
    std::atomic<bool> listenReady{ false };
    bool listenOnly = false;
    bool connectOnly = false;
    bool autoMap = false;
    bool natPmpMapped = false;
    bool upnpMapped = false;
    uint16_t mappedExternalPort = 0;
    uint16_t mappedInternalPort = 0;
    std::string upnpControlURL;

    // Own the worker threads
    std::thread listenThread;
    std::thread connectThread;

    void addLog(const std::string& s) {
        std::lock_guard<std::mutex> lk(logMutex);
        log.push_back(s);
    }
};

// Load or create peer ID
static inline bool loadOrCreatePeerId(std::vector<uint8_t>& idOut) {
    std::ifstream in("peer_id.bin", std::ios::binary);
    if (in) {
        std::vector<uint8_t> buf(32);
        in.read(reinterpret_cast<char*>(buf.data()), 32);
        if (in.gcount() == 32) {
            idOut = std::move(buf);
            return true;
        }
    }
    idOut.resize(32);
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(idOut.data(), idOut.size());
    std::ofstream out("peer_id.bin", std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(idOut.data()), (std::streamsize)idOut.size());
    return true;
}

// Peer hello message functions
static inline bool sendPeerHello(SOCKET s, const std::vector<uint8_t>& peerId, uint8_t role) {
    std::vector<uint8_t> payload;
    payload.reserve(33);
    payload.insert(payload.end(), peerId.begin(), peerId.end());
    payload.push_back(role);
    return writeFrame(s, MsgType::PeerHello, payload);
}

static inline bool recvPeerHello(SOCKET s, std::vector<uint8_t>& peerIdOut, uint8_t& roleOut) {
    MsgType t;
    std::vector<uint8_t> pl;
    if (!readFrame(s, t, pl) || t != MsgType::PeerHello)
        return false;
    if (pl.size() != 33)
        return false;
    peerIdOut.assign(pl.begin(), pl.begin() + 32);
    roleOut = pl[32];
    return true;
}

// Format timestamp
static inline std::string fmtTime(uint64_t ms) {
    time_t sec = (time_t)(ms / 1000);
    uint64_t rem = ms % 1000;
    tm t{};
    localtime_s(&t, &sec);
    std::stringstream ss;
    ss << std::put_time(&t, "%H:%M:%S") << '.' << std::setw(3) << std::setfill('0') << rem;
    return ss.str();
}
