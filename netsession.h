#pragma once
#include <winsock2.h>
#include <thread>
#include <atomic>
#include <functional>
#include <vector>
#include <mutex>
#include "protocol.h"

class NetSession {
public:
    using MessageCallback = std::function<void(MsgType,const std::vector<uint8_t>&)>;
    using EventCallback = std::function<void()>;

    NetSession(SOCKET s) : sock(s) {}
    ~NetSession(){ stop(); }

    void onMessage(MessageCallback cb){ messageCb = std::move(cb); }
    void onClosed(EventCallback cb){ closedCb = std::move(cb); }
    void onError(EventCallback cb){ errorCb = std::move(cb); }

    bool start(){
        if(running.load()) return false;
        running.store(true);
        recvThread = std::thread([this]{ this->recvLoop(); });
        return true;
    }

    void stop(){
        if(!running.load()) return;
        running.store(false);
        shutdown(sock, SD_BOTH);
        if(recvThread.joinable()) recvThread.join();
    }

    bool sendFrame(MsgType t, const std::vector<uint8_t>& payload){
        std::lock_guard<std::mutex> lock(sendMutex);
        return writeFrame(sock, t, payload);
    }

private:
    void recvLoop(){
        while(running.load()){
            MsgType type; std::vector<uint8_t> payload;
            if(!readFrame(sock, type, payload)){
                running.store(false);
                if(closedCb) closedCb();
                break;
            }
            if(messageCb) messageCb(type,payload);
        }
    }

    SOCKET sock;
    std::thread recvThread;
    std::atomic<bool> running{false};
    std::mutex sendMutex;
    MessageCallback messageCb; EventCallback closedCb; EventCallback errorCb;
};
