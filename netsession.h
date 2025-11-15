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
        recvThread = std::thread([this]{
            recvThreadId = std::this_thread::get_id();
            this->recvLoop();
        });
        return true;
    }

    void stop(){
        if(!running.load()) return;
        running.store(false);
        // Shutdown socket to unblock any pending recv in this thread.
        shutdown(sock, SD_BOTH);
        // Avoid joining from within the same thread (would cause std::terminate).
        if(std::this_thread::get_id() != recvThreadId){
            if(recvThread.joinable()) recvThread.join();
        }
        // If called from recvThread, it will exit naturally after running becomes false.
    }

    bool sendFrame(MsgType t, const std::vector<uint8_t>& payload){
        std::lock_guard<std::mutex> lock(sendMutex);
        return writeFrame(sock, t, payload);
    }

    bool isRecvThread() const { return std::this_thread::get_id() == recvThreadId; }

private:
    void recvLoop(){
        bool connectionClosed = false;
        while(running.load()){
            MsgType type; std::vector<uint8_t> payload;
            if(!readFrame(sock, type, payload)){
                running.store(false);
                connectionClosed = true;
                break;
            }
            if(messageCb) messageCb(type,payload);
        }
        // Invoke callbacks after exiting the loop to avoid thread self-join
        if(connectionClosed && closedCb) closedCb();
    }

    SOCKET sock;
    std::thread recvThread;
    std::thread::id recvThreadId{}; // track recv thread for self-join guard
    std::atomic<bool> running{false};
    std::mutex sendMutex;
    MessageCallback messageCb; EventCallback closedCb; EventCallback errorCb;
};
