#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tchar.h>

#include <iostream>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <chrono>
#include <thread>
#include <fstream>
#include <sstream>
#include <iomanip>

#include "protocol.h"
#include "netsession.h"
#include "stun_client.h"

#include <osrng.h>
#include <rsa.h>
#include <secblock.h>
#include <gcm.h>
#include <filters.h>
#include <queue.h>
#include <sha.h>
#include <hmac.h>
#include <hex.h>

#include <mstcpip.h>
#include <commctrl.h>
#include <iphlpapi.h>
#include <wininet.h>
#include <shobjidl.h>


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "cryptlib.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wininet.lib")

using namespace std;

// Socket helper definitions
static void set_nodelay(SOCKET s){ int one=1; setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char*)&one, sizeof(one)); }
static void set_keepalive(SOCKET s, DWORD idleMs, DWORD intervalMs, DWORD count){ BOOL on=TRUE; setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (char*)&on, sizeof(on)); tcp_keepalive ka{}; ka.onoff=1; ka.keepalivetime=idleMs; ka.keepaliveinterval=intervalMs; DWORD bytesRet=0; WSAIoctl(s, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), nullptr, 0, &bytesRet, nullptr, nullptr); }
static string sock_tuple_str(SOCKET s){ sockaddr_in a{}, b{}; int al=sizeof(a), bl=sizeof(b); stringstream ss; if(getsockname(s,(sockaddr*)&a,&al)==0){ char lip[64]{}; inet_ntop(AF_INET,&a.sin_addr,lip,sizeof(lip)); ss<<lip<<":"<<ntohs(a.sin_port); } else { ss<<"?:?"; } ss<<" -> "; if(getpeername(s,(sockaddr*)&b,&bl)==0){ char rip[64]{}; inet_ntop(AF_INET,&b.sin_addr,rip,sizeof(rip)); ss<<rip<<":"<<ntohs(b.sin_port); } else { ss<<"?:?"; } return ss.str(); }

static vector<uint8_t> serializePublicKey(const CryptoPP::RSA::PublicKey& pub){ CryptoPP::ByteQueue q; pub.Save(q); size_t n=q.CurrentSize(); vector<uint8_t> buf(n); q.Get(buf.data(), n); return buf; }
static bool loadPublicKey(const uint8_t* data,size_t len,CryptoPP::RSA::PublicKey& pub){ try{ CryptoPP::ByteQueue q; q.Put(data,len); pub.Load(q); return true;}catch(...){ return false;} }
static vector<uint8_t> rsaWrapAesKey(const CryptoPP::RSA::PublicKey& pub,const CryptoPP::SecByteBlock& aesKey){ CryptoPP::AutoSeededRandomPool rng; CryptoPP::RSAES_OAEP_SHA_Encryptor enc(pub); string wrapped; CryptoPP::StringSource ss(aesKey.data(), aesKey.size(), true, new CryptoPP::PK_EncryptorFilter(rng, enc, new CryptoPP::StringSink(wrapped))); return vector<uint8_t>(wrapped.begin(), wrapped.end()); }
static bool aesGcmEncrypt(const CryptoPP::SecByteBlock& key,const CryptoPP::SecByteBlock& nonce,const string& plain, vector<uint8_t>& outCipher){ try{ CryptoPP::GCM<CryptoPP::AES>::Encryption enc; enc.SetKeyWithIV(key,key.size(),nonce,nonce.size()); string cipher; CryptoPP::AuthenticatedEncryptionFilter aef(enc,new CryptoPP::StringSink(cipher),false,16); CryptoPP::StringSource ss(plain,true,new CryptoPP::Redirector(aef)); outCipher.assign(cipher.begin(), cipher.end()); return true;}catch(const CryptoPP::Exception& e){ cerr<<"GCM encrypt error: "<<e.what()<<endl; return false;} }
static bool aesGcmDecrypt(const CryptoPP::SecByteBlock& key,const CryptoPP::SecByteBlock& nonce,const uint8_t* cipher,size_t len,string& outPlain){ try{ CryptoPP::GCM<CryptoPP::AES>::Decryption dec; dec.SetKeyWithIV(key,key.size(),nonce,nonce.size()); string plain; CryptoPP::AuthenticatedDecryptionFilter adf(dec,new CryptoPP::StringSink(plain),CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,16); CryptoPP::StringSource ss(cipher,len,true,new CryptoPP::Redirector(adf)); outPlain=move(plain); return true;}catch(const CryptoPP::Exception& e){ cerr<<"GCM decrypt error: "<<e.what()<<endl; return false;} }
static void write_u64be(uint64_t v, string& out, size_t offset){ for(int i=7;i>=0;--i) out[offset + (7-i)] = (char)((v >> (i*8)) & 0xFF); }
static uint64_t read_u64be(const string& in, size_t offset){ uint64_t v=0; for(int i=0;i<8;++i){ v = (v<<8) | (uint8_t)in[offset+i]; } return v; }
static bool makeDataPayload(const CryptoPP::SecByteBlock& sessionKey, uint64_t counter, const string& msg, CryptoPP::AutoSeededRandomPool& rng, vector<uint8_t>& payloadOut, bool useHmac) {
    CryptoPP::SecByteBlock nonce(12); rng.GenerateBlock(nonce, nonce.size());
    uint64_t unixMs = (uint64_t)chrono::duration_cast<chrono::milliseconds>(chrono::system_clock::now().time_since_epoch()).count();
    string plain; plain.resize(16);
    write_u64be(counter, plain, 0);
    write_u64be(unixMs, plain, 8);
    plain.append(msg);
    if (useHmac) {
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(sessionKey, sessionKey.size());
        hmac.Update(reinterpret_cast<const CryptoPP::byte*>(plain.data()), plain.size());
        CryptoPP::byte mac[32]; hmac.Final(mac);
        plain.append(reinterpret_cast<const char*>(mac), 32);
    }
    vector<uint8_t> cipher; if (!aesGcmEncrypt(sessionKey, nonce, plain, cipher)) return false;
    payloadOut.clear(); payloadOut.push_back((uint8_t)nonce.size());
    payloadOut.insert(payloadOut.end(), nonce.begin(), nonce.end());
    uint32_t clen = (uint32_t)cipher.size();
    payloadOut.push_back((uint8_t)((clen >> 24) & 0xFF));
    payloadOut.push_back((uint8_t)((clen >> 16) & 0xFF));
    payloadOut.push_back((uint8_t)((clen >> 8) & 0xFF));
    payloadOut.push_back((uint8_t)(clen & 0xFF));
    payloadOut.insert(payloadOut.end(), cipher.begin(), cipher.end());
    return true;
}
static bool parseDataPayload(const CryptoPP::SecByteBlock& sessionKey, const vector<uint8_t>& data, uint64_t& counterOut, uint64_t& tsMsOut, string& msgOut, bool expectHmac, string& err) {
    if (data.size() < 1 + 4) { err = "short frame"; return false; }
    size_t idx = 0; uint8_t nlen = data[idx++];
    if (data.size() < 1 + nlen + 4) { err = "short nonce"; return false; }
    CryptoPP::SecByteBlock nonce(nlen); memcpy(nonce, data.data() + idx, nlen); idx += nlen;
    uint32_t clen = ((uint32_t)data[idx] << 24) | ((uint32_t)data[idx+1] << 16) | ((uint32_t)data[idx+2] << 8) | (uint32_t)data[idx+3]; idx += 4;
    if (data.size() < idx + clen) { err = "short cipher"; return false; }
    string plain; if (!aesGcmDecrypt(sessionKey, nonce, data.data()+idx, clen, plain)) { err = "auth fail"; return false; }
    if (plain.size() < 16) { err = "short plain"; return false; }
    // If HMAC present, must be at least 32 bytes long; detect dynamically if not expecting strictly
    bool hasHmac = plain.size() >= 16 + 32;
    size_t macOff = hasHmac ? (plain.size() - 32) : plain.size();
    counterOut = read_u64be(plain, 0);
    tsMsOut = read_u64be(plain, 8);
    msgOut.assign(plain.begin()+16, plain.begin()+macOff);
    if (expectHmac && hasHmac) {
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(sessionKey, sessionKey.size());
        hmac.Update(reinterpret_cast<const CryptoPP::byte*>(plain.data()), macOff);
        CryptoPP::byte mac[32]; hmac.Final(mac);
        if (memcmp(mac, plain.data()+macOff, 32) != 0) { err = "hmac mismatch"; return false; }
    } else if (expectHmac && !hasHmac) { err = "missing hmac"; return false; }
    return true;
}
static bool loadOrCreatePeerId(vector<uint8_t>& idOut){ ifstream in("peer_id.bin", ios::binary); if(in){ vector<uint8_t> buf(32); in.read(reinterpret_cast<char*>(buf.data()), 32); if(in.gcount()==32){ idOut = move(buf); return true; } } idOut.resize(32); CryptoPP::AutoSeededRandomPool rng; rng.GenerateBlock(idOut.data(), idOut.size()); ofstream out("peer_id.bin", ios::binary|ios::trunc); out.write(reinterpret_cast<const char*>(idOut.data()), (std::streamsize)idOut.size()); return true; }
static bool sendPeerHello(SOCKET s, const vector<uint8_t>& peerId, uint8_t role){ vector<uint8_t> payload; payload.reserve(33); payload.insert(payload.end(), peerId.begin(), peerId.end()); payload.push_back(role); return writeFrame(s, MsgType::PeerHello, payload); }
static bool recvPeerHello(SOCKET s, vector<uint8_t>& peerIdOut, uint8_t& roleOut){ MsgType t; vector<uint8_t> pl; if(!readFrame(s,t,pl) || t!=MsgType::PeerHello) return false; if(pl.size()!=33) return false; peerIdOut.assign(pl.begin(), pl.begin()+32); roleOut = pl[32]; return true; }
static string fmtTime(uint64_t ms){ time_t sec = (time_t)(ms/1000); uint64_t rem = ms % 1000; tm t{}; localtime_s(&t,&sec); stringstream ss; ss<< put_time(&t, "%H:%M:%S") << '.' << setw(3) << setfill('0') << rem; return ss.str(); }

struct AppState{
    SOCKET sock = INVALID_SOCKET;
    NetSession* session = nullptr;
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSA::PrivateKey priv;
    CryptoPP::RSA::PublicKey pub;
    CryptoPP::RSA::PublicKey peerPub;
    CryptoPP::SecByteBlock sessionKey;
    bool sessionReady = false;
    bool connected = false;
    vector<string> log; mutex logMutex;
    uint64_t lastRecvCounter = 0; atomic<uint64_t> sendCounter{0};
    bool pendingRekey = false; CryptoPP::SecByteBlock pendingKey;
    chrono::steady_clock::time_point nextRekey = chrono::steady_clock::now() + chrono::seconds(60);
    vector<uint8_t> localPeerId; vector<uint8_t> remotePeerId;
    atomic<bool> sessionChosen{false}; atomic<bool> stopIo{false};
    bool useHmac = true; atomic<bool> listenReady{false};
    bool listenOnly=false; bool connectOnly=false;
    // Automap state
    bool autoMap=false; bool natPmpMapped=false; bool upnpMapped=false; uint16_t mappedExternalPort=0; uint16_t mappedInternalPort=0; string upnpControlURL; // for deletion

    void addLog(const string& s){ lock_guard<mutex> lk(logMutex); log.push_back(s); }
};

static bool session_send(struct AppState& st, const string& msg) {
    if (!st.connected || !st.session || !st.sessionReady) return false;
    uint64_t ctr = ++st.sendCounter; vector<uint8_t> out; if (!makeDataPayload(st.sessionKey, ctr, msg, st.rng, out, st.useHmac)) return false; return st.session->sendFrame(MsgType::Data, out);
}

static bool DoOutboundHandshake(AppState& st, SOCKET s, const char* label){ CryptoPP::InvertibleRSAFunction params; params.GenerateRandomWithKeySize(st.rng, 3072); st.priv = CryptoPP::RSA::PrivateKey(params); st.pub = CryptoPP::RSA::PublicKey(params); loadOrCreatePeerId(st.localPeerId); vector<uint8_t> mypub = serializePublicKey(st.pub); if(!writeFrame(s, MsgType::PublicKey, mypub)){ st.addLog(string(label)+" send PublicKey failed"); return false; } MsgType t; vector<uint8_t> payload; if(!readFrame(s, t, payload) || t!=MsgType::PublicKey){ st.addLog(string(label)+" expected PublicKey"); return false; } if(!loadPublicKey(payload.data(), payload.size(), st.peerPub)){ st.addLog(string(label)+" bad PublicKey"); return false; } vector<uint8_t> remoteId; uint8_t remoteRole=1; if(!sendPeerHello(s, st.localPeerId, 0) || !recvPeerHello(s, remoteId, remoteRole)){ st.addLog(string(label)+" PeerHello fail"); return false; } if(st.sessionChosen.load()){ st.addLog(string(label)+" loser (already chosen)"); return false; } st.remotePeerId = remoteId; st.sock = s; st.connected = true; st.addLog(string(label)+" connected"); st.session = new NetSession(st.sock); st.session->onMessage([&](MsgType mt, const vector<uint8_t>& data){ if (mt == MsgType::SessionOk) { if (st.pendingRekey) { st.sessionKey.Assign(st.pendingKey.data(), st.pendingKey.size()); st.pendingRekey=false; st.lastRecvCounter=0; st.sendCounter.store(0); st.addLog("Re-key complete"); } st.sessionReady = true; st.addLog("Session ready"); st.nextRekey = chrono::steady_clock::now() + chrono::seconds(60); return; } if (mt == MsgType::Data) { if (!st.sessionReady) { st.addLog("Data before session ready"); return; } uint64_t ctr, ts; string msg, err; if (!parseDataPayload(st.sessionKey, data, ctr, ts, msg, st.useHmac, err)) { st.addLog(string("Recv error: ")+err); return; } if (ctr <= st.lastRecvCounter) { st.addLog("Duplicate/out-of-order"); return; } st.lastRecvCounter = ctr; st.addLog(fmtTime(ts)+string(" Peer: ")+msg); return; } }); st.session->onClosed([&]{ st.addLog("Disconnected"); }); st.session->start(); st.sessionKey.CleanNew(32); st.rng.GenerateBlock(st.sessionKey, st.sessionKey.size()); vector<uint8_t> wrapped = rsaWrapAesKey(st.peerPub, st.sessionKey); vector<uint8_t> skPayload; uint16_t klen = (uint16_t)wrapped.size(); skPayload.push_back((uint8_t)((klen >> 8) & 0xFF)); skPayload.push_back((uint8_t)(klen & 0xFF)); skPayload.insert(skPayload.end(), wrapped.begin(), wrapped.end()); if(!writeFrame(st.sock, MsgType::SessionKey, skPayload)){ st.addLog(string(label)+" SessionKey send failed"); st.session->stop(); delete st.session; st.session=nullptr; closesocket(s); st.connected=false; return false; } st.addLog(string(label)+" SessionKey sent"); st.sessionChosen.store(true); return true; }

static void SimultaneousConnect(AppState& st, const char* remoteHost, uint16_t listenPort, uint16_t remotePort){ if(st.listenOnly) return; sockaddr_in raddr{}; raddr.sin_family=AF_INET; if(InetPtonA(AF_INET, remoteHost, &raddr.sin_addr)!=1){ st.addLog("[connect] bad remote ip"); return; } raddr.sin_port=htons(remotePort); SOCKET cs = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); if(cs==INVALID_SOCKET){ st.addLog("[connect] socket failed"); return; } BOOL yes=1; setsockopt(cs, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes)); sockaddr_in laddr{}; laddr.sin_family=AF_INET; laddr.sin_addr.s_addr=htonl(INADDR_ANY); laddr.sin_port=htons(listenPort); if(::bind(cs, (SOCKADDR*)&laddr, sizeof(laddr))==SOCKET_ERROR){ st.addLog("[connect] bind local failed"); closesocket(cs); return; } u_long nb=1; ioctlsocket(cs, FIONBIO, &nb); int cr = ::connect(cs, (SOCKADDR*)&raddr, sizeof(raddr)); if(cr==SOCKET_ERROR){ int e=WSAGetLastError(); if(e!=WSAEWOULDBLOCK && e!=WSAEINPROGRESS){ st.addLog("[connect] connect immediate fail"); closesocket(cs); return; } } st.addLog("[connect] simultaneous open pending..."); auto simStart = chrono::steady_clock::now(); while(!st.stopIo.load() && !st.sessionChosen.load()){ if(chrono::steady_clock::now() - simStart > chrono::seconds(15)){ st.addLog("[connect] sim-open timeout"); break; } fd_set wfds; FD_ZERO(&wfds); FD_SET(cs,&wfds); timeval tv{0,200*1000}; int r = select(0,nullptr,&wfds,nullptr,&tv); if(r>0 && FD_ISSET(cs,&wfds)){ int soerr=0; int slen=sizeof(soerr); getsockopt(cs, SOL_SOCKET, SO_ERROR, (char*)&soerr, &slen); if(soerr==0){ nb=0; ioctlsocket(cs, FIONBIO, &nb); SOCKET s=cs; cs=INVALID_SOCKET; set_nodelay(s); st.addLog(string("[connect] tuple ")+sock_tuple_str(s)); DoOutboundHandshake(st, s, "[connect]"); return; } else { st.addLog("[connect] failed (SO_ERROR)"); closesocket(cs); return; } } } if(cs!=INVALID_SOCKET) closesocket(cs); }

static void ListenAndAccept(AppState& st, uint16_t port){
    if(st.connectOnly) return;
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(ls==INVALID_SOCKET){ st.addLog("[listen] socket failed"); return; }
    BOOL yes = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
    sockaddr_in svc{}; svc.sin_family=AF_INET; svc.sin_addr.s_addr=htonl(INADDR_ANY); svc.sin_port=htons(port);
    if(::bind(ls,(SOCKADDR*)&svc,sizeof(svc))==SOCKET_ERROR){ st.addLog("[listen] bind failed"); closesocket(ls); return; }
    if(::listen(ls, 1)==SOCKET_ERROR){ st.addLog("[listen] listen failed"); closesocket(ls); return; }
    st.listenReady.store(true); st.addLog(string("[listen] listening on ")+to_string(port));
    while(!st.stopIo.load() && !st.sessionChosen.load()){
        fd_set fds; FD_ZERO(&fds); FD_SET(ls,&fds); timeval tv{1,0};
        int r = select(0,&fds,nullptr,nullptr,&tv); if(r<=0) continue;
        SOCKET s = accept(ls,nullptr,nullptr); // fixed: nullptr
        if(s==INVALID_SOCKET) continue;
        if(st.sessionChosen.load()) { closesocket(s); break; }
        set_nodelay(s);
        st.addLog(string("[listen] accepted tuple ")+sock_tuple_str(s));

        CryptoPP::InvertibleRSAFunction params; params.GenerateRandomWithKeySize(st.rng, 3072);
        st.priv = CryptoPP::RSA::PrivateKey(params); st.pub = CryptoPP::RSA::PublicKey(params);
        loadOrCreatePeerId(st.localPeerId);
        vector<uint8_t> hostPubSer = serializePublicKey(st.pub);
        if(!writeFrame(s, MsgType::PublicKey, hostPubSer)){ closesocket(s); continue; }

        MsgType t; vector<uint8_t> pl;
        if(!readFrame(s,t,pl) || t!=MsgType::PublicKey){ closesocket(s); continue; }
        if(!loadPublicKey(pl.data(), pl.size(), st.peerPub)){ closesocket(s); continue; }

        vector<uint8_t> remoteId; uint8_t roleDummy=0;
        if(!recvPeerHello(s, remoteId, roleDummy) || !sendPeerHello(s, st.localPeerId, 1)) { closesocket(s); continue; }

        st.remotePeerId = remoteId; st.sock = s; st.connected = true;
        st.addLog("Accepted (inbound)");

        st.session = new NetSession(st.sock);
        st.session->onMessage([&](MsgType mt, const vector<uint8_t>& data){
            if (mt == MsgType::SessionKey) {
                if (data.size() < 2) { st.addLog("[listen] malformed SessionKey"); return; }
                uint16_t rklen = ((uint16_t)data[0] << 8) | (uint16_t)data[1];
                if (data.size() < 2 + rklen) { st.addLog("[listen] SessionKey len mismatch"); return; }
                const uint8_t* rkptr = data.data() + 2;
                CryptoPP::SecByteBlock key;
                try{
                    CryptoPP::AutoSeededRandomPool rng; CryptoPP::RSAES_OAEP_SHA_Decryptor dec(st.priv);
                    string unwrapped; CryptoPP::StringSource ss(rkptr, rklen, true, new CryptoPP::PK_DecryptorFilter(rng, dec, new CryptoPP::StringSink(unwrapped)));
                    key.Assign(reinterpret_cast<const CryptoPP::byte*>(unwrapped.data()), unwrapped.size());
                } catch(...){ st.addLog("[listen] RSA unwrap fail"); return; }
                st.sessionKey.Assign(key.data(), key.size());
                st.session->sendFrame(MsgType::SessionOk, {});
                st.sessionReady = true; st.addLog("[listen] Session ready");
                st.nextRekey = chrono::steady_clock::now() + chrono::seconds(60);
                st.sessionChosen.store(true);
                return;
            }
            if (mt == MsgType::Data) {
                if (!st.sessionReady) { st.addLog("[listen] data before ready"); return; }
                uint64_t ctr, ts; string msg, err;
                if (!parseDataPayload(st.sessionKey, data, ctr, ts, msg, st.useHmac, err)) { st.addLog(string("[listen] recv error: ")+err); return; }
                if (ctr <= st.lastRecvCounter) { st.addLog("[listen] duplicate/out-of-order"); return; }
                st.lastRecvCounter = ctr;
                st.addLog(fmtTime(ts)+string(" Peer: ")+msg);
                return;
            }
        });
        st.session->onClosed([&]{ st.addLog("[listen] disconnected"); });
        st.session->start();
        break;
    }
    st.listenReady.store(false);
    closesocket(ls);
}

// --- NAT-PMP / UPnP helpers---
static string getLocalIPv4(){ char hn[256]{}; if(gethostname(hn,sizeof(hn))!=0) return {}; addrinfo hints{}; hints.ai_family=AF_INET; addrinfo* res=nullptr; if(getaddrinfo(hn,nullptr,&hints,&res)!=0) return {}; for(auto p=res;p;p=p->ai_next){ sockaddr_in* sin=(sockaddr_in*)p->ai_addr; char buf[64]; inet_ntop(AF_INET,&sin->sin_addr,buf,sizeof(buf)); freeaddrinfo(res); return buf; } freeaddrinfo(res); return {}; }
static string getGatewayIPv4(){ ULONG sz=0; GetAdaptersInfo(nullptr,&sz); vector<char> buf(sz); IP_ADAPTER_INFO* ai=(IP_ADAPTER_INFO*)buf.data(); if(GetAdaptersInfo(ai,&sz)!=NO_ERROR) return {}; for(auto p=ai;p;p=p->Next){ if(strlen(p->GatewayList.IpAddress.String)>0) return p->GatewayList.IpAddress.String; } return {}; }

static bool natpmpAdd(uint16_t internalPort, uint16_t& externalPortOut, string& err){ string gw=getGatewayIPv4(); if(gw.empty()){ err="no gw"; return false;} SOCKET s=socket(AF_INET,SOCK_DGRAM,0); if(s==INVALID_SOCKET){ err="sock"; return false;} sockaddr_in g{}; g.sin_family=AF_INET; g.sin_port=htons(5351); InetPtonA(AF_INET, gw.c_str(), &g.sin_addr); unsigned char req[12]{}; req[0]=0; req[1]=2; req[4]=(internalPort>>8)&0xFF; req[5]=internalPort&0xFF; // ext=0 => let NAT choose
 req[10]=0x0E; req[11]=0x10; // 3600s lifetime
 sendto(s,(char*)req,12,0,(sockaddr*)&g,sizeof(g)); fd_set fds; FD_ZERO(&fds); FD_SET(s,&fds); timeval tv{1,0}; if(select(0,&fds,nullptr,nullptr,&tv)<=0){ closesocket(s); err="timeout"; return false;} unsigned char resp[16]; int r=recv(s,(char*)resp,sizeof(resp),0); closesocket(s); if(r<12||resp[1]!=2){ err="bad resp"; return false;} externalPortOut=(uint16_t)((resp[8]<<8)|resp[9]); return true; }
static bool natpmpDelete(uint16_t internalPort){ string gw=getGatewayIPv4(); if(gw.empty()) return false; SOCKET s=socket(AF_INET,SOCK_DGRAM,0); if(s==INVALID_SOCKET) return false; sockaddr_in g{}; g.sin_family=AF_INET; g.sin_port=htons(5351); InetPtonA(AF_INET, gw.c_str(), &g.sin_addr); unsigned char req[12]{}; req[0]=0; req[1]=2; req[4]=(internalPort>>8)&0xFF; req[5]=internalPort&0xFF; // lifetime 0 -> delete
 sendto(s,(char*)req,12,0,(sockaddr*)&g,sizeof(g)); closesocket(s); return true; }

static bool upnpDiscoverControlURL(string& controlURL, string& hostPort, string& path){ SOCKET s=socket(AF_INET,SOCK_DGRAM,0); if(s==INVALID_SOCKET) return false; sockaddr_in m{}; m.sin_family=AF_INET; m.sin_port=htons(1900); InetPtonA(AF_INET,"239.255.255.250",&m.sin_addr); string req="M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:2\r\nST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"; sendto(s,req.c_str(),(int)req.size(),0,(sockaddr*)&m,sizeof(m)); fd_set fds; FD_ZERO(&fds); FD_SET(s,&fds); timeval tv{3,0}; if(select(0,&fds,nullptr,nullptr,&tv)<=0){ closesocket(s); return false;} char buf[4096]; int r=recv(s,buf,sizeof(buf)-1,0); closesocket(s); if(r<=0){ return false;} buf[r]=0; string resp(buf); auto pos=resp.find("LOCATION:"); if(pos==string::npos) return false; auto end=resp.find('\n',pos); string loc=resp.substr(pos+9,end-pos-9); while(!loc.empty() && (loc[0]==' '||loc[0]=='\r')) loc.erase(loc.begin()); while(!loc.empty() && (loc.back()=='\r'||loc.back()=='\n')) loc.pop_back(); HINTERNET hi=InternetOpenA("P2PChat",INTERNET_OPEN_TYPE_PRECONFIG,NULL,NULL,0); if(!hi) return false; HINTERNET hf=InternetOpenUrlA(hi,loc.c_str(),NULL,0,INTERNET_FLAG_RELOAD,0); if(!hf){ InternetCloseHandle(hi); return false;} string xml; char xbuf[2048]; DWORD rd=0; while(InternetReadFile(hf,xbuf,sizeof(xbuf),&rd) && rd>0) xml.append(xbuf,rd); InternetCloseHandle(hf); InternetCloseHandle(hi); auto svc=xml.find("urn:schemas-upnp-org:service:WANIPConnection:1"); if(svc==string::npos) svc=xml.find("urn:schemas-upnp-org:service:WANPPPConnection:1"); if(svc==string::npos) return false; auto cp=xml.find("<controlURL>",svc); if(cp==string::npos) return false; auto ce=xml.find("</controlURL>",cp); if(ce==string::npos) return false; path=xml.substr(cp+12,ce-(cp+12)); auto protoEnd=loc.find("://"); if(protoEnd==string::npos) return false; auto hostStart=protoEnd+3; auto slash=loc.find('/',hostStart); hostPort=loc.substr(hostStart, slash==string::npos? string::npos: slash-hostStart); if(path.empty()||path[0]!='/') path="/"+path; controlURL=loc.substr(0, hostStart)+hostPort+path; return true; }
static bool upnpAddPortMapping(uint16_t externalPort,uint16_t internalPort,const string& internalClient,string& controlURL,string& err){ string hostPort,path; if(!upnpDiscoverControlURL(controlURL,hostPort,path)){ err="discover"; return false;} SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); if(s==INVALID_SOCKET){ err="sock"; return false;} string host=hostPort; string port="80"; auto colon=hostPort.find(':'); if(colon!=string::npos){ host=hostPort.substr(0,colon); port=hostPort.substr(colon+1);} sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_port=htons((u_short)atoi(port.c_str())); if(InetPtonA(AF_INET,host.c_str(),&addr.sin_addr)!=1){ err="inet"; closesocket(s); return false;} if(connect(s,(sockaddr*)&addr,sizeof(addr))==SOCKET_ERROR){ err="connect"; closesocket(s); return false;} string body="<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewExternalPort="+to_string(externalPort)+"</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort="+to_string(internalPort)+"</NewInternalPort><NewInternalClient="+internalClient+"</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>P2PChat</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>"; string req="POST "+path+" HTTP/1.1\r\nHOST: "+hostPort+"\r\nCONTENT-TYPE: text/xml; charset=\"utf-8\"\r\nCONTENT-LENGTH: "+to_string(body.size())+"\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"\r\n\r\n"+body; send(s,req.c_str(),(int)req.size(),0); char resp[2048]; int r=recv(s,resp,sizeof(resp)-1,0); closesocket(s); if(r<=0){ err="noresp"; return false;} resp[r]=0; if(string(resp).find("200 OK")==string::npos){ err="http"; return false;} return true; }
static void upnpDeletePortMapping(uint16_t externalPort,const string& controlURL){ if(controlURL.empty()) return; string hostPortPath=controlURL.substr(controlURL.find("://")+3); auto slash=hostPortPath.find('/'); if(slash==string::npos) return; string hostPort=hostPortPath.substr(0,slash); string path=hostPortPath.substr(slash); string host=hostPort; string port="80"; auto colon=hostPort.find(':'); if(colon!=string::npos){ host=hostPort.substr(0,colon); port=hostPort.substr(colon+1);} SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP); if(s==INVALID_SOCKET) return; sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_port=htons((u_short)atoi(port.c_str())); if(InetPtonA(AF_INET,host.c_str(),&addr.sin_addr)!=1){ closesocket(s); return;} if(connect(s,(sockaddr*)&addr,sizeof(addr))==SOCKET_ERROR){ closesocket(s); return;} string body="<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:DeletePortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewExternalPort="+to_string(externalPort)+"</NewExternalPort><NewProtocol>TCP</NewProtocol></u:DeletePortMapping></s:Body></s:Envelope>"; string req="POST "+path+" HTTP/1.1\r\nHOST: "+hostPort+"\r\nCONTENT-TYPE: text/xml; charset=\"utf-8\"\r\nCONTENT-LENGTH: "+to_string(body.size())+"\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping\"\r\n\r\n"+body; send(s,req.c_str(),(int)req.size(),0); char buf[512]; recv(s,buf,sizeof(buf),0); closesocket(s); }

// UI control IDs
#define IDC_HOST        1001
#define IDC_LPORT       1002
#define IDC_CPORT       1003
#define IDC_HMAC        1004
#define IDC_LISTENONLY  1005
#define IDC_CONNECTONLY 1006
#define IDC_AUTOMAP     1007
#define IDC_STUN        1008
#define IDC_START       1009
#define IDC_STOP        1010
#define IDC_LOG         1011
#define IDC_INPUT       1012
#define IDC_SEND        1013
#define IDC_STATUS      1014

// Global UI state
static AppState g_state; static bool g_started=false; static size_t g_logIndex=0;
static HWND g_hLog=nullptr, g_hInput=nullptr, g_hStatus=nullptr, g_hHost=nullptr, g_hLPort=nullptr, g_hCPort=nullptr, g_hHmac=nullptr, g_hListenOnly=nullptr, g_hConnectOnly=nullptr, g_hAutoMap=nullptr;

static void SetCtlFont(HWND h){ SendMessage(h, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE); }
static void AppendLogLine(const string& line){ if(!g_hLog) return; int len=GetWindowTextLengthA(g_hLog); SendMessage(g_hLog, EM_SETSEL, len, len); string s=line+"\r\n"; SendMessageA(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)s.c_str()); }
static void RefreshUi(){ while(g_logIndex < g_state.log.size()) AppendLogLine(g_state.log[g_logIndex++]); if(g_hStatus){ const char* sttxt = g_state.connected? (g_state.sessionReady? "Ready" : "Handshaking") : (g_started? "Connecting/Listening" : "Idle"); SetWindowTextA(g_hStatus, sttxt); } }

static LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam){
    switch(msg){
    case WM_CREATE:{
        CreateWindowExA(0, "STATIC", "Peer Host:", WS_CHILD|WS_VISIBLE, 10,10,70,20, hwnd, 0, 0, 0);
        g_hHost = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "127.0.0.1", WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL, 85,8,180,22, hwnd, (HMENU)IDC_HOST, 0, 0);
        CreateWindowExA(0, "STATIC", "Listen:", WS_CHILD|WS_VISIBLE, 275,10,55,20, hwnd, 0, 0, 0);
        g_hLPort = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "27015", WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL, 330,8,60,22, hwnd, (HMENU)IDC_LPORT, 0, 0);
        CreateWindowExA(0, "STATIC", "Connect:", WS_CHILD|WS_VISIBLE, 395,10,60,20, hwnd, 0, 0, 0);
        g_hCPort = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "27015", WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL, 455,8,60,22, hwnd, (HMENU)IDC_CPORT, 0, 0);
        g_hHmac = CreateWindowExA(0, "BUTTON", "HMAC", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 520,8,60,22, hwnd, (HMENU)IDC_HMAC, 0, 0);
        g_hListenOnly = CreateWindowExA(0, "BUTTON", "ListenOnly", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 585,8,85,22, hwnd, (HMENU)IDC_LISTENONLY, 0, 0);
        g_hConnectOnly = CreateWindowExA(0, "BUTTON", "ConnectOnly", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 675,8,90,22, hwnd, (HMENU)IDC_CONNECTONLY, 0, 0);
        g_hAutoMap = CreateWindowExA(0, "BUTTON", "Auto-map", WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX, 770,8,80,22, hwnd, (HMENU)IDC_AUTOMAP, 0, 0);
        CreateWindowExA(0, "BUTTON", "STUN External IP", WS_CHILD|WS_VISIBLE, 855,8,140,22, hwnd, (HMENU)IDC_STUN, 0, 0);
        CreateWindowExA(0, "BUTTON", "Start", WS_CHILD|WS_VISIBLE, 1000,8,55,22, hwnd, (HMENU)IDC_START, 0, 0);
        CreateWindowExA(0, "BUTTON", "Stop", WS_CHILD|WS_VISIBLE, 1060,8,55,22, hwnd, (HMENU)IDC_STOP, 0, 0);
        g_hLog = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY|WS_VSCROLL, 10,40,1105,360, hwnd, (HMENU)IDC_LOG, 0, 0);
        g_hInput = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL, 10,405,1030,24, hwnd, (HMENU)IDC_INPUT, 0, 0);
        CreateWindowExA(0, "BUTTON", "Send", WS_CHILD|WS_VISIBLE, 1045,405,70,24, hwnd, (HMENU)IDC_SEND, 0, 0);
        g_hStatus = CreateWindowExA(0, "STATIC", "Idle", WS_CHILD|WS_VISIBLE, 10,435,300,20, hwnd, (HMENU)IDC_STATUS, 0, 0);
        // Fonts
        SetCtlFont(g_hHost); SetCtlFont(g_hLPort); SetCtlFont(g_hCPort); SetCtlFont(g_hHmac); SetCtlFont(g_hListenOnly); SetCtlFont(g_hConnectOnly); SetCtlFont(g_hAutoMap); SetCtlFont(g_hLog); SetCtlFont(g_hInput); SetCtlFont(g_hStatus);
        SetTimer(hwnd,1,250,nullptr);
        return 0; }
    case WM_TIMER: RefreshUi(); return 0;
    case WM_COMMAND:{ int id=LOWORD(wParam); if(id==IDC_START){
            char hostBuf[256]{}; GetWindowTextA(g_hHost, hostBuf, sizeof(hostBuf));
            char lbuf[32]{}; GetWindowTextA(g_hLPort, lbuf, sizeof(lbuf)); int listenPort=atoi(lbuf);
            char cbuf[32]{}; GetWindowTextA(g_hCPort, cbuf, sizeof(cbuf)); int connectPort=atoi(cbuf);
            g_state.useHmac = SendMessage(g_hHmac,BM_GETCHECK,0,0)==BST_CHECKED;
            g_state.listenOnly = SendMessage(g_hListenOnly,BM_GETCHECK,0,0)==BST_CHECKED;
            g_state.connectOnly = SendMessage(g_hConnectOnly,BM_GETCHECK,0,0)==BST_CHECKED;
            g_state.autoMap = SendMessage(g_hAutoMap,BM_GETCHECK,0,0)==BST_CHECKED;
            if(g_state.listenOnly && g_state.connectOnly){ g_state.listenOnly=false; g_state.connectOnly=false; }
            g_state.stopIo.store(false); g_state.sessionChosen.store(false); g_state.connected=false; g_state.sessionReady=false; g_state.lastRecvCounter=0; g_state.sendCounter.store(0); g_state.listenReady.store(false);
            g_started=true; g_state.addLog(string("Starting modes: ") + (g_state.listenOnly?"listen":"") + (g_state.connectOnly? (g_state.listenOnly?"+connect":"connect") : (!g_state.listenOnly?"listen+connect":"")) + (g_state.autoMap?" +automap":""));
            const uint16_t lport=(uint16_t)listenPort; const uint16_t cport=(uint16_t)connectPort; string host=hostBuf;
            if(g_state.autoMap && !g_state.connectOnly){ g_state.mappedInternalPort=lport; string err; uint16_t ext=0; if(natpmpAdd(lport, ext, err)){ g_state.natPmpMapped=true; g_state.mappedExternalPort=ext; g_state.addLog(string("NAT-PMP mapped ")+to_string(lport)+" -> "+to_string(ext)); } else { string uerr; string ctrl; if(upnpAddPortMapping(lport,lport,getLocalIPv4(),ctrl,uerr)){ g_state.upnpMapped=true; g_state.upnpControlURL=ctrl; g_state.mappedExternalPort=lport; g_state.addLog(string("UPnP mapped external ")+to_string(lport)); } else { g_state.addLog(string("Auto-map failed PMP:")+err+" UPnP:"+uerr); } } }
            if(!g_state.connectOnly){ thread([&]{ ListenAndAccept(g_state,lport); }).detach(); }
            if(!g_state.listenOnly){ thread([&]{ SimultaneousConnect(g_state, host.c_str(), lport, cport); }).detach(); }
            return 0; }
        if(id==IDC_STOP){ g_state.stopIo.store(true); g_state.listenReady.store(false); if(g_state.natPmpMapped){ natpmpDelete(g_state.mappedInternalPort); g_state.addLog("NAT-PMP mapping removed"); } if(g_state.upnpMapped){ upnpDeletePortMapping(g_state.mappedExternalPort, g_state.upnpControlURL); g_state.addLog("UPnP mapping removed"); } g_state.natPmpMapped=false; g_state.upnpMapped=false; g_state.upnpControlURL.clear(); if(g_state.sock!=INVALID_SOCKET){ shutdown(g_state.sock,SD_BOTH); closesocket(g_state.sock); g_state.sock=INVALID_SOCKET; } if(g_state.session){ g_state.session->stop(); delete g_state.session; g_state.session=nullptr; } g_state.connected=false; g_state.sessionReady=false; g_started=false; g_state.addLog("Stopped"); return 0; }
        if(id==IDC_STUN){ stun::MappedAddress ma; string err; if(stun::GetMappedAddress("stun.l.google.com",19302,3000,ma,err)){ g_state.addLog(string("External: ")+ma.ip+":"+to_string(ma.port)); } else { g_state.addLog(string("STUN fail: ")+err); } return 0; }
        if(id==IDC_SEND){ char buf[1024]{}; GetWindowTextA(g_hInput, buf, sizeof(buf)); if(buf[0]){ string msg=buf; SetWindowTextA(g_hInput, ""); if(session_send(g_state,msg)){ uint64_t nowMs=(uint64_t)chrono::duration_cast<chrono::milliseconds>(chrono::system_clock::now().time_since_epoch()).count(); g_state.addLog(fmtTime(nowMs)+string(" You: ")+msg); } else { g_state.addLog("Send failed or not ready"); } } return 0; }
        return 0; }
    case WM_CLOSE: DestroyWindow(hwnd); return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    default: return DefWindowProc(hwnd,msg,wParam,lParam);
    }
}

// Entry point
int APIENTRY WinMain(HINSTANCE hInst,HINSTANCE,LPSTR, int){
    SetCurrentProcessExplicitAppUserModelID(L"Tumblechat.App");
    WSADATA wsd; if(WSAStartup(MAKEWORD(2,2),&wsd)!=0){ MessageBoxA(NULL,"WSAStartup failed","Error",MB_ICONERROR); return 1; }
    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_STANDARD_CLASSES|ICC_WIN95_CLASSES}; InitCommonControlsEx(&icc);
    WNDCLASSEXW wc{}; wc.cbSize=sizeof(wc); wc.lpfnWndProc=MainWndProc; wc.hInstance=hInst; wc.hCursor=LoadCursor(NULL,IDC_ARROW); wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1); wc.lpszClassName=L"TumblechatWin"; if(!RegisterClassExW(&wc)){ WSACleanup(); return 1; }
    HWND hwnd=CreateWindowExW(0,L"TumblechatWin",L"Tumblechat", WS_OVERLAPPEDWINDOW|WS_VISIBLE,100,100,1140,500,NULL,NULL,hInst,NULL); if(!hwnd){ MessageBoxA(NULL,"CreateWindow failed","Error",MB_ICONERROR); WSACleanup(); return 1; }
    SetWindowTextW(hwnd, L"Tumblechat");
    MSG msg; while(GetMessage(&msg,NULL,0,0)>0){ TranslateMessage(&msg); DispatchMessage(&msg); }
    g_state.stopIo.store(true); if(g_state.session){ g_state.session->stop(); delete g_state.session; g_state.session=nullptr; } if(g_state.sock!=INVALID_SOCKET){ shutdown(g_state.sock,SD_BOTH); closesocket(g_state.sock); }
    WSACleanup(); return 0; }
