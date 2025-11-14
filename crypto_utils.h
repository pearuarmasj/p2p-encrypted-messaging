#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <iostream>
#include <chrono>
#include <cstring>

#include <osrng.h>
#include <rsa.h>
#include <secblock.h>
#include <gcm.h>
#include <filters.h>
#include <queue.h>
#include <sha.h>
#include <hmac.h>

// RSA key serialization
static inline std::vector<uint8_t> serializePublicKey(const CryptoPP::RSA::PublicKey& pub) {
    CryptoPP::ByteQueue q;
    pub.Save(q);
    size_t n = q.CurrentSize();
    std::vector<uint8_t> buf(n);
    q.Get(buf.data(), n);
    return buf;
}

static inline bool loadPublicKey(const uint8_t* data, size_t len, CryptoPP::RSA::PublicKey& pub) {
    try {
        CryptoPP::ByteQueue q;
        q.Put(data, len);
        pub.Load(q);
        return true;
    } catch (...) {
        return false;
    }
}

// RSA key wrapping
static inline std::vector<uint8_t> rsaWrapAesKey(const CryptoPP::RSA::PublicKey& pub, const CryptoPP::SecByteBlock& aesKey) {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Encryptor enc(pub);
    std::string wrapped;
    CryptoPP::StringSource ss(aesKey.data(), aesKey.size(), true,
        new CryptoPP::PK_EncryptorFilter(rng, enc, new CryptoPP::StringSink(wrapped)));
    return std::vector<uint8_t>(wrapped.begin(), wrapped.end());
}

// AES-GCM encryption/decryption
static inline bool aesGcmEncrypt(const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& nonce,
    const std::string& plain, std::vector<uint8_t>& outCipher) {
    try {
        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key, key.size(), nonce, nonce.size());
        std::string cipher;
        CryptoPP::AuthenticatedEncryptionFilter aef(enc, new CryptoPP::StringSink(cipher), false, 16);
        CryptoPP::StringSource ss(plain, true, new CryptoPP::Redirector(aef));
        outCipher.assign(cipher.begin(), cipher.end());
        return true;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "GCM encrypt error: " << e.what() << std::endl;
        return false;
    }
}

static inline bool aesGcmDecrypt(const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& nonce,
    const uint8_t* cipher, size_t len, std::string& outPlain) {
    try {
        CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key, key.size(), nonce, nonce.size());
        std::string plain;
        CryptoPP::AuthenticatedDecryptionFilter adf(dec, new CryptoPP::StringSink(plain),
            CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION, 16);
        CryptoPP::StringSource ss(cipher, len, true, new CryptoPP::Redirector(adf));
        outPlain = std::move(plain);
        return true;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "GCM decrypt error: " << e.what() << std::endl;
        return false;
    }
}

// Utility functions for encoding/decoding 64-bit integers
static inline void write_u64be(uint64_t v, std::string& out, size_t offset) {
    for (int i = 7; i >= 0; --i)
        out[offset + (7 - i)] = (char)((v >> (i * 8)) & 0xFF);
}

static inline uint64_t read_u64be(const std::string& in, size_t offset) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | (uint8_t)in[offset + i];
    }
    return v;
}

// Data payload generation and parsing
static inline bool makeDataPayload(const CryptoPP::SecByteBlock& sessionKey, uint64_t counter,
    const std::string& msg, CryptoPP::AutoSeededRandomPool& rng,
    std::vector<uint8_t>& payloadOut, bool useHmac) {
    CryptoPP::SecByteBlock nonce(12);
    rng.GenerateBlock(nonce, nonce.size());
    uint64_t unixMs = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::string plain;
    plain.resize(16);
    write_u64be(counter, plain, 0);
    write_u64be(unixMs, plain, 8);
    plain.append(msg);
    if (useHmac) {
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(sessionKey, sessionKey.size());
        hmac.Update(reinterpret_cast<const CryptoPP::byte*>(plain.data()), plain.size());
        CryptoPP::byte mac[32];
        hmac.Final(mac);
        plain.append(reinterpret_cast<const char*>(mac), 32);
    }
    std::vector<uint8_t> cipher;
    if (!aesGcmEncrypt(sessionKey, nonce, plain, cipher))
        return false;
    payloadOut.clear();
    payloadOut.push_back((uint8_t)nonce.size());
    payloadOut.insert(payloadOut.end(), nonce.begin(), nonce.end());
    uint32_t clen = (uint32_t)cipher.size();
    payloadOut.push_back((uint8_t)((clen >> 24) & 0xFF));
    payloadOut.push_back((uint8_t)((clen >> 16) & 0xFF));
    payloadOut.push_back((uint8_t)((clen >> 8) & 0xFF));
    payloadOut.push_back((uint8_t)(clen & 0xFF));
    payloadOut.insert(payloadOut.end(), cipher.begin(), cipher.end());
    return true;
}

static inline bool parseDataPayload(const CryptoPP::SecByteBlock& sessionKey,
    const std::vector<uint8_t>& data, uint64_t& counterOut, uint64_t& tsMsOut,
    std::string& msgOut, bool expectHmac, std::string& err) {
    if (data.size() < 1 + 4) {
        err = "short frame";
        return false;
    }
    size_t idx = 0;
    uint8_t nlen = data[idx++];
    if (data.size() < 1 + nlen + 4) {
        err = "short nonce";
        return false;
    }
    CryptoPP::SecByteBlock nonce(nlen);
    memcpy(nonce, data.data() + idx, nlen);
    idx += nlen;
    uint32_t clen = ((uint32_t)data[idx] << 24) | ((uint32_t)data[idx + 1] << 16) |
        ((uint32_t)data[idx + 2] << 8) | (uint32_t)data[idx + 3];
    idx += 4;
    if (data.size() < idx + clen) {
        err = "short cipher";
        return false;
    }
    std::string plain;
    if (!aesGcmDecrypt(sessionKey, nonce, data.data() + idx, clen, plain)) {
        err = "auth fail";
        return false;
    }
    if (plain.size() < 16) {
        err = "short plain";
        return false;
    }
    
    // Only process HMAC when expectHmac is true
    size_t macOff = plain.size();
    if (expectHmac) {
        // HMAC must be present and 32 bytes long
        if (plain.size() < 16 + 32) {
            err = "missing hmac";
            return false;
        }
        macOff = plain.size() - 32;
        
        // Verify HMAC
        CryptoPP::HMAC<CryptoPP::SHA256> hmac(sessionKey, sessionKey.size());
        hmac.Update(reinterpret_cast<const CryptoPP::byte*>(plain.data()), macOff);
        CryptoPP::byte mac[32];
        hmac.Final(mac);
        if (memcmp(mac, plain.data() + macOff, 32) != 0) {
            err = "hmac mismatch";
            return false;
        }
    }
    
    // Ensure plain is large enough for counter and timestamp
    counterOut = read_u64be(plain, 0);
    tsMsOut = read_u64be(plain, 8);
    msgOut.assign(plain.begin() + 16, plain.begin() + macOff);
    
    return true;
}
