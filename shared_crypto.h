#pragma once

#include <iostream>
#include <winsock2.h>
#include <string>
#include <base64.h>
#include <filters.h>
#include <modes.h>
#include <aes.h>
#include <secblock.h>
#include <hex.h>
#include <files.h>

#define DEFAULT_BUFLEN 65536

// Shared encryption and serialization functions

void EncryptMessage(const std::string& plain, std::string& cipher, const CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], const CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE]) {
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
        encryption.SetKeyWithIV(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);

        // The StreamTransformationFilter adds padding as required.
        CryptoPP::StringSource ss(plain, true,
            new CryptoPP::StreamTransformationFilter(encryption,
                new CryptoPP::Base64Encoder(new CryptoPP::StringSink(cipher), false) // false for no newline
            )
        );
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error in EncryptMessage: " << e.what() << std::endl;
    }
}

void DecryptMessage(const std::string& cipher, std::string& plain, const CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH], const CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE]) {
    try {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;
        decryption.SetKeyWithIV(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);

        CryptoPP::StringSource ss(cipher, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StreamTransformationFilter(decryption,
                    new CryptoPP::StringSink(plain)
                )
            )
        );
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error in DecryptMessage: " << e.what() << std::endl;
    }
}

std::string recvMessage(SOCKET socket, const CryptoPP::SecByteBlock &key, const CryptoPP::SecByteBlock &iv) {
    char recvbuf[DEFAULT_BUFLEN];
    std::string message;
    int iResult;

    do {
        iResult = recv(socket, recvbuf, DEFAULT_BUFLEN, 0);
        if (iResult > 0) {
            message.append(recvbuf, iResult);
        } else if (iResult == 0) {
            std::cout << "Connection closing..." << std::endl;
        } else {
            std::cout << "recv failed with error: " << WSAGetLastError() << std::endl;
            // Handle error, close socket, etc.
            break;
        }
    } while (iResult == DEFAULT_BUFLEN); // If the buffer was filled, there might be more data.

    std::string plain;
    DecryptMessage(message, plain, key, iv);
    return plain;
}

// Serialization of the key and IV blocks for sending over the network, using hex encoding
void SerializeSecByteBlocks(const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv, std::string& serialized) {
    // Serialize the key
    std::string serializedKey;
    CryptoPP::StringSource ss(key.data(), key.size(), true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(serializedKey)
        )
    );

    // Serialize the IV
    std::string serializedIV;
    CryptoPP::StringSource ss2(iv.data(), iv.size(), true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(serializedIV)
        )
    );

    // Concatenate the key and IV
    serialized = serializedKey + serializedIV;
}

// Deserialize the SecByteBlocks using hex decoding, and print the key and IV to the console
void DeserializeSecByteBlocks(const std::string& serialized, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv) {
    // Deserialize the key
    std::string serializedKey = serialized.substr(0, CryptoPP::AES::DEFAULT_KEYLENGTH * 2);
    CryptoPP::StringSource ss(serializedKey, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::ArraySink((CryptoPP::byte*)key, CryptoPP::AES::DEFAULT_KEYLENGTH)
        )
    );

    // Deserialize the IV
    std::string serializedIV = serialized.substr(CryptoPP::AES::DEFAULT_KEYLENGTH * 2, CryptoPP::AES::BLOCKSIZE * 2);
    CryptoPP::StringSource ss2(serializedIV, true,
        new CryptoPP::HexDecoder(
            new CryptoPP::ArraySink((CryptoPP::byte*)iv, CryptoPP::AES::BLOCKSIZE)
        )
    );

    // Print the key and IV to the console
    std::cout << "Key: ";
    CryptoPP::StringSource ss3(key.data(), key.size(), true,
        new CryptoPP::HexEncoder(
            new CryptoPP::FileSink(std::cout)
        )
    );
    std::cout << std::endl;
    std::cout << "IV: ";
    CryptoPP::StringSource ss4(iv.data(), iv.size(), true,
        new CryptoPP::HexEncoder(
            new CryptoPP::FileSink(std::cout)
        )
    );
    std::cout << std::endl;
}
