#include <iostream>        // For standard I/O operations
#include <winsock2.h>      // For Windows Socket operations
#include <ws2tcpip.h>      // For Windows Socket operations (IP specifics)        
#include <osrng.h>         // For cryptographic random number generation
#include <cryptlib.h>      // For CryptoPP
#include <string>          // For string
#include <sstream>         // For string stream
#include <ostream>         // For output stream
#include <base64.h>        // For base64 encoding/decoding
#include <istream>         // For input stream
#include <assert.h>        // For assert
#include <filters.h>       // For CryptoPP filters
#include <modes.h>         // For CryptoPP modes
#include <aes.h>           // For AES cryptography
#include <secblock.h>      // For CryptoPP SecByteBlock
#include <hex.h>           // For CryptoPP HexEncoder
#include <files.h>         // For CryptoPP FileSink and FileSource

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "cryptlib.lib")
#define DEFAULT_PORT "27015"
#define IP_ADDRESS "127.0.0.1" // Change this to your local IPv4 address on your machine and port forward it through your router if you want to connect to this server from another machine on the internet
#define DEFAULT_BUFLEN 65536
// This will be the program that the host will run, and the client will connect to.

using namespace std;
using namespace CryptoPP;

// Key and IV generation

void GenerateAESKey(CryptoPP::byte key[AES::DEFAULT_KEYLENGTH]) {
    AutoSeededRandomPool rng;
    rng.GenerateBlock(key, AES::DEFAULT_KEYLENGTH);
}

void GenerateAESIV(CryptoPP::byte iv[AES::BLOCKSIZE]) {
    AutoSeededRandomPool rng;
    rng.GenerateBlock(iv, AES::BLOCKSIZE);
}

// Send the key and IV to the client

void SendKeyAndIV(SOCKET& ClientSocket, const CryptoPP::byte key[AES::DEFAULT_KEYLENGTH], const CryptoPP::byte iv[AES::BLOCKSIZE]) {
    // Send the key
    int iSendResult = send(ClientSocket, (char*)key, AES::DEFAULT_KEYLENGTH, 0);
    if (iSendResult == SOCKET_ERROR) {
        cout << "send failed with error: " << WSAGetLastError() << endl;
        closesocket(ClientSocket);
        WSACleanup();
        exit(1);
    }

    // Send the IV
    iSendResult = send(ClientSocket, (char*)iv, AES::BLOCKSIZE, 0);
    if (iSendResult == SOCKET_ERROR) {
        cout << "send failed with error: " << WSAGetLastError() << endl;
        closesocket(ClientSocket);
        WSACleanup();
        exit(1);
    }
}

void EncryptMessage(const string& plain, string& cipher, const CryptoPP::byte key[AES::DEFAULT_KEYLENGTH], const CryptoPP::byte iv[AES::BLOCKSIZE]) {
    try {
        CBC_Mode<AES>::Encryption encryption;
        encryption.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

        // The StreamTransformationFilter adds padding as required.
        StringSource ss(plain, true,
            new StreamTransformationFilter(encryption,
                new Base64Encoder(new StringSink(cipher), false) // false for no newline
            )
        );
    } catch (const Exception& e) {
        cerr << "Error in EncryptMessage: " << e.what() << endl;
    }
}

void DecryptMessage(const string& cipher, string& plain, const CryptoPP::byte key[AES::DEFAULT_KEYLENGTH], const CryptoPP::byte iv[AES::BLOCKSIZE]) {
    try {
        CBC_Mode<AES>::Decryption decryption;
        decryption.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

        StringSource ss(cipher, true,
            new Base64Decoder(
                new StreamTransformationFilter(decryption,
                    new StringSink(plain)
                )
            )
        );
    } catch (const Exception& e) {
        cerr << "Error in DecryptMessage: " << e.what() << endl;
    }
}

string recvMessage(SOCKET ListenSocket, const CryptoPP::SecByteBlock &key, const CryptoPP::SecByteBlock &iv) {
    char recvbuf[DEFAULT_BUFLEN];
    string message;
    int iResult;

    do {
        iResult = recv(ListenSocket, recvbuf, DEFAULT_BUFLEN, 0);
        if (iResult > 0) {
            message.append(recvbuf, iResult);
        } else if (iResult == 0) {
            cout << "Connection closing..." << endl;
        } else {
            cout << "recv failed with error: " << WSAGetLastError() << endl;
            // Handle error, close socket, etc.
            break;
        }
    } while (iResult == DEFAULT_BUFLEN); // If the buffer was filled, there might be more data.

    string plain;
    DecryptMessage(message, plain, key, iv);
    return plain;
}

// Serialization of the key and IV blocks for sending over the network, using hex encoding
void SerializeSecByteBlocks(const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv, string& serialized) {
    // Serialize the key
    string serializedKey;
    StringSource ss(key.data(), key.size(), true,
        new HexEncoder(
            new StringSink(serializedKey)
        )
    );

    // Serialize the IV
    string serializedIV;
    StringSource ss2(iv.data(), iv.size(), true,
        new HexEncoder(
            new StringSink(serializedIV)
        )
    );

    // Concatenate the key and IV
    serialized = serializedKey + serializedIV;
}

// Deserialize the SecByteBlocks from the client using hex decoding, and print the key and IV to the console
void DeserializeSecByteBlocks(const string& serialized, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv) {
    // Deserialize the key
    string serializedKey = serialized.substr(0, AES::DEFAULT_KEYLENGTH * 2);
    StringSource ss(serializedKey, true,
        new HexDecoder(
            new ArraySink((CryptoPP::byte*)key, AES::DEFAULT_KEYLENGTH)
        )
    );

    // Deserialize the IV
    string serializedIV = serialized.substr(AES::DEFAULT_KEYLENGTH * 2, AES::BLOCKSIZE * 2);
    StringSource ss2(serializedIV, true,
        new HexDecoder(
            new ArraySink((CryptoPP::byte*)iv, AES::BLOCKSIZE)
        )
    );

    // Print the key and IV to the console
    cout << "Key: ";
    StringSource ss3(key.data(), key.size(), true,
        new HexEncoder(
            new FileSink(cout)
        )
    );
    cout << endl;
    cout << "IV: ";
    StringSource ss4(iv.data(), iv.size(), true,
        new HexEncoder(
            new FileSink(cout)
        )
    );
    cout << endl;
}

// Send the HEX serialized blocks to the client
void SendSerializedBlocks(SOCKET& ClientSocket, const string& serialized) {
    // Send the serialized blocks
    int iSendResult = send(ClientSocket, serialized.c_str(), serialized.size(), 0);
}

// Discard the old key and IV and generate new ones, then send them to the client
void RegenerateKeyAndIV(SOCKET& ClientSocket, CryptoPP::SecByteBlock& key2, CryptoPP::SecByteBlock& iv2) {
    // Generate the key and IV
    GenerateAESKey(key2);
    GenerateAESIV(iv2);

    // Print the key and IV to the console
    cout << "Key: ";
    StringSource(key2.data(), key2.size(), true,
        new HexEncoder(
            new FileSink(cout)
        )
    );
    cout << endl;
    cout << "IV: ";
    StringSource(iv2.data(), iv2.size(), true,
        new HexEncoder(
            new FileSink(cout)
        )
    );
    cout << endl;

    // Serialize the blocks
    string serialized;
    SerializeSecByteBlocks(key2, iv2, serialized);

    // Print the serialized blocks to the console
    cout << "Serialized key and IV: " << serialized << endl;

    // Send the SERIALIZED blocks to the client
    SendSerializedBlocks(ClientSocket, serialized);
}

int main() {
    // Initialize Winsock
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != NO_ERROR) {
        cout << "WSAStartup failed with error: " << iResult << endl;
        return 1;
    }

    // Create a SOCKET for connecting to server
    SOCKET ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ListenSocket == INVALID_SOCKET) {
        cout << "socket failed with error: " << WSAGetLastError() << endl;
        WSACleanup();
        return 1;
    }

    // Setup the TCP listening socket
    sockaddr_in service;
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = inet_addr(IP_ADDRESS);
    service.sin_port = htons(27015);

    if (bind(ListenSocket, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
        cout << "bind failed with error: " << WSAGetLastError() << endl;
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    if (listen(ListenSocket, 1) == SOCKET_ERROR) {
        cout << "listen failed with error: " << WSAGetLastError() << endl;
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // Accept a client socket
    SOCKET ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET) {
        cout << "accept failed with error: " << WSAGetLastError() << endl;
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // No longer need server socket
    closesocket(ListenSocket);

    // Generate the key and IV
    CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
    CryptoPP::byte iv[AES::BLOCKSIZE];
    GenerateAESKey(key);
    GenerateAESIV(iv);

    // Print the key and IV to the console
    cout << "Key: ";
    StringSource(key, AES::DEFAULT_KEYLENGTH, true,
        new HexEncoder(
            new FileSink(cout)
        )
    );
    cout << endl;
    cout << "IV: ";
    StringSource(iv, AES::BLOCKSIZE, true,
        new HexEncoder(
            new FileSink(cout)
        )
    );
    cout << endl;

    // Put the key and IV into SecByteBlocks
    CryptoPP::SecByteBlock& keyBlock = *(new CryptoPP::SecByteBlock(key, AES::DEFAULT_KEYLENGTH));
    CryptoPP::SecByteBlock& ivBlock = *(new CryptoPP::SecByteBlock(iv, AES::BLOCKSIZE));

    // Serialize the blocks
    string serialized;
    SerializeSecByteBlocks(keyBlock, ivBlock, serialized);

    // Print the serialized blocks to the console
    cout << "Serialized key and IV: " << serialized << endl;

    // Send the SERIALIZED blocks to the client
    SendSerializedBlocks(ClientSocket, serialized);
    if (iResult == SOCKET_ERROR) {
        cout << "send failed with error: " << WSAGetLastError() << endl;
        closesocket(ClientSocket);
        WSACleanup();
        return 1;
    }

    // Establish an encrypted communication loop with the client
    bool keepCommunicating = true;
    while (keepCommunicating) {
        // Receive a message from the client
        char recvbuf[DEFAULT_BUFLEN];
        int iResult = recv(ClientSocket, recvbuf, DEFAULT_BUFLEN, 0);
        if (iResult > 0) {
            string cipher = recvbuf;
            string plain;
            DecryptMessage(cipher, plain, key, iv);
            // Print the key and IV to the console
            cout << "Key: ";
            StringSource(key, AES::DEFAULT_KEYLENGTH, true,
                new HexEncoder(
                    new FileSink(cout)
                )
            );
            cout << "\n";
            cout << "IV: ";
            StringSource(iv, AES::BLOCKSIZE, true,
                new HexEncoder(
                    new FileSink(cout)
                )
            );
            cout << "\nClient: " << plain << endl;
        } else if (iResult == 0) {
            cout << "Connection closing..." << endl;
            keepCommunicating = false;
        } else {
            cout << "recv failed with error: " << WSAGetLastError() << endl;
            closesocket(ClientSocket);
            WSACleanup();
            return 1;
        }

        // Generate a new key and IV and send them to the client before the message
        CryptoPP::SecByteBlock key2(AES::DEFAULT_KEYLENGTH);
        CryptoPP::SecByteBlock iv2(AES::BLOCKSIZE);
        RegenerateKeyAndIV(ClientSocket, key2, iv2);
        string plain;
        cout << "Enter a message to send to the client: ";
        getline(cin, plain);
        string cipher;
        EncryptMessage(plain, cipher, key2, iv2);
        iResult = send(ClientSocket, cipher.c_str(), cipher.length(), 0);
        if (iResult == SOCKET_ERROR) {
            cout << "send failed with error: " << WSAGetLastError() << endl;
            closesocket(ClientSocket);
            WSACleanup();
            return 1;
        }
    }

    // Cleanup
    closesocket(ClientSocket);
    WSACleanup();

    return 0;
}