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

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "cryptlib.lib")
#define DEFAULT_PORT "27015"
#define IP_ADDRESS "127.0.0.1"
#define DEFAULT_BUFLEN 65536
// This will be the program that the client will run, and connect to the host.

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

string recvMessage(SOCKET socket, const CryptoPP::SecByteBlock &key, const CryptoPP::SecByteBlock &iv) {
    char recvbuf[DEFAULT_BUFLEN];
    string message;
    int iResult;

    do {
        iResult = recv(socket, recvbuf, DEFAULT_BUFLEN, 0);
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

    // Print the key and IV
    cout << "Key: ";
    for (int i = 0; i < AES::DEFAULT_KEYLENGTH; i++) {
        cout << hex << (int)key[i];
    }
    cout << endl;
    cout << "IV: ";
    for (int i = 0; i < AES::BLOCKSIZE; i++) {
        cout << hex << (int)iv[i];
    }

    // Send the key and IV to the client
    SendKeyAndIV(ClientSocket, key, iv);

    // Establish an encrypted communication loop with the client
    bool keepCommunicating = true;
    while (keepCommunicating) {
        // Receive a message from the client
        char recvbuf[DEFAULT_BUFLEN];
        int iResult = recv(ClientSocket, recvbuf, DEFAULT_BUFLEN, 0);
        if (iResult > 0) {
            cout << "\nBytes received: " << iResult << endl;
            cout << "Key: "; // Print the key again
            for (int i = 0; i < AES::DEFAULT_KEYLENGTH; i++) {
                cout << hex << (int)key[i];
            }
            cout << "\nIV: "; // Print the IV again
            for (int i = 0; i < AES::BLOCKSIZE; i++) {
                cout << hex << (int)iv[i];
            }
            cout << endl;
            string cipher = recvbuf;
            string plain;
            DecryptMessage(cipher, plain, key, iv);
            cout << "Client: " << plain << endl;
        } else if (iResult == 0) {
            cout << "Connection closing..." << endl;
            keepCommunicating = false;
        } else {
            cout << "recv failed with error: " << WSAGetLastError() << endl;
            closesocket(ClientSocket);
            WSACleanup();
            return 1;
        }

        // Send a message to the client
        string plain;
        cout << "Enter a message to send to the client: ";
        getline(cin, plain);
        string cipher;
        EncryptMessage(plain, cipher, key, iv);
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