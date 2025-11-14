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
#include "shared_crypto.h" // Shared encryption and serialization functions

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "cryptlib.lib")
#define DEFAULT_PORT "27015"
#define IP_ADDRESS "127.0.0.1" // Change this to the public IP address of the network the host application is listening on.
// This will be the program that the client will run, and connect to the host.

using namespace std;
using namespace CryptoPP;

// Receive the key and IV from the host, confirm the reception and print success message

void ReceiveKeyAndIV(SOCKET& ConnectSocket, CryptoPP::byte key[AES::DEFAULT_KEYLENGTH], CryptoPP::byte iv[AES::BLOCKSIZE]) {
    // Receive the key
    int iResult = recv(ConnectSocket, (char*)key, AES::DEFAULT_KEYLENGTH, 0);
    if (iResult > 0) {
        cout << "Key received successfully." << endl;
    }
    else if (iResult == 0) {
        cout << "Connection closed." << endl;
        closesocket(ConnectSocket);
        WSACleanup();
        exit(1);
    }
    else {
        cout << "recv failed with error: " << WSAGetLastError() << endl;
        closesocket(ConnectSocket);
        WSACleanup();
        exit(1);
    }

    // Receive the IV
    iResult = recv(ConnectSocket, (char*)iv, AES::BLOCKSIZE, 0);
    if (iResult > 0) {
        cout << "IV received successfully." << endl;
    }
    else if (iResult == 0) {
        cout << "Connection closed." << endl;
        closesocket(ConnectSocket);
        WSACleanup();
        exit(1);
    }
    else {
        cout << "recv failed with error: " << WSAGetLastError() << endl;
        closesocket(ConnectSocket);
        WSACleanup();
        exit(1);
    }
}

// Functions moved to shared_crypto.h

// Receive the HEX serialized blocks from the host
void ReceiveSerializedSecByteBlocks(SOCKET& ConnectSocket, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv) {
    // Receive the serialized key and IV
    char recvbuf[DEFAULT_BUFLEN];
    int iResult = recv(ConnectSocket, recvbuf, DEFAULT_BUFLEN, 0);
    if (iResult > 0) {
        cout << "Received serialized key and IV: " << recvbuf << endl;
        // Deserialize the key and IV
        string serialized(recvbuf, iResult);
        DeserializeSecByteBlocks(serialized, key, iv);
    }
    else if (iResult == 0) {
        cout << "Connection closed." << endl;
        closesocket(ConnectSocket);
        WSACleanup();
        exit(1);
    }
    else {
        cout << "recv failed with error: " << WSAGetLastError() << endl;
        closesocket(ConnectSocket);
        WSACleanup();
        exit(1);
    }
}

// Receive the new key and IV from the host
void ReceiveNewKeyAndIV(SOCKET& ConnectSocket, CryptoPP::SecByteBlock& key2, CryptoPP::SecByteBlock& iv2) {
    // Receive the new key and IV
    char recvbuf[DEFAULT_BUFLEN];
    int iResult = recv(ConnectSocket, recvbuf, DEFAULT_BUFLEN, 0);
    if (iResult > 0) {
        // Print the new key and IV to the console
        cout << "Received new key and IV: " << recvbuf << endl;
        // Deserialize the new key and IV
        string serialized(recvbuf, iResult);
        DeserializeSecByteBlocks(serialized, key2, iv2);
    }
    else if (iResult == 0) {
        cout << "Connection closed." << endl;
        closesocket(ConnectSocket);
        WSACleanup();
        exit(1);
    }
    else {
        cout << "recv failed with error: " << WSAGetLastError() << endl;
        closesocket(ConnectSocket);
        WSACleanup();
        exit(1);
    }
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
    SOCKET ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ConnectSocket == INVALID_SOCKET) {
        cout << "socket failed with error: " << WSAGetLastError() << endl;
        WSACleanup();
        return 1;
    }

    // Create a sockaddr_in object and set its values
    sockaddr_in clientService;
    clientService.sin_family = AF_INET;
    clientService.sin_addr.s_addr = inet_addr(IP_ADDRESS);
    clientService.sin_port = htons(27015);

    // Connect to server on port 27015
    if (connect(ConnectSocket, (SOCKADDR*)&clientService, sizeof(clientService)) == SOCKET_ERROR) {
        cout << "Failed to connect." << endl;
        WSACleanup();
        return 1;
    }

    // Receive the serialized key and IV blocks from the host
    CryptoPP::SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    CryptoPP::SecByteBlock iv(AES::BLOCKSIZE);
    ReceiveSerializedSecByteBlocks(ConnectSocket, key, iv);

    // Establish an encrypted communication loop with the host
    bool keepCommunicating = true;
    while (keepCommunicating) {
        // Send a message to the host
        string plain;
        cout << "Enter a message to send to the host: ";
        getline(cin, plain);
        string cipher;
        EncryptMessage(plain, cipher, key, iv);
        iResult = send(ConnectSocket, cipher.c_str(), cipher.length(), 0);
        if (iResult == SOCKET_ERROR) {
            cout << "send failed with error: " << WSAGetLastError() << endl;
            closesocket(ConnectSocket);
            WSACleanup();
            return 1;
        }

        // Receive the new key and IV from the host before receiving the message
        CryptoPP::SecByteBlock key2(AES::DEFAULT_KEYLENGTH);
        CryptoPP::SecByteBlock iv2(AES::BLOCKSIZE);
        ReceiveNewKeyAndIV(ConnectSocket, key2, iv2);
        // Receive the message
        char recvbuf[DEFAULT_BUFLEN];
        iResult = recv(ConnectSocket, recvbuf, DEFAULT_BUFLEN, 0);
        if (iResult > 0) {
            string cipher(recvbuf, iResult);
            string plain;
            DecryptMessage(cipher, plain, key2, iv2);
            cout << "Host: " << plain << endl;
        }
        else if (iResult == 0) {
            cout << "Connection closed." << endl;
            keepCommunicating = false;
        }
        else {
            cout << "recv failed with error: " << WSAGetLastError() << endl;
            closesocket(ConnectSocket);
            WSACleanup();
            return 1;
        }
    }

    // Close the socket
    closesocket(ConnectSocket);
    WSACleanup();

    return 0;
}