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
#define IP_ADDRESS "127.0.0.1"
#define DEFAULT_BUFLEN 65536
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

string recvMessage(SOCKET ConnectSocket, const CryptoPP::SecByteBlock &key, const CryptoPP::SecByteBlock &iv) {
    char recvbuf[DEFAULT_BUFLEN];
    string message;
    int iResult;

    do {
        iResult = recv(ConnectSocket, recvbuf, DEFAULT_BUFLEN, 0);
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

// Deserialize the SecByteBlocks from the host using hex decoding, and print the key and IV to the console
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

// Receive the HEX serialized blocks from the host
void ReceiveSerializedSecByteBlocks(SOCKET& ConnectSocket, CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv) {
    // Receive the serialized key and IV
    char recvbuf[DEFAULT_BUFLEN];
    int iResult = recv(ConnectSocket, recvbuf, DEFAULT_BUFLEN, 0);
    // Print the serialized blocks to the console
    if (iResult > 0) {
        cout << "Received serialized key and IV: " << recvbuf << endl;
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
    if (iResult > 0) {
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
        cout << "\nEnter a message to send to the host: ";
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

        // Receive a message from the host
        char recvbuf[DEFAULT_BUFLEN];
        iResult = recv(ConnectSocket, recvbuf, DEFAULT_BUFLEN, 0);
        if (iResult > 0) {
            string cipher(recvbuf, iResult);
            string plain;
            DecryptMessage(cipher, plain, key, iv);
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