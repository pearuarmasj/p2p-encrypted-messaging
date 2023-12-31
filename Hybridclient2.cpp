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
#include <files.h>         // For CryptoPP FileSink and FileSource
#include <queue.h>         // For CryptoPP Queue
#include <queue>           // For std::queue
#include <rsa.h>           // For CryptoPP RSA cryptography

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "cryptlib.lib")
#define DEFAULT_PORT "27015"
#define IP_ADDRESS "127.0.0.1" // Change this to the public IP address of the network the host application is listening on.
#define DEFAULT_BUFLEN 262144
#define RSA_KEYLENGTH 3072
#define AES_DEFAULT_KEYLENGTH 32
#define AES_BLOCKSIZE 16
#define AES_IV_SIZE 16

using namespace std;
using namespace CryptoPP;

// This will be the program that the client will run and connect to the host.

// This class will be used to set up the connection socket to the host.

class Client
{
public:
    SOCKET ConnectSocket;
    sockaddr_in clientService;

    Client()
    {
        // Initialize Winsock
        WSADATA wsaData;
        int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != NO_ERROR) {
            cout << "WSAStartup failed with error: " << iResult << endl;
            exit(1);
        }

        // Create a SOCKET for connecting to server
        ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (ConnectSocket == INVALID_SOCKET) {
            cout << "socket failed with error: " << WSAGetLastError() << endl;
            WSACleanup();
            exit(1);
        }

        // The sockaddr_in structure specifies the address family,
        // IP address, and port of the server to be connected to.
        clientService.sin_family = AF_INET;
        clientService.sin_addr.s_addr = inet_addr(IP_ADDRESS);
        clientService.sin_port = htons(27015);

        // Connect to server.
        iResult = connect(ConnectSocket, (SOCKADDR*)&clientService, sizeof(clientService));
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            cout << "Unable to connect to server: " << WSAGetLastError() << endl;
            WSACleanup();
            exit(1);
        }
    }
};

// This function will generate AES key and IV client-side.
void GenerateAESKeyAndIV(CryptoPP::byte key[], CryptoPP::byte iv[]) {
    AutoSeededRandomPool rng;
    rng.GenerateBlock(key, AES_DEFAULT_KEYLENGTH);
    rng.GenerateBlock(iv, AES_IV_SIZE);
}

// This function will receive the RSA public key SecByteBlock from the host, and decode it from base64.
void ReceiveRSAPublicKey(SOCKET ConnectSocket, SecByteBlock& publicKey) {
    int iResult;
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;
    iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
    if (iResult > 0) {
        cout << "Bytes received: " << iResult << endl;
        cout << "Received RSA public key from host." << endl;
        cout << "Received RSA public key: " << recvbuf << endl;
        cout << "Decoding RSA public key from base64..." << endl;
        string encodedPublicKey = recvbuf;
        string decodedPublicKey;
        StringSource ss(encodedPublicKey, true, new Base64Decoder(new StringSink(decodedPublicKey)));
        publicKey.Assign((CryptoPP::byte*)decodedPublicKey.data(), decodedPublicKey.size());
        cout << "RSA public key decoded from base64." << endl;
    }
    else if (iResult == 0) {
        cout << "Connection closed." << endl;
    }
    else {
        cout << "recv failed: " << WSAGetLastError() << endl;
    }
}

// This function will convert the decoded RSA public key into an RSA::PublicKey object.
void ConvertRSAPublicKeyToRSAPublicKeyObject(SecByteBlock& publicKey, RSA::PublicKey& rsaPublicKey) {
    cout << "Converting RSA public key to RSA public key object..." << endl;
    StringSource ss(publicKey, publicKey.size(), true);
    rsaPublicKey.Load(ss);
    cout << "RSA public key converted to RSA public key object." << endl;
}

// This function will encrypt and encode the AES key and IV using the RSA public key.
void EncryptAndEncodeAESKeyAndIV(RSA::PublicKey& rsaPublicKey, CryptoPP::byte key[], CryptoPP::byte iv[], string& encodedKey, string& encodedIV) {
    cout << "Encrypting AES key and IV using RSA public key..." << endl;
    string encryptedKey, encryptedIV;
    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Encryptor e(rsaPublicKey);
    StringSource ss1(key, AES_DEFAULT_KEYLENGTH, true, new PK_EncryptorFilter(rng, e, new StringSink(encryptedKey)));
    StringSource ss2(iv, AES_IV_SIZE, true, new PK_EncryptorFilter(rng, e, new StringSink(encryptedIV)));
    cout << "AES key and IV encrypted using RSA public key." << endl;
    cout << "Encoding encrypted AES key and IV using base64..." << endl;
    StringSource ss3(encryptedKey, true, new Base64Encoder(new StringSink(encodedKey)));
    StringSource ss4(encryptedIV, true, new Base64Encoder(new StringSink(encodedIV)));
    cout << "Encrypted AES key and IV encoded using base64." << endl;
}

// This function will be used to encrypt and encode messages using the AES key and IV.
void EncryptAndEncodeMessage(CryptoPP::byte key[], CryptoPP::byte iv[], string& message, string& encodedMessage) {
    string encryptedMessage;
    CBC_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, AES_DEFAULT_KEYLENGTH, iv);
    StringSource(message, true, new StreamTransformationFilter(e, new StringSink(encryptedMessage)));

    StringSource(encryptedMessage, true, new Base64Encoder(new StringSink(encodedMessage)));

    cout << "Encrypted message: " << encodedMessage << endl;
}

// This function will be used to decrypt and decode messages using the AES key and IV.
void DecryptAndDecodeMessage(CryptoPP::byte key[], CryptoPP::byte iv[], string& encodedMessage, string& decryptedMessage) {
    string decodedMessage;
    StringSource(encodedMessage, true, new Base64Decoder(new StringSink(decodedMessage)));

    CBC_Mode<AES>::Decryption d;
    d.SetKeyWithIV(key, AES_DEFAULT_KEYLENGTH, iv);
    StringSource(decodedMessage, true, new StreamTransformationFilter(d, new StringSink(decryptedMessage)));

    cout << "Decrypted message: " << decryptedMessage << endl;
}

int main() {
    Client client;

    // Receive RSA public key from host.
    SecByteBlock publicKey;
    ReceiveRSAPublicKey(client.ConnectSocket, publicKey);

    Sleep(500);

    // Convert RSA public key to RSA public key object.
    RSA::PublicKey rsaPublicKey;
    ConvertRSAPublicKeyToRSAPublicKeyObject(publicKey, rsaPublicKey);

    // Print the RSA public key in string sink.
    string publicKeyString;
    StringSink ss(publicKeyString);
    rsaPublicKey.Save(ss);
    cout << "RSA public key: " << publicKeyString << endl;

    // Generate AES key and IV.
    CryptoPP::byte key[AES_DEFAULT_KEYLENGTH];
    CryptoPP::byte iv[AES_IV_SIZE];
    GenerateAESKeyAndIV(key, iv);

    // Print the generated AES key and IV in string sink.
    string keyString, ivString;
    StringSink ss1(keyString);
    StringSink ss2(ivString);
    ss1.Put(key, AES_DEFAULT_KEYLENGTH);
    ss2.Put(iv, AES_IV_SIZE);
    cout << "Generated AES key: " << keyString << endl;
    cout << "Generated AES IV: " << ivString << endl;

    // Encrypt and encode AES key and IV using RSA public key.
    string encodedKey, encodedIV;
    EncryptAndEncodeAESKeyAndIV(rsaPublicKey, key, iv, encodedKey, encodedIV);

    // Print the encrypted and encoded AES key and IV.
    cout << "Encrypted and encoded AES key: " << encodedKey << endl;
    cout << "Encrypted and encoded AES IV: " << encodedIV << endl;

    Sleep(500);

    // Send the encrypted and encoded AES key and IV to the host.
    int iResult;
    iResult = send(client.ConnectSocket, encodedKey.c_str(), encodedKey.size(), 0);
    if (iResult == SOCKET_ERROR) {
        cout << "send failed: " << WSAGetLastError() << endl;
        closesocket(client.ConnectSocket);
        WSACleanup();
        exit(1);
    }
    cout << "Bytes sent: " << iResult << endl;

    Sleep(500);

    iResult = send(client.ConnectSocket, encodedIV.c_str(), encodedIV.size(), 0);
    if (iResult == SOCKET_ERROR) {
        cout << "send failed: " << WSAGetLastError() << endl;
        closesocket(client.ConnectSocket);
        WSACleanup();
        exit(1);
    }
    cout << "Bytes sent: " << iResult << endl;

    Sleep(500);

    // Establish an encrypted communication loop with the host.
    bool keepCommunicating = true;
    while (keepCommunicating) {
        // Send encoded message to host.
        string message;
        cout << "Enter message to send to host: ";
        getline(cin, message);
        string encodedMessage;
        EncryptAndEncodeMessage(key, iv, message, encodedMessage);
        iResult = send(client.ConnectSocket, encodedMessage.c_str(), encodedMessage.size(), 0);
        if (iResult == SOCKET_ERROR) {
            cout << "send failed: " << WSAGetLastError() << endl;
            closesocket(client.ConnectSocket);
            WSACleanup();
            exit(1);
        }
        cout << "Bytes sent: " << iResult << endl;

        // Receive encoded message from host.
        char recvbuf[DEFAULT_BUFLEN];
        int recvbuflen = DEFAULT_BUFLEN;
        iResult = recv(client.ConnectSocket, recvbuf, DEFAULT_BUFLEN, 0);
        if (iResult > 0) {
            string encodedMessage = recvbuf;
            string decryptedMessage;
            cout << "Received encrypted message from host: " << encodedMessage << endl;
            DecryptAndDecodeMessage(key, iv, encodedMessage, decryptedMessage);
        }
        else if (iResult == 0) {
            cout << "Connection closed." << endl;
            keepCommunicating = false;
        }
        else {
            cout << "recv failed: " << WSAGetLastError() << endl;
            keepCommunicating = false;
        }

        memset(recvbuf, 0, recvbuflen);

        Sleep(500);

        // Receive new RSA public key from host.
        SecByteBlock newPublicKey;
        ReceiveRSAPublicKey(client.ConnectSocket, newPublicKey);

        Sleep(500);

        // Convert new RSA public key to RSA public key object.
        RSA::PublicKey newRSAPublicKey;
        ConvertRSAPublicKeyToRSAPublicKeyObject(newPublicKey, newRSAPublicKey);

        // Print the new RSA public key in string sink.
        string newPublicKeyString;
        StringSink ss(newPublicKeyString);
        newRSAPublicKey.Save(ss);
        cout << "New RSA public key: " << newPublicKeyString << endl;

        // Generate new AES key and IV.
        CryptoPP::byte newKey[AES_DEFAULT_KEYLENGTH];
        CryptoPP::byte newIV[AES_IV_SIZE];
        GenerateAESKeyAndIV(newKey, newIV);

        // Print the generated new AES key and IV in string sink.
        string newKeyString, newIVString;
        StringSink ss1(newKeyString);
        StringSink ss2(newIVString);
        ss1.Put(newKey, AES_DEFAULT_KEYLENGTH);
        ss2.Put(newIV, AES_IV_SIZE);
        cout << "Generated new AES key: " << newKeyString << endl;
        cout << "Generated new AES IV: " << newIVString << endl;

        // Encrypt and encode new AES key and IV using new RSA public key.
        string newEncodedKey, newEncodedIV;
        EncryptAndEncodeAESKeyAndIV(newRSAPublicKey, newKey, newIV, newEncodedKey, newEncodedIV);

        // Print the encrypted and encoded new AES key and IV.
        cout << "Encrypted and encoded new AES key: " << newEncodedKey << endl;
        cout << "Encrypted and encoded new AES IV: " << newEncodedIV << endl;

        Sleep(500);

        // Send the encrypted and encoded new AES key and IV to the host.
        int iResult;
        iResult = send(client.ConnectSocket, newEncodedKey.c_str(), newEncodedKey.size(), 0);
        if (iResult == SOCKET_ERROR) {
            cout << "send failed: " << WSAGetLastError() << endl;
            closesocket(client.ConnectSocket);
            WSACleanup();
            exit(1);
        }
        cout << "Bytes sent: " << iResult << endl;

        Sleep(500);

        iResult = send(client.ConnectSocket, newEncodedIV.c_str(), newEncodedIV.size(), 0);
        if (iResult == SOCKET_ERROR) {
            cout << "send failed: " << WSAGetLastError() << endl;
            closesocket(client.ConnectSocket);
            WSACleanup();
            exit(1);
        }
        cout << "Bytes sent: " << iResult << endl;
    }
    // Close the socket
    closesocket(client.ConnectSocket);
    WSACleanup();

    return 0;
}