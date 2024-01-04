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
#include <rsa.h>           // For CryptoPP RSA cryptography
#include <queue.h>         // For CryptoPP Queue
#include <queue>           // For std::queue

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "cryptlib.lib")
#define DEFAULT_PORT "27015"
#define IP_ADDRESS "192.168.1.128"
#define DEFAULT_BUFLEN 262144
#define RSA_KEYLENGTH 3072
#define AES_DEFAULT_KEYLENGTH 32
#define AES_BLOCKSIZE 16
#define AES_IV_SIZE 16

using namespace std;
using namespace CryptoPP;

// This will be the program that the host will run and wait for the client to connect.

// We will use CBC mode and Base64 for the encoding and encryption of messages and keys.
// We will also use base64 for serialization / deserialization of keys.
// We will make sure that we are exact with our data handling, manipulation, and transmission.
// We will also make sure that the functions / logic of both the client and host are the same and perfectly complementary.
// Our code will be as clean, short, but as secure as possible.

// This class will set up the host's listening socket and accept a connection from the client.

class Host
{
public:
    SOCKET ListenSocket;
    SOCKET ClientSocket;
    sockaddr_in service;
    int iResult;

    Host()
    {
        // Initialize Winsock
        WSADATA wsaData;
        iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (iResult != NO_ERROR) {
            cout << "WSAStartup failed with error: " << iResult << endl;
            exit(1);
        }

        // Create a SOCKET for listening for incoming connection requests.
        ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (ListenSocket == INVALID_SOCKET) {
            cout << "socket failed with error: " << WSAGetLastError() << endl;
            WSACleanup();
            exit(1);
        }

        // The sockaddr_in structure specifies the address family,
        // IP address, and port for the socket that is being bound.
        service.sin_family = AF_INET;
        service.sin_addr.s_addr = inet_addr(IP_ADDRESS);
        service.sin_port = htons(27015);

        // Bind the socket.
        iResult = bind(ListenSocket, (SOCKADDR*)&service, sizeof(service));
        if (iResult == SOCKET_ERROR) {
            cout << "bind failed with error: " << WSAGetLastError() << endl;
            closesocket(ListenSocket);
            WSACleanup();
            exit(1);
        }

        // Listen for incoming connection requests.
        // on the created socket
        if (listen(ListenSocket, 1) == SOCKET_ERROR)
            cout << "Error listening on socket.\n";

        // Accept the connection.
        ClientSocket = SOCKET_ERROR;
        while (ClientSocket == SOCKET_ERROR) {
            cout << "Waiting for a client to connect...\n";
            ClientSocket = accept(ListenSocket, NULL, NULL);
        }
        cout << "Client connected.\n";
    }

    ~Host()
    {
        // No longer need server socket
        closesocket(ListenSocket);
        closesocket(ClientSocket);
        WSACleanup();
    }
};

// This function will generate the RSA key pair.
void GenerateRSAKeyPair(RSA::PrivateKey& privateKey, RSA::PublicKey& publicKey)
{
    AutoSeededRandomPool rng;
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, RSA_KEYLENGTH);
    privateKey = RSA::PrivateKey(params);
    publicKey = RSA::PublicKey(params);
}

// Function to serialize and encode RSA keys to Base64
void SerializeAndEncodeToBase64(const RSA::PrivateKey& privateKey, const RSA::PublicKey& publicKey, string& encodedPrivateKey, string& encodedPublicKey) {
    // Serialize private key
    ByteQueue queue;
    privateKey.Save(queue);
    SecByteBlock privateKeyBlock(queue.CurrentSize());
    queue.Get(privateKeyBlock, privateKeyBlock.size());

    // Serialize public key
    queue.Clear();
    publicKey.Save(queue);
    SecByteBlock publicKeyBlock(queue.CurrentSize());
    queue.Get(publicKeyBlock, publicKeyBlock.size());

    // Encode to Base64
    Base64Encoder encoder;
    StringSink* pSink;

    // Encode private key
    pSink = new StringSink(encodedPrivateKey);
    encoder.Attach(pSink);
    encoder.Put(privateKeyBlock, privateKeyBlock.size());
    encoder.MessageEnd();

    // Encode public key
    encodedPublicKey.clear();
    pSink = new StringSink(encodedPublicKey);
    encoder.Attach(pSink);
    encoder.Put(publicKeyBlock, publicKeyBlock.size());
    encoder.MessageEnd();
}

// This function will receive the encrypted AES key and IV strings from the client, then decrypt them using the RSA private key, then decode them from Base64.
void ReceiveAndDecryptAESKeyAndIV(const RSA::PrivateKey& privateKey, string encodedKey, string encodedIV) {
    // Decode from Base64
    string decodedKey, decodedIV;
    StringSource(encodedKey, true, new Base64Decoder(new StringSink(decodedKey)));
    StringSource(encodedIV, true, new Base64Decoder(new StringSink(decodedIV)));

    // Decrypt using RSA private key
    RSAES_OAEP_SHA_Decryptor d(privateKey);
    AutoSeededRandomPool rng;
    string decryptedKey, decryptedIV;
    StringSource(decodedKey, true, new PK_DecryptorFilter(rng, d, new StringSink(decryptedKey)));
    StringSource(decodedIV, true, new PK_DecryptorFilter(rng, d, new StringSink(decryptedIV)));

    // Print decrypted AES key and IV
    cout << "Decrypted AES key: " << decryptedKey << "\n";
    cout << "Decrypted IV: " << decryptedIV << "\n";
}

// This function will use the decrypted AES key and IV to decrypt the message from the client.
void DecryptMessage(const SecByteBlock& keyBlock, const SecByteBlock& ivBlock, SOCKET& ClientSocket) {
    // Receive encrypted message from client
    int iResult;
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;
    iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
    if (iResult > 0) {
        // Decode message from Base64
        string encodedMessage(recvbuf);
        StringSource(encodedMessage, true, new Base64Decoder(new ArraySink((CryptoPP::byte*)recvbuf, recvbuflen)));

        // Decrypt message using AES key and IV
        string decryptedMessage;
        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(keyBlock, keyBlock.size(), ivBlock);
        StringSource((CryptoPP::byte*)recvbuf, recvbuflen, true, new StreamTransformationFilter(d, new StringSink(decryptedMessage)));

        // Print decrypted message
        cout << "Decrypted message from client: " << decryptedMessage << "\n";
    }
    else if (iResult == 0)
        cout << "Connection closed\n";
    else
        cout << "recv failed with error: " << WSAGetLastError() << "\n";
}

// This function will encrypt messages using the AES key and IV.
void EncryptMessage(const SecByteBlock& keyBlock, const SecByteBlock& ivBlock, SOCKET& ClientSocket) {
    // Encrypt message using AES key and IV
    string message = "Hello from host!";
    string encryptedMessage;
    CBC_Mode<AES>::Encryption e;
    e.SetKeyWithIV(keyBlock, keyBlock.size(), ivBlock);
    StringSource(message, true, new StreamTransformationFilter(e, new StringSink(encryptedMessage)));

    // Encode message to Base64
    string encodedMessage;
    StringSource(encryptedMessage, true, new Base64Encoder(new StringSink(encodedMessage)));

    // Send encoded message to client
    int iResult;
    iResult = send(ClientSocket, encodedMessage.c_str(), encodedMessage.size(), 0);
    if (iResult == SOCKET_ERROR) {
        cout << "send failed with error: " << WSAGetLastError() << "\n";
        closesocket(ClientSocket);
        WSACleanup();
        exit(1);
    }
    cout << "Sent encrypted message to client: " << encodedMessage << "\n";
}

int main() {
    Host host;

    // Generate RSA key pair.
    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;
    GenerateRSAKeyPair(privateKey, publicKey);

    // Serialize and encode RSA keys to Base64
    string encodedPrivateKey;
    string encodedPublicKey;
    SerializeAndEncodeToBase64(privateKey, publicKey, encodedPrivateKey, encodedPublicKey);

    // Print the encoded public key
    cout << "Encoded public key: " << encodedPublicKey << endl;

    // Send RSA public key to client
    int iResult;
    iResult = send(host.ClientSocket, encodedPublicKey.c_str(), encodedPublicKey.size(), 0);
    if (iResult == SOCKET_ERROR) {
        cout << "send failed with error: " << WSAGetLastError() << endl;
        closesocket(host.ClientSocket);
        WSACleanup();
        exit(1);
    }
    cout << "Bytes sent: " << iResult << endl;

    Sleep(500);

    // Receive and decrypt AES key and IV from client
    char recvbuf[DEFAULT_BUFLEN];
    int recvbuflen = DEFAULT_BUFLEN;
    iResult = recv(host.ClientSocket, recvbuf, recvbuflen, 0);
    if (iResult > 0) {
        string encodedKey(recvbuf);
        Sleep(500);
        iResult = recv(host.ClientSocket, recvbuf, recvbuflen, 0);
        if (iResult > 0) {
            string encodedIV(recvbuf);
            cout << "Encoded AES key: " << encodedKey << "\n";
            cout << "Encoded IV: " << encodedIV << "\n";
            ReceiveAndDecryptAESKeyAndIV(privateKey, encodedKey, encodedIV);
        }
        else if (iResult == 0)
            cout << "Connection closed\n";
        else
            cout << "recv failed with error: " << WSAGetLastError() << "\n";
    }
    else if (iResult == 0)
        cout << "Connection closed\n";
    else
        cout << "recv failed with error: " << WSAGetLastError() << "\n";
}