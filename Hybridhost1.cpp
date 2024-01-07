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
#define IP_ADDRESS "127.0.0.1" // Change this to the IPv4 address of your machine, and port forward it through your router on port 27015, if the client is anywhere other than your local network.
#define DEFAULT_BUFLEN 262144
#define RSA_KEYLENGTH 3072
#define AES_DEFAULT_KEYLENGTH 32
#define AES_BLOCKSIZE 16
#define AES_IV_SIZE 16

using namespace std;
using namespace CryptoPP;

// This will be the program that the host will run and wait for the client to connect.

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

    // Print public key in string sink.
    string publicKeyString;
    StringSink* pSink = new StringSink(publicKeyString);
    publicKey.Save(*pSink);
    cout << "Public key: " << publicKeyString << endl;
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

// This function will recv the encrypted AES key and IV from the client, then decrypt them using the RSA private key, then decode them from Base64.
void ReceiveAndDecryptAESKeyAndIV(SOCKET ClientSocket, string& encryptedKey, string& encryptedIV, const RSA::PrivateKey& privateKey) {
    // Receive encrypted AES key from client
    char recvbuf[DEFAULT_BUFLEN];
    int iResult = recv(ClientSocket, recvbuf, DEFAULT_BUFLEN, 0);
    if (iResult > 0) {
        cout << "Bytes received: " << iResult << endl;
    }
    else if (iResult == 0) {
        cout << "Connection closed\n";
        closesocket(ClientSocket);
        WSACleanup();
        exit(1);
    }
    else {
        cout << "recv failed with error: " << WSAGetLastError() << endl;
        closesocket(ClientSocket);
        WSACleanup();
        exit(1);
    }

    Sleep(500);

    // Decode from Base64
    string decodedKey;
    StringSource(recvbuf, true, new Base64Decoder(new StringSink(decodedKey)));

    // Decrypt using RSA private key
    string decryptedKey;
    RSAES_OAEP_SHA_Decryptor d(privateKey);
    AutoSeededRandomPool rng;
    StringSource(decodedKey, true, new PK_DecryptorFilter(rng, d, new StringSink(decryptedKey)));

    // Print decrypted AES key
    cout << "Decrypted AES key: " << decryptedKey << "\n";

    // Receive encrypted AES IV from client
    Sleep(500);
    iResult = recv(ClientSocket, recvbuf, DEFAULT_BUFLEN, 0);
    if (iResult > 0) {
        cout << "Bytes received: " << iResult << endl;
    }
    else if (iResult == 0) {
        cout << "Connection closed\n";
        closesocket(ClientSocket);
        WSACleanup();
        exit(1);
    }
    else {
        cout << "recv failed with error: " << WSAGetLastError() << endl;
        closesocket(ClientSocket);
        WSACleanup();
        exit(1);
    }

    Sleep(500);

    // Decode from Base64
    string decodedIV;
    StringSource(recvbuf, true, new Base64Decoder(new StringSink(decodedIV)));

    // Decrypt using RSA private key
    string decryptedIV;
    StringSource(decodedIV, true, new PK_DecryptorFilter(rng, d, new StringSink(decryptedIV)));

    // Print decrypted AES IV
    cout << "Decrypted AES IV: " << decryptedIV << "\n";

    // Set encryptedKey and encryptedIV to the decrypted values
    encryptedKey = decryptedKey;
    encryptedIV = decryptedIV;
}

// This function will use the decrypted AES key and IV to decrypt the message from the client.
void DecryptAndDecodeMessage(string& encodedMessage, string& decryptedMessage, string decryptedKey, string decryptedIV) {
    // Decode from Base64
    string decodedMessage;
    StringSource(encodedMessage, true, new Base64Decoder(new StringSink(decodedMessage)));

    // Decrypt using AES key and IV
    CBC_Mode<AES>::Decryption d;
    d.SetKeyWithIV((CryptoPP::byte*)decryptedKey.data(), decryptedKey.size(), (CryptoPP::byte*)decryptedIV.data());
    StringSource(decodedMessage, true, new StreamTransformationFilter(d, new StringSink(decryptedMessage)));

    // Print decrypted message
    cout << "Decrypted message: " << decryptedMessage << "\n";
}

// This function will use the decrypted AES key and IV to encrypt a message to send to the client.
void EncryptAndEncodeMessage(string& message, string& encodedMessage, string decryptedKey, string decryptedIV) {
    // Encrypt using AES key and IV
    string encryptedMessage;
    CBC_Mode<AES>::Encryption e;
    e.SetKeyWithIV((CryptoPP::byte*)decryptedKey.data(), decryptedKey.size(), (CryptoPP::byte*)decryptedIV.data());
    StringSource(message, true, new StreamTransformationFilter(e, new StringSink(encryptedMessage)));

    // Encode to Base64
    StringSource(encryptedMessage, true, new Base64Encoder(new StringSink(encodedMessage)));

    // Print encoded message
    cout << "Encoded message: " << encodedMessage << "\n";
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
    string encryptedKey;
    string encryptedIV;
    ReceiveAndDecryptAESKeyAndIV(host.ClientSocket, encryptedKey, encryptedIV, privateKey);

    Sleep(500);

    // Establish an encrypted communication loop with the client
    bool keepCommunicating = true;
    while (keepCommunicating) {
        // Receive message from client
        char recvbuf[DEFAULT_BUFLEN];
        int recvbuflen = DEFAULT_BUFLEN;
        iResult = recv(host.ClientSocket, recvbuf, DEFAULT_BUFLEN, 0);
        if (iResult > 0) {
            string encodedMessage = recvbuf;
            string decryptedMessage;
            cout << "Received encrypted message: " << encodedMessage << "\n";
            DecryptAndDecodeMessage(encodedMessage, decryptedMessage, encryptedKey, encryptedIV);
        }
        else if (iResult == 0) {
            cout << "Connection closed\n";
            closesocket(host.ClientSocket);
            WSACleanup();
            exit(1);
        }
        else {
            cout << "recv failed with error: " << WSAGetLastError() << endl;
            closesocket(host.ClientSocket);
            WSACleanup();
            exit(1);
        }

        // Send encoded message to client
        string message;
        cout << "Enter a message to send to the client: ";
        getline(cin, message);
        string encodedMessage;
        EncryptAndEncodeMessage(message, encodedMessage, encryptedKey, encryptedIV);
        iResult = send(host.ClientSocket, encodedMessage.c_str(), encodedMessage.size(), 0);
        if (iResult == SOCKET_ERROR) {
            cout << "send failed with error: " << WSAGetLastError() << endl;
            closesocket(host.ClientSocket);
            WSACleanup();
            exit(1);
        }
        cout << "Bytes sent: " << iResult << endl;

        memset(recvbuf, 0, recvbuflen);

        Sleep(500);

        // Generate and send new RSA Public Key to client
        RSA::PrivateKey newPrivateKey;
        RSA::PublicKey newPublicKey;
        GenerateRSAKeyPair(newPrivateKey, newPublicKey);
        string newEncodedPrivateKey;
        string newEncodedPublicKey;
        SerializeAndEncodeToBase64(newPrivateKey, newPublicKey, newEncodedPrivateKey, newEncodedPublicKey);
        cout << "New encoded public key: " << newEncodedPublicKey << endl;
        iResult = send(host.ClientSocket, newEncodedPublicKey.c_str(), newEncodedPublicKey.size(), 0);
        if (iResult == SOCKET_ERROR) {
            cout << "send failed with error: " << WSAGetLastError() << endl;
            closesocket(host.ClientSocket);
            WSACleanup();
            exit(1);
        }
        cout << "Bytes sent: " << iResult << endl;

        Sleep(500);

        // Receive and decrypt new AES key and IV from client
        string newEncryptedKey;
        string newEncryptedIV;
        ReceiveAndDecryptAESKeyAndIV(host.ClientSocket, newEncryptedKey, newEncryptedIV, newPrivateKey);

    }

    // Clean up socket and shut down
    closesocket(host.ClientSocket);
    WSACleanup();
    return 0;
}