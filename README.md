When / if I ever get around to developing a system, or preferably even a GUI to just input information, for now you must have built and set up Crypto++ 8.9.0 in order to properly compile this of course. As for the compiler itself, I use g++ (GCC) 13.2.0 that I got from MinGW, and adding it to my PATH as well and all that of course, so I could just use the command wherever. https://github.com/skeeto/w64devkit/releases/download/v1.21.0/w64devkit-1.21.0.zip

![image](https://github.com/pearuarmasj/p2p-encrypted-messaging/assets/60179057/4f3d1353-70b3-427f-bbbd-e2c1a05f5e89)


And the specific command I used to compile these cpp files into an exe were ```g++ -o Hybridclient2.exe Hybridclient2.cpp -lws2_32 -lcryptopp``` after cd'ing into the directory of the cpp source file of course. And to make it so that you don't need to spam the incldue / library directories fully, I added the directory of my built Crypto++ library and its include / lib folder into my INCLUDE and LIB system variables respectively.

![image](https://github.com/pearuarmasj/p2p-encrypted-messaging/assets/60179057/ca17daa1-d10b-406d-bb9b-753e7a6e0a53)
![image](https://github.com/pearuarmasj/p2p-encrypted-messaging/assets/60179057/c67c7f1d-becb-4f9b-b4f0-4a19a4bc81e2)

These were also present under my user variables above, but I haven't touched or added them myself, I presume this is related to building Crypto++, and in vscode, changing the properties and other settings / jsons of the C/C++ extension to also include the above. As for building Crypto++ itself, I used Visual Studio 2022 Professional.

---

## Security Architecture

This application now implements **hybrid asymmetric encryption** using TWO industry-standard cryptographic systems:

### Dual Asymmetric Encryption Standards

1. **RSA-4096 with OAEP Padding**
   - 4096-bit key size for strong security (~152-bit security level)
   - OAEP (Optimal Asymmetric Encryption Padding) with SHA-256
   - Used to encrypt random seed for session key derivation

2. **ECDH P-521 Curve**
   - P-521 (NIST secp521r1) elliptic curve
   - ~256-bit equivalent security level
   - Used for Diffie-Hellman key agreement

### Hybrid Key Derivation

Session keys are derived by **combining both RSA and ECDH** using HKDF-SHA256:
- RSA encrypts a random seed
- ECDH performs key agreement
- Both secrets are combined using HKDF (HMAC-based Key Derivation Function)
- Result: AES-256 session key protected by both cryptosystems

### Security Benefits

- **Defense-in-Depth**: Both RSA and ECDH must be compromised to break encryption
- **Forward Secrecy**: Ephemeral ECDH keys generated per session
- **Post-Quantum Readiness**: Hybrid approach provides migration path
- **Industry Standard**: Uses well-vetted Crypto++ library implementations
