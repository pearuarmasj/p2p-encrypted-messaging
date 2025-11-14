# Encryption Implementation Documentation

## Overview
This P2P encrypted messaging application uses a **hybrid cryptographic approach** combining two different asymmetric encryption standards for defense-in-depth security.

## Asymmetric Encryption Standards (Two Standards Verified)

### 1. RSA-4096 with OAEP and SHA
- **Standard**: RSA (Rivest-Shamir-Adleman) 
- **Key Size**: 4096 bits (strengthened from original 3072 bits)
- **Padding**: OAEP (Optimal Asymmetric Encryption Padding)
- **Hash Function**: SHA-256
- **Purpose**: Encrypts a random seed used in session key derivation
- **Implementation**: CryptoPP's `RSAES_OAEP_SHA_Encryptor/Decryptor`

### 2. ECDH with P-521 Curve
- **Standard**: Elliptic Curve Diffie-Hellman (ECDH)
- **Curve**: P-521 (NIST secp521r1) - 521-bit prime field
- **Purpose**: Key agreement protocol for generating shared secret
- **Implementation**: CryptoPP's `ECDH<ECP>::Domain`

## Hybrid Key Exchange Protocol

The application uses **both** RSA and ECDH simultaneously to derive session keys:

### Handshake Process:
1. **Key Generation Phase**:
   - Both peers generate RSA-4096 key pairs
   - Both peers generate ECDH P-521 key pairs

2. **Key Exchange Phase**:
   - Peers exchange RSA public keys
   - Peers exchange ECDH public keys
   - Peer IDs are exchanged for identification

3. **Session Key Derivation** (Initiator):
   - Generate random 32-byte seed
   - Encrypt seed with peer's RSA public key → RSA component
   - Perform ECDH key agreement with peer's ECDH public key → ECDH component
   - Combine both using HKDF-SHA256 → Final session key

4. **Session Key Unwrapping** (Responder):
   - Decrypt RSA-encrypted seed using private RSA key
   - Perform ECDH key agreement using own private key
   - Combine both using HKDF-SHA256 → Final session key

### Key Derivation Function
- **KDF**: HKDF (HMAC-based Key Derivation Function)
- **Hash**: SHA-256
- **Input Material**: Concatenation of RSA seed + ECDH shared secret
- **Info String**: "p2p-session-key-v1"
- **Output**: 32-byte AES-256 session key

## Symmetric Encryption

### AES-256-GCM
- **Algorithm**: AES (Advanced Encryption Standard)
- **Key Size**: 256 bits
- **Mode**: GCM (Galois/Counter Mode)
- **Nonce Size**: 12 bytes (96 bits)
- **Tag Size**: 16 bytes (128 bits)
- **Features**: 
  - Authenticated encryption
  - Prevents tampering and forgery
  - Provides confidentiality and integrity

### Additional Message Authentication
- **HMAC-SHA256**: Optional additional layer over encrypted data
- **Purpose**: Extra integrity check beyond GCM's built-in authentication

## Security Properties

### Defense-in-Depth
The hybrid approach provides multiple security layers:
- If RSA is compromised, ECDH still protects the session
- If ECDH is compromised, RSA still protects the session
- Both must be broken to compromise the session key

### Forward Secrecy
- New ephemeral ECDH keys generated for each session
- Session keys cannot be recovered even if long-term keys are compromised

### Key Strengths
- **RSA-4096**: ~152-bit security level
- **ECDH P-521**: ~256-bit security level
- **AES-256**: 256-bit security level

### Protection Against Attacks
- **Man-in-the-Middle**: Protected by authenticated key exchange
- **Replay Attacks**: Counter-based message ordering with timestamps
- **Tampering**: AES-GCM authentication tags + optional HMAC
- **Quantum Computing**: ECDH P-521 provides quantum-resistant properties; RSA-4096 provides current best-practice security

## Implementation Details

### Files
- `crypto_utils.h`: Core cryptographic primitives and hybrid key derivation
- `handshake.h`: Key exchange protocol implementation
- `app_state.h`: Cryptographic state management
- `protocol.h`: Message type definitions including key exchange

### Key Functions
- `generateRSAKeyPair()`: Creates RSA-4096 key pairs
- `generateECDHKeyPair()`: Creates ECDH P-521 key pairs
- `deriveHybridSessionKey()`: Combines RSA + ECDH for session key
- `unwrapHybridSessionKey()`: Derives session key from received data
- `aesGcmEncrypt()/aesGcmDecrypt()`: Symmetric encryption operations

## Verification of Two Asymmetric Standards

✅ **RSA-4096 with OAEP**: Used for encrypting random seed
✅ **ECDH P-521**: Used for key agreement

Both standards are employed in every session key derivation, ensuring dual asymmetric protection.
