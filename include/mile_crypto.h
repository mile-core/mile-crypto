#ifndef MILE_CRYPTO_H
#define MILE_CRYPTO_H

///
/// Mile hash functions and Ed25519 library primitives
///

#include <string>
#include <iostream>
#include <vector>

#include "mile_sha3.h"
#include "mile_types.h"
#include "mile_base58.h"


#define GCC_VERSION (__GNUC__ * 10000 \
                     + __GNUC_MINOR__ * 100 \
                     + __GNUC_PATCHLEVEL__)

#if !(GCC_VERSION > 70200 || __clang__)
#define __USE_MILECSA_FIXED_POINT_IMP__ 1
#endif

/**
 * Convert float to fixed point. It needs to calculate right signed digest of message contains number values.
 *
 * @param value
 * @param precision
 * @param output
 */
extern void float2FixedPoint(float value, int precision, std::string &output);

struct Hash : public Array<eHashSize> { };
struct Digest : public Array<eDigestSize> { };
struct PrivateKey : public Array<ePrivateKeySize> { };
struct PublicKey : public Array<ePublicKeySize> { };
struct Signature : public Array<eSignatureSize> { };

struct Seed : public Array<eSeedSize> {
public:
    /**
     * Create seed from secret phrase
     * @param phrase
     */
    Seed(const std::string &phrase);

    Seed():Array(){};
    Seed(const Seed &s):Array(s){}
};

/**
 * Create keys pair from seed object.
 *
 * @param privateKey
 * @param publicKey
 * @param seed
 */
void CreateKeyPair(PrivateKey& privateKey, PublicKey& publicKey, Seed& seed);

/**
 * Create random keys pair
 *
 * @param privateKey
 * @param publicKey
 */
void CreateKeyPair(PrivateKey& privateKey, PublicKey& publicKey);

/**
 * Restore public key from private key
 *
 * @param privateKey
 * @param publicKey
 */
void RestoreKeyPairFromPrivate(const PrivateKey& privateKey, PublicKey& publicKey);

/**
 * Digest hash calculator
 */
class DigestCalculator
{
public:
    DigestCalculator();

    /**
     * Initialize digest before updates
     */
    void Initialize();

    /**
     * Finalize calculations must be call at the end of digest processing.
     *
     * @param digest
     */
    void Finalize(Digest& digest);


    /**
     * Update digest from any string
     *
     * @param message
     */
    void Update(const std::vector<unsigned char>& message);

    /**
     * Update digest from any buffered message
     *
     * @tparam N
     * @param array
     */
    template<size_t N>
    void Update(const Array<N>& array)
    {
        sha3_Update(&m_ctx, array.Data.data(), array.Data.size());
    }

    /**
     * Update digest from boolean value
     *
     * @param value
     */
    void Update(bool value);

    /**
     * Update digest from symbol
     *
     * @param value
     */
    void Update(unsigned char value);

    /**
     *
     * @param value
     * @param littleEndian
     */
    void Update(unsigned short value, bool littleEndian = true);

    /**
     *
     * @param value
     * @param littleEndian
     */
    void Update(const uint64_t& value, bool littleEndian = true);

    /**
     *
     * @param value
     * @param littleEndian
     */
    void Update(unsigned int value, bool littleEndian = true);

    /**
     *
     * @param value
     * @param littleEndian
     */
    void Update(const uint256_t& value, bool littleEndian = true);

    /**
     * Update digest from string.
     * String data will be padded if size > string size
     *
     * @param s
     * @param size
     */
    void Update(const string& s, size_t size = 0);

private:
    sha3_context m_ctx;
};

/**
 * Signer
 */
class Signer
{
public:
    Signer();
    Signer(const Signer& signer);

    /**
     * Create signer from private key
     *
     * @param privateKey
     */
    Signer(const PrivateKey& privateKey);

    /**
     * Create verification signer
     *
     * @param privateKey
     */
    Signer(const PublicKey& publicKey);

    /**
     * Create Signer from keys pair
     *
     * @param privateKey
     * @param publicKey
     */
    Signer(const PrivateKey& privateKey, const PublicKey& publicKey);

    ~Signer();

    /**
     * Recreate signer with random keys pair
     */
    void GenerateRandomKeys();

    /**
     * Set new keys pair and recreate signer
     *
     * @param privateKey
     * @param publicKey
     */
    void Set(const PrivateKey& privateKey, const PublicKey& publicKey);

    /**
     * Public key getter
     * @return
     */
    const PublicKey& GetPublicKey() const { return m_publicKey; }

    /**
     * Sign message and return Signature object
     *
     * @param message
     * @param signature
     */
    void SignMessage(const std::vector<unsigned char>& message, Signature& signature) const;

    /**
     * Sign digest and return Signature object
     *
     * @param digest
     * @param signature
     */
    void SignDigest(const Digest& digest, Signature& signature) const;

    /**
     *
     * @param message
     * @param signature
     * @return
     */
    bool VerifySignature(const std::vector<unsigned char>& message, const Signature& signature) const;

    /**
     *
     * @param digest
     * @param signature
     * @return
     */
    bool VerifySignature(const Digest& digest, const Signature& signature) const;

    /**
     * Dump sign to stream object
     *
     * @param outputStream
     */
    void Dump(std::ostream& outputStream);


    Signer& operator= (const Signer& other);

private:
    PrivateKey m_privateKey;
    PublicKey  m_publicKey;
};

///
/// Utils
///

namespace std
{
    template<>
    struct hash<PublicKey>
    {
        size_t operator()(const PublicKey& that) const
        {
            std::size_t hash;
            std::memcpy(&hash, that.Data.data(), sizeof(std::size_t));
            return hash;
        }
    };
}

/**
 * Create string from var args
 *
 * @param format
 * @param ...
 * @return
 */
const std::string StringFormat(const char* format, ...);

/**
 * Create formated string error message with standard prefix
 *
 * @param format
 * @param ...
 * @return
 */
const std::string ErrorFormat(const char* format, ...);

#endif
