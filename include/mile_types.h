#ifndef MILECSA_CRYPTO_TYPES_H
#define MILECSA_CRYPTO_TYPES_H

#include <array>
#include <string>
#include <cstring>
#include <boost/multiprecision/cpp_int.hpp>
#include "mile_base58.h"

typedef boost::multiprecision::uint256_t uint256_t;

/**
 * Convert uint256 to decimals string
 * @param ui
 * @return
 */
std::string UInt256ToDecString(const uint256_t &ui);

/**
 * Convert uint256 to hex string
 * @param ui
 * @return
 */

std::string UInt256ToHexString(const uint256_t& ui);

/**
 * Convert vector to unsigned int 256 bits
 *
 * @param v
 * @param ui
 * @param littleEndian
 * @return
 */
bool VectorToUInt256(const vector<unsigned char>& v, uint256_t& ui, bool littleEndian = true);

/**
 * Convert unsigned int 256 bits to vector. Add padding with zeros if needed.
 * @param ui
 * @param v
 * @param littleEndian
 */
void UInt256ToVector(const uint256_t& ui, vector<unsigned char>& v, bool littleEndian = true);

/**
 * Convert string to uint256
 *
 * @param s
 * @param ui
 * @param hexString
 * @return
 */
bool StringToUInt256(const std::string& s, uint256_t& ui, bool hexString);

/**
 * Convert uint64 to decimals string
 *
 * @param ui
 * @return
 */
std::string UInt64ToDecString(const uint64_t& ui);
bool DecStringToUint(const std::string& decString, unsigned int& value);

/**
 * Convert string to uint64
 *
 * @param s
 * @param ui
 * @param hexString
 * @return
 */
bool StringToUInt64(const std::string& s, uint64_t& ui, bool hexString = true);

/**
 * Convert uint64 to vector of chars.
 *
 *  note: use export_bits and import_bits if newer version of boost will be used on CentOS
 *  (or use two implementations depending on boost version)
 *
 * @param ui
 * @param v
 * @param littleEndian
 */
void UInt64ToVector(const uint64_t& ui, vector<unsigned char>& v, bool littleEndian = true);

/**
 * Convert vector of chars to uint64
 *
 * @param v
 * @param ui
 * @param littleEndian
 * @return
 */
bool VectorToUInt64(const vector<unsigned char>& v, uint64_t& ui, bool littleEndian = true);

/**
 * Hash functions and Ed25519 library parameters
 */
enum ECrypto
{
    eDigestSize     = 32, // 256 bits
    eSeedSize       = 32, // 256 bits
    ePrivateKeySize = 64, // 512 bits
    ePublicKeySize  = 32, // 256 bits
    eSignatureSize  = 64,  // 512 bits
    eHashSize = 32  // 256 bits maybe
};

/**
 * Common buffer class base58 encode/decode interface
 *
 * @tparam N
 */
template<size_t N>
struct Array
{
    std::array<unsigned char, N> Data;
    //
    constexpr size_t Size() const { return Data.size(); }

    Array()
    {
        // Clear();
    }

    // copy constructor
    Array(const Array& other)
    {
        Data = other.Data;
    }

    // clear std::array
    void Clear()
    {
        Data.fill(0);
    }
    bool IsZero() const
    {
        for (size_t i = 0; i < N; i++)
        {
            if (Data[i] != 0)
            {
                 return false;
            }
        }
        return true;
    }
    // convert vector to binary std::array with const size
    bool Set(const vector<unsigned char>& data, std::string& errorDescription)
    {
        errorDescription = "";

        if (data.size() != N)
        {
            std::stringstream errorMessage;
            errorMessage << "bad data size: " << data.size() << " <> " << N;
            errorDescription = errorMessage.str();
            return false;
        }

        for (size_t i = 0; i < N; i++)
        {
            Data[i] = data[i];
        }

        return true;
    }
    // get data from vector and convert to binary std::array with const size
    bool Set(const vector<unsigned char>& data, size_t offset, std::string& errorDescription)
    {
        errorDescription = "";

        if ((offset + N) > data.size())
        {
            std::stringstream errorMessage;
            errorMessage << "bad data size or offset: (offset " << offset << " + array size " << N << ") > data size " << data.size();
            errorDescription = errorMessage.str();
            return false;
        }

        for (size_t i = 0; i < N; i++)
        {
            Data[i] = data[i + offset];
        }

        return true;
    }
    // convert hex std::string to binary array with const size
    bool SetHexString(const std::string& hexString, std::string& errorDescription)
    {
        errorDescription = "";

        if (hexString.empty())
        {
            errorDescription = "empty hex string";
            return false;
        }

        if (hexString.size() != N*2)
        {
            std::stringstream errorMessage;
            errorMessage << "bad hex string size: " << hexString.size() << " <> " << N*2;
            errorDescription = errorMessage.str();
            return false;
        }

        for (size_t i = 0; i < hexString.size(); i += 2)
        {
            std::string s = hexString.substr(i, 2);
            unsigned char value = 0;
            //
            if (!HexStringToUchar(s, value))
            {
                std::stringstream errorMessage;
                errorMessage << "bad " << i/2 << " hex symbol '" << s.c_str() << "'";
                errorDescription = errorMessage.str();
                return false;
            }
            Data[i >> 1] = value;
        }

        return true;
    }
    // convert base58check string to binary array with const size
    bool SetBase58CheckString(const std::string& base58CheckString, std::string& errorDescription)
    {
        return DecodeBase58Check(base58CheckString, Data, errorDescription);
    }
    // convert array data to hex std::string
    std::string ToHexString() const
    {
        return BinToHex(Data);
    }
    // convert array data to base58check std::string
    std::string ToBase58CheckString() const
    {
        return EncodeBase58Check(Data);
    }
    // append array contents to specified vector
    void AppendTo(vector<unsigned char>& v) const
    {
        v.insert(v.end(), Data.begin(), Data.end());
    }
    //
    Array<N>& operator= (const Array<N>& other)
    {
        Data = other.Data;
        return *this;
    }
};

template<size_t N>
bool operator== (const Array<N>& a, const Array<N>& b) { return a.Data == b.Data; }

template<size_t N>
bool operator!= (const Array<N>& a, const Array<N>& b) { return a.Data != b.Data; }

template<size_t N>
bool operator< (const Array<N>& a, const Array<N>& b) { return a.Data < b.Data; }

template<size_t N>
bool operator<= (const Array<N>& a, const Array<N>& b) { return a.Data <= b.Data; }

template<size_t N>
bool operator> (const Array<N>& a, const Array<N>& b) { return a.Data > b.Data; }

template<size_t N>
bool operator>= (const Array<N>& a, const Array<N>& b) { return a.Data >= b.Data; }

#endif // MILECS_CRYPTO_TYPES_H
