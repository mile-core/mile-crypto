# Mile Crypto Library

Basic library for cryptographic primitives in MILE

## Requirements
1. c++11
1. cmake
1. boost multiprecision installed includes (>=1.66, exclude 1.68!)

## Build
    $ git clone https://github.com/mile-core/mile-crypto
    $ cd ./mile-crypto; mkdir build; cd ./build
    $ cmake ..; make -j4
    $ make test

## Boost updates (if it needs)
    $ wget https://dl.bintray.com/boostorg/release/1.67.0/source/boost_1_67_0.tar.gz
    $ tar -xzf boost_1_*
    $ cd boost_1_*
    $ ./bootstrap.sh --prefix=/usr
    $ ./b2 install --prefix=/usr --with=all -j4


## Tested
1. Centos7 (gcc v4.8.5)
1. OSX 10.13, XCode10

# Example

```cpp

    #include "mile_crypto.h"

    // Create seed from phrase    
    Seed seed("secret-phrase");

    
    Digest     digest;
    PublicKey  pk;
    PrivateKey pvk;
    Signature  signature;
    DigestCalculator calculator;

    // Create keys pair from seed
    CreateKeyPair(pvk, pk, seed);

    // Create signer from private key
    Signer    signer(pvk);

    // initialize digest calculator
    calculator.Initialize();
    calculator.Finalize(digest);
    signer.SignDigest(digest, signature);

    std::cout << "Seed      : " + seed.ToBase58CheckString()) << std::endl;
    std::cout << "Digest    : " + digest.ToBase58CheckString()) << std::endl;
    std::cout << "Signature : " + signature.ToBase58CheckString()) << std::endl;

    std::cout << signer.VerifySignature(digest,signature) << std::endl;
    std::cout << ("2GzK7Z1gisn3iqUHDu97PnhmeRqAwK5ZpLLZRWSr4MguQCzBce" == digest.ToBase58CheckString()) << std::endl;

```