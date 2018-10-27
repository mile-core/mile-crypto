//
// Created by mile developer on 27/10/2018.
//

#define BOOST_TEST_MODULE signer

#include "mile_crypto.h"
#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_CASE( SignerVerify )
{
    Seed seed("secret-phrase");

    Digest     digest;
    PublicKey  pk;
    PrivateKey pvk;
    Signature  signature;
    DigestCalculator calculator;

    CreateKeyPair(pvk, pk, seed);

    Signer    signer(pvk);

    calculator.Initialize();
    calculator.Finalize(digest);
    signer.SignDigest(digest, signature);

    BOOST_TEST_MESSAGE("Seed      : " + seed.ToBase58CheckString());
    BOOST_TEST_MESSAGE("Digest    : " + digest.ToBase58CheckString());
    BOOST_TEST_MESSAGE("Signature : " + signature.ToBase58CheckString());

    BOOST_CHECK_EQUAL(true, signer.VerifySignature(digest,signature));
    BOOST_CHECK_EQUAL("2GzK7Z1gisn3iqUHDu97PnhmeRqAwK5ZpLLZRWSr4MguQCzBce",digest.ToBase58CheckString());

    Signer    verificator(pk);

    BOOST_CHECK_EQUAL(true, verificator.VerifySignature(digest,signature));

    // new pair
    CreateKeyPair(pvk, pk);

    Signer    false_verificator(pk);
    BOOST_CHECK_EQUAL(false, false_verificator.VerifySignature(digest,signature));

}
