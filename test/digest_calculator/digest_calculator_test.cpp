//
// Created by mile developer on 27/10/2018.
//

#define BOOST_TEST_MODULE digest_calculator

#include "mile_crypto.h"
#include <boost/test/included/unit_test.hpp>

BOOST_AUTO_TEST_CASE( FixedPoint )
{
    Digest digest;

    DigestCalculator calculator;

    calculator.Initialize();

    calculator.Finalize(digest);

    BOOST_TEST_MESSAGE("Digest : " + digest.ToBase58CheckString());

    BOOST_CHECK_EQUAL("2GzK7Z1gisn3iqUHDu97PnhmeRqAwK5ZpLLZRWSr4MguQCzBce",digest.ToBase58CheckString());
}

