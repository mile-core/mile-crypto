
set (MILE_TEST_LIB mile_crypto_test)

set (BOOST_COMPONENTS
        unit_test_framework
        )

include_directories(
        ./
        ../include
)

find_package (Boost REQUIRED COMPONENTS ${BOOST_COMPONENTS})

add_subdirectory(initial)
add_subdirectory(digest_calculator)
add_subdirectory(signer_test)
enable_testing ()
