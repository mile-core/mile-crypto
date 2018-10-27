add_library(mile_crypto STATIC IMPORTED)


find_library(mile_crypto_LIBRARY_PATH mile_crypto HINTS "${CMAKE_CURRENT_LIST_DIR}/../../")
set_target_properties(mile_crypto PROPERTIES IMPORTED_LOCATION "${mile_crypto_LIBRARY_PATH}")

include_directories(
        "${mile_crypto_INCLUDE_PATH}"
)

message(STATUS "CMAKE_CURRENT_LIST_DIR "  ${CMAKE_CURRENT_LIST_DIR})
message(STATUS "CMAKE_INSTALL_PREFIX " ${CMAKE_INSTALL_PREFIX})
message(STATUS "mile_crypto_LIBRARY_PATH " ${mile_crypto_LIBRARY_PATH})
message(STATUS "mile_crypto_INCLUDE_PATH " ${mile_crypto_INCLUDE_PATH})
