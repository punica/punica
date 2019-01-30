cmake_minimum_required (VERSION 3.5)

project (punica)

option(CODE_COVERAGE "Enable code coverage" OFF)

if(DTLS)
    message(FATAL_ERROR "DTLS option is not supported." )
endif()

set(THIRD_PARTY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party")

set(ULFIUS_CMAKE_MODULES_DIR "${THIRD_PARTY_DIR}/ulfius/cmake-modules")
set(WAKAAMA_SOURCES_DIR "${THIRD_PARTY_DIR}/wakaama/core")
set(SHARED_INCLUDE_DIRS "${THIRD_PARTY_DIR}/wakaama/examples/shared")
include_directories (${WAKAAMA_SOURCES_DIR} ${SHARED_INCLUDE_DIRS} ${CMAKE_INSTALL_PREFIX}/include)

execute_process(COMMAND git describe --abbrev=0 --tags OUTPUT_VARIABLE PUNICA_VERSION)

string(REPLACE "\n" "" PUNICA_VERSION ${PUNICA_VERSION})
string(REPLACE "v" "" PUNICA_VERSION ${PUNICA_VERSION})

set(PUNICA_FULL_VERSION "${PROJECT_NAME} ${PUNICA_VERSION}")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/version.h.in ${CMAKE_CURRENT_SOURCE_DIR}/src/version.h)

list(APPEND CMAKE_MODULE_PATH ${ULFIUS_CMAKE_MODULES_DIR})

include(${CMAKE_CURRENT_LIST_DIR}/src/punica.cmake)

add_executable(${PROJECT_NAME} ${PUNICA_SOURCES})

# Find SHARED libraries
set(CMAKE_FIND_LIBRARY_SUFFIXES
    ${CMAKE_SHARED_LIBRARY_SUFFIX}
    ${CMAKE_SHARED_MODULE_SUFFIX}
    ${CMAKE_STATIC_LIBRARY_SUFFIX}
    )

# Nettle and Hogweed comes together, it depends on gmp
find_library(GMP_LIBRARY gmp)
find_library(NETTLE_LIBRARY nettle)
find_library(HOGWEED_LIBRARY hogweed)
set(NETTLE_LIBRARIES ${HOGWEED_LIBRARY} ${NETTLE_LIBRARY} ${GMP_LIBRARY})

# GnuTLS depends on nettle, libtasn1, hogweed, z, unistring (p11-kit if not built manually),
# if find_package doesn't add those libraries, it must be done manually.
find_library(ASN1_LIBRARY tasn1)
find_library(P11-KIT_LIBRARY p11-kit)
find_library(Z_LIBRARY z)
find_package(GnuTLS REQUIRED)
set(GNUTLS_LIBRARIES ${GNUTLS_LIBRARIES} ${NETTLE_LIBRARIES} ${UNISTRING_LIBRARY} ${Z_LIBRARY} ${ASN1_LIBRARY} ${P11-KIT_LIBRARY} ${IDN2_LIBRARY})

find_package(OpenSSL REQUIRED)

# Find STATIC libraries
set(CMAKE_FIND_LIBRARY_SUFFIXES
    ${CMAKE_STATIC_LIBRARY_SUFFIX}
    ${CMAKE_SHARED_LIBRARY_SUFFIX}
    ${CMAKE_SHARED_MODULE_SUFFIX}
    )

# Find and link Threads package libraries (pthread on linux)
find_package(Threads REQUIRED)
# Inform about libraries linked to define Threads and its symbols
message("Threads: ${CMAKE_THREAD_LIBS_INIT}")
set(LIBRARIES ${LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

# Jansson
find_package(Jansson REQUIRED)
set(LIBRARIES ${LIBRARIES} ${JANSSON_LIBRARIES})

# curl depends on gnutls, (idn2, rtmp, ares, ldap if not built manually)
find_package(CURL REQUIRED)
set(CURL_LIBRARIES ${CURL_LIBRARIES} ${GNUTLS_LIBRARIES})

# gcrypt depends on gpg-error
find_library(GPG-ERROR_LIBRARY gpg-error)
find_library(GCRYPT_LIBRARY gcrypt)
set(GCRYPT_LIBRARIES ${GCRYPT_LIBRARY} ${GPG-ERROR_LIBRARY})

# MicroHTTPD depends on gnutls, gcrypt, pthread (libcurl if not built manually)
find_package(MHD REQUIRED)
set(MHD_LIBRARIES ${MHD_LIBRARIES} ${GNUTLS_LIBRARIES} ${CURL_LIBRARIES} ${GCRYPT_LIBRARIES}  ${CMAKE_THREAD_LIBS_INIT})

# Orcania depends on jansson
find_package(Orcania REQUIRED)
set(ORCANIA_LIBRARIES ${ORCANIA_LIBRARIES} ${ORCANIA_LIBRARIES} ${JANSSON_LIBRARIES})
find_library(ULFIUS_LIBRARY ulfius)

# Ulfius depends on liborcania, libcurl, jansson, libmicrohttpd > 0.9.51 (libyder if not built manually)
set(ULFIUS_LIBRARIES ${ULFIUS_LIBRARY} ${ORCANIA_LIBRARIES} ${MHD_LIBRARIES})
# Inform about libraries linked to define Ulfius and its symbols
message("Ulfius: ${ULFIUS_LIBRARIES}")
set(LIBRARIES ${LIBRARIES} ${ULFIUS_LIBRARIES})

# JWT_LIBRARY depends on jansson, openssl or gnutls >=3.6.0
# NOTE: cheks for gnutls v3.5.8, but all sybols are defined in v3.6.0 or higher
find_library(JWT_LIBRARY jwt)
set(JWT_LIBRARIES ${JWT_LIBRARY} ${OPENSSL_LIBRARIES} ${JANSSON_LIBRARIES})
# Inform about libraries linked to define JWT and its symbols
message("JWT: ${JWT_LIBRARIES}")
set(LIBRARIES ${LIBRARIES} ${JWT_LIBRARIES})

# WAKAAMA_LIBRARY
find_library(WAKAAMA_LIBRARY wakaama)
# Inform about libraries linked to define Wakaama and its symbols
message("Wakaama: ${WAKAAMA_LIBRARY}")
set(LIBRARIES ${LIBRARIES} ${WAKAAMA_LIBRARY})

message("ALL libraries: ${LIBRARIES}")
target_link_libraries(${PROJECT_NAME} ${LIBRARIES})

target_compile_options(${PROJECT_NAME} PRIVATE "-Wall")

if(CODE_COVERAGE)
    target_compile_options(${PROJECT_NAME} PRIVATE "-coverage")
    target_link_libraries(${PROJECT_NAME} "gcov")
endif()
