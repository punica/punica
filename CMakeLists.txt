cmake_minimum_required (VERSION 3.5)

project (punica)

option(CODE_COVERAGE "Enable code coverage" OFF)
option(BUILD_STATIC "Build with static libraries" OFF)

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

include(${CMAKE_CURRENT_LIST_DIR}/src/punica.cmake)

add_executable(${PROJECT_NAME} ${PUNICA_SOURCES})

if(BUILD_STATIC)
    message("WARNING: static builds are experimental!")
    set(CMAKE_FIND_LIBRARY_SUFFIXES
        ${CMAKE_STATIC_LIBRARY_SUFFIX}
        ${CMAKE_SHARED_LIBRARY_SUFFIX}
        ${CMAKE_SHARED_MODULE_SUFFIX})
endif()
message("Suffixes: ${CMAKE_FIND_LIBRARY_SUFFIXES}")

LIST(APPEND CMAKE_MODULE_PATH ${ULFIUS_CMAKE_MODULES_DIR})

message("${CMAKE_MODULE_PATH}")

# GnuTLS depends on nettle (libtasn1, p11-kit, hogweed if not built manually),
# find_package doesn't add those libraries, it must be done manually. 
find_library(GMP_LIBRARY gmp)
find_library(Z_LIBRARY z)
find_library(HOGWEED_LIBRARY hogweed)
find_library(NETTLE_LIBRARY nettle)
find_library(ASN1_LIBRARY tasn1)
find_library(UNISTRING_LIBRARY unistring)
find_library(GNUTLS-OPENSSL_LIBRARY gnutls-openssl)
find_package(GnuTLS REQUIRED)
set(GNUTLS_LIBRARIES ${GNUTLS-OPENSSL_LIBRARY} ${GNUTLS_LIBRARIES} ${HOGWEED_LIBRARY} ${NETTLE_LIBRARY} ${GMP_LIBRARY} ${ASN1_LIBRARY} ${UNISTRING_LIBRARY} ${Z_LIBRARY})

# CURL_LIBRARY depends on gnutls, libidn2
find_package(CURL REQUIRED)
set(CURL_LIBRARIES ${CURL_LIBRARIES} ${GNUTLS_LIBRARIES})

# MICROHTTPD_LIBRARY depends on gnutls, libgcrypt, pthread (libcurl, libidn2 if not built manually)
find_library(GCRYPT_LIBRARY gcrypt)
find_package(MHD REQUIRED)
set(MHD_LIBRARIES ${MHD_LIBRARIES} ${GNUTLS_LIBRARIES} ${CURL_LIBRARIES} ${GCRYPT_LIBRARY})

# ULFIUS_LIBRARY depends on liborcania, libcurl, jansson, libmicrohttpd > 0.9.51 (libyder if not built manually)
# ORCANIA_LIBARY depends on jansson
find_package(Jansson REQUIRED)
find_package(Orcania REQUIRED)
find_library(ULFIUS_LIBRARY ulfius)
set(ULFIUS_LIBRARIES ${ULFIUS_LIBRARY} ${ORCANIA_LIBRARIES} ${MHD_LIBRARIES} ${JANSSON_LIBRARIES})
# Inform about libraries linked to define Ulfius and its symbols
message("Ulfius: ${ULFIUS_LIBRARIES}")
set(LIBRARIES ${LIBRARIES} ${ULFIUS_LIBRARIES})

# "${JWT_LIB}" # depends on jansson, openssl (if gnutls v3.5.8 or higher not built manually)
find_library(JWT_LIBRARY jwt)
set(JWT_LIBRARIES ${JWT_LIBRARY} ${GNUTLS_LIBRARIES} ${JANSSON_LIBRARIES})
# Inform about libraries linked to define JWT and its symbols
message("JWT: ${JWT_LIBRARIES}")
set(LIBRARIES ${LIBRARIES} ${JWT_LIBRARIES})

# "${WAKAAMA_LIB}"
find_library(WAKAAMA_LIBRARY wakaama)
# Inform about libraries linked to define Wakaama and its symbols
message("Wakaama: ${WAKAAMA_LIBRARY}")
set(LIBRARIES ${LIBRARIES} ${WAKAAMA_LIBRARY})

find_package(Threads REQUIRED)
# Inform about libraries linked to define Threads (pthread on linux) and its symbols
message("Threads: ${CMAKE_THREAD_LIBS_INIT}")
set(LIBRARIES ${LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

message("ALL libraries: ${LIBRARIES}")
target_link_libraries(${PROJECT_NAME} ${LIBRARIES})

target_compile_options(${PROJECT_NAME} PRIVATE "-Wall" "-pthread")

if(CODE_COVERAGE)
    target_compile_options(${PROJECT_NAME} PRIVATE "-coverage")
    target_link_libraries(${PROJECT_NAME} "gcov")
endif()

