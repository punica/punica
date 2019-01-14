cmake_minimum_required (VERSION 3.5)

project (punica)

option(CODE_COVERAGE "Enable code coverage" OFF)
option(BUILD_STATIC "Build with static libraries" OFF)

if(DTLS)
    message(FATAL_ERROR "DTLS option is not supported." )
endif()

set(WAKAAMA_SOURCES_DIR "third_party/wakaama/core")
set(SHARED_INCLUDE_DIRS "third_party/wakaama/examples/shared")
include_directories (${WAKAAMA_SOURCES_DIR} ${SHARED_INCLUDE_DIRS} ${CMAKE_INSTALL_PREFIX}/include)

execute_process(COMMAND git describe --abbrev=0 --tags OUTPUT_VARIABLE PUNICA_VERSION)

string(REPLACE "\n" "" PUNICA_VERSION ${PUNICA_VERSION})
string(REPLACE "v" "" PUNICA_VERSION ${PUNICA_VERSION})

set(PUNICA_FULL_VERSION "${PROJECT_NAME} ${PUNICA_VERSION}")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/version.h.in ${CMAKE_CURRENT_SOURCE_DIR}/src/version.h)

include(${CMAKE_CURRENT_LIST_DIR}/src/punica.cmake)

if(BUILD_STATIC)
    message("WARNING: static builds are experimental!")
    set(CMAKE_FIND_LIBRARY_SUFFIXES
        ${CMAKE_STATIC_LIBRARY_SUFFIX}
        ${CMAKE_SHARED_LIBRARY_SUFFIX}
        ${CMAKE_SHARED_MODULE_SUFFIX})
endif()

add_executable(${PROJECT_NAME} ${PUNICA_SOURCES})

find_library(PTHREAD_LIB pthread)
find_library(GNUTLS_LIB gnutls)
find_library(MICROHTTPD_LIB microhttpd)
find_library(JANSSON_LIB jansson)
find_library(JWT_LIB jwt)
find_library(CURL_LIB curl)
find_library(ORCANIA_LIB orcania)
find_library(ULFIUS_LIB ulfius)
find_library(WAKAAMA_LIB wakaama)

target_compile_options(${PROJECT_NAME} PRIVATE "-Wall" "-pthread")

target_link_libraries(${PROJECT_NAME}
                      "${PTHREAD_LIB}"
                      "${GNUTLS_LIB}"
                      "${MICROHTTPD_LIB}"
                      "${JANSSON_LIB}"
                      "${JWT_LIB}"
                      "${CURL_LIB}"
                      "${ORCANIA_LIB}"
                      "${ULFIUS_LIB}"
                      "${WAKAAMA_LIB}"
                     )

if(CODE_COVERAGE)
    target_compile_options(${PROJECT_NAME} PRIVATE "-coverage")
    target_link_libraries(${PROJECT_NAME} "gcov")
endif()

