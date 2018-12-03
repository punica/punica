cmake_minimum_required (VERSION 2.8)

project (restserver)

option(CODE_COVERAGE "Enable code coverage" OFF)

if(DTLS)
    message(FATAL_ERROR "DTLS option is not supported." )
endif()

add_definitions(-D_GNU_SOURCE)

SET(WAKAAMA_SOURCES_DIR "third_party/wakaama/core")
SET(SHARED_INCLUDE_DIRS "third_party/wakaama/examples/shared")
include_directories (${WAKAAMA_SOURCES_DIR} ${SHARED_INCLUDE_DIRS})

execute_process(COMMAND git describe --abbrev=0 --tags OUTPUT_VARIABLE RESTSERVER_VERSION)

string(REPLACE "\n" "" RESTSERVER_VERSION ${RESTSERVER_VERSION})
string(REPLACE "v" "" RESTSERVER_VERSION ${RESTSERVER_VERSION})

set(RESTSERVER_FULL_VERSION "restserver ${RESTSERVER_VERSION}")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/version.h.in ${CMAKE_CURRENT_SOURCE_DIR}/src/version.h)

include(${CMAKE_CURRENT_LIST_DIR}/src/punica.cmake)

add_executable(${PROJECT_NAME} ${PUNICA_SOURCES} ${WAKAAMA_SOURCES} ${SHARED_SOURCES})
find_library(ULFIUS_LIB ulfius)
find_library(JANSSON_LIB jansson)
find_library(JWT_LIB jwt)
find_library(WAKAAMA_LIB wakaama)
target_compile_options(restserver PRIVATE "-Wall" "-pthread")
target_link_libraries(restserver pthread "${ULFIUS_LIB}" "${JANSSON_LIB}" "${JWT_LIB}" "${WAKAAMA_LIB}")


if(CODE_COVERAGE)
    target_compile_options(restserver PRIVATE "-coverage")
    target_link_libraries(restserver "gcov")
endif()

# Add WITH_LOGS to debug variant
set_property(TARGET ${PROJECT_NAME} APPEND PROPERTY COMPILE_DEFINITIONS $<$<CONFIG:Debug>:WITH_LOGS>)

SOURCE_GROUP(wakaama FILES ${WAKAAMA_SOURCES})
