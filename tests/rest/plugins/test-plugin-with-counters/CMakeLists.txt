cmake_minimum_required(VERSION 3.5)

set(CMAKE_CXX_STANDARD 11)

set(PROJECT_NAME test_plugin_with_counters)
project (${PROJECT_NAME})
set(CMAKE_BUILD_TYPE Release)

set(PUNICA_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../)
set(TEST_PLUGIN_SOURCES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(TEST_PLUGIN_SOURCES
    ${TEST_PLUGIN_SOURCES_DIR}/test_plugin_with_counters.cpp
    ${TEST_PLUGIN_SOURCES_DIR}/counter.cpp
)

include_directories(${PUNICA_ROOT_DIR}/include)

add_library(${PROJECT_NAME} SHARED ${TEST_PLUGIN_SOURCES})

target_compile_options(${PROJECT_NAME} PRIVATE "-Wall" "-O" "-g3")
