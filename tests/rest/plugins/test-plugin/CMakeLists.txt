cmake_minimum_required(VERSION 3.0)

project (test_plugin)
set(CMAKE_BUILD_TYPE Release)

set(TEST_PLUGIN_SOURCES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_library(test_plugin SHARED ${TEST_PLUGIN_SOURCES_DIR}/test_plugin.cpp)
