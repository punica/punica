cmake_minimum_required(VERSION 3.0)

project (plugin_without_api)
set(CMAKE_BUILD_TYPE Release)

set(PLUGIN_WITHOUT_API_SOURCES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_library(plugin_without_api SHARED ${PLUGIN_WITHOUT_API_SOURCES_DIR}/plugin_without_api.cpp)
