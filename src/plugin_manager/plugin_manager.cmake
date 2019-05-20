# Provides PLUGIN_MANAGER_SOURCES_DIR, PLUGIN_MANAGER_SOURCES variables.

include(${CMAKE_CURRENT_LIST_DIR}/rest_framework/rest_framework.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/lwm2m_framework/lwm2m_framework.cmake)

set(PLUGIN_MANAGER_SOURCES_DIR ${CMAKE_CURRENT_LIST_DIR})
set(PLUGIN_MANAGER_SOURCES
    ${PLUGIN_MANAGER_SOURCES_DIR}/basic_core.cpp
    ${PLUGIN_MANAGER_SOURCES_DIR}/basic_plugin_manager.cpp
    ${PLUGIN_MANAGER_SOURCES_DIR}/basic_plugin_wrapper.cpp
    ${REST_FRAMEWORK_SOURCES}
    ${LWM2M_FRAMEWORK_SOURCES}
    )
