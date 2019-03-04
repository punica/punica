# Provides REST_FRAMEWORK_SOURCES_DIR and REST_FRAMEWORK_SOURCES variables.

set(REST_FRAMEWORK_SOURCES_DIR ${CMAKE_CURRENT_LIST_DIR})
set(REST_FRAMEWORK_SOURCES
    ${REST_FRAMEWORK_SOURCES_DIR}/ulfius_request.cpp
    ${REST_FRAMEWORK_SOURCES_DIR}/ulfius_response.cpp
    ${REST_FRAMEWORK_SOURCES_DIR}/ulfius_rest_framework.cpp
    )
