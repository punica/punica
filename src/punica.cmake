# Provides PUNICA_SOURCES, PUNICA_SOURCES_DIR variables
# and sets 'LWM2M_SERVER_MODE' flag

include(${CMAKE_CURRENT_LIST_DIR}/rest/rest.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/utils/utils.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/plugin_manager/plugin_manager.cmake)

set(PUNICA_SOURCES_DIR ${CMAKE_CURRENT_LIST_DIR})

set(PUNICA_SOURCES
    ${PUNICA_SOURCES}
    ${PUNICA_SOURCES_DIR}/punica.c
    ${PUNICA_SOURCES_DIR}/linked_list.c
    ${PUNICA_SOURCES_DIR}/logging.c
    ${PUNICA_SOURCES_DIR}/settings.c
    ${PUNICA_SOURCES_DIR}/security.c
    ${PUNICA_SOURCES_DIR}/database.c
    ${PUNICA_SOURCES_DIR}/udp_connection_api.c
    ${PUNICA_SOURCES_DIR}/dtls_connection_api.c
    )

set(PUNICA_SOURCES
    ${PUNICA_SOURCES}
    ${REST_SOURCES}
    ${PLUGIN_MANAGER_SOURCES}
    ${UTILS_SOURCES}
    )

add_definitions(-DLWM2M_SERVER_MODE)
