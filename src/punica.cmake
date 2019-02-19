# Provides PUNICA_SOURCES, PUNICA_SOURCES_DIR variables
# and sets 'LWM2M_SERVER_MODE' flag

include(${CMAKE_CURRENT_LIST_DIR}/rest/rest.cmake)

set(PUNICA_SOURCES ${PUNICA_SOURCES} ${REST_SOURCES})

set(PUNICA_SOURCES_DIR ${CMAKE_CURRENT_LIST_DIR})

set(PUNICA_SOURCES
    ${PUNICA_SOURCES}
    ${PUNICA_SOURCES_DIR}/punica_main.c
    ${PUNICA_SOURCES_DIR}/linked_list.c
    ${PUNICA_SOURCES_DIR}/logging.c
    ${PUNICA_SOURCES_DIR}/settings.c
    ${PUNICA_SOURCES_DIR}/security.c
    ${PUNICA_SOURCES_DIR}/database.c
    )

add_definitions(-DLWM2M_SERVER_MODE)
