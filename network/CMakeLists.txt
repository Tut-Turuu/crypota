file(GLOB NETWORK_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

add_library(network STATIC ${NETWORK_SOURCES})


target_include_directories(network
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/inc
)

target_link_libraries(network
    crypto
)