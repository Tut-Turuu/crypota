add_executable(network
    src/client.cpp
)


target_link_libraries(network
    crypto
    asio
)


target_include_directories(network_app
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/inc
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

