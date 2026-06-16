file(GLOB CRYPTO_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

add_library(crypto STATIC ${CRYPTO_SOURCES})

target_include_directories(crypto
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/inc
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(crypto gmp gmpxx)