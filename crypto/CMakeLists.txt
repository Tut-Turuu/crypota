file(GLOB CRYPTO_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

add_library(crypto STATIC ${CRYPTO_SOURCES})

target_include_directories(crypto
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/inc
)

target_link_libraries(crypto PUBLIC filesys PRIVATE gmp gmpxx)