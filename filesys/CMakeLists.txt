file(GLOB FILESYS_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

add_library(filesys STATIC ${FILESYS_SOURCES})

target_include_directories(filesys
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/inc
)


target_link_libraries(filesys crypto)