cmake_minimum_required(VERSION 3.20)


set(PROJECT_NAME practice)
project("${PROJECT_NAME}")


set(CMAKE_CXX_STANDART 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDART_REQUIRED TRUE)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


add_subdirectory(filesys)
add_subdirectory(crypto)
add_subdirectory(network)

add_executable("${PROJECT_NAME}" test1.cpp)
# add_executable("${PROJECT_NAME}" main.cpp)


target_link_libraries("${PROJECT_NAME}" filesys crypto network)




