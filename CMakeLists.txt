cmake_minimum_required(VERSION 3.20)


set(PROJECT_NAME practice)
project("${PROJECT_NAME}")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-fcoroutines)
endif()

# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=x86-64 -O2")
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fsanitize=undefined -g -O0")
# set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address -fsanitize=undefined")

include(FetchContent)
include(ExternalProject)

add_subdirectory(filesys)
add_subdirectory(crypto)
add_subdirectory(network)

find_library(GMP_LIBRARY NAMES gmp)
find_library(GMPXX_LIBRARY NAMES gmpxx)
find_path(GMP_INCLUDE_DIR NAMES gmp.h)

if(GMP_LIBRARY AND GMPXX_LIBRARY AND GMP_INCLUDE_DIR)
    message(STATUS "Found system GMP: ${GMP_LIBRARY}")
    message(STATUS "Found system GMPXX: ${GMPXX_LIBRARY}")
    
    add_library(GMP::GMP INTERFACE IMPORTED)
    target_link_libraries(GMP::GMP INTERFACE ${GMPXX_LIBRARY} ${GMP_LIBRARY})
    target_include_directories(GMP::GMP INTERFACE ${GMP_INCLUDE_DIR})
else()
    message(STATUS "GMP not found in system, will build from source...")
    
    ExternalProject_Add(gmp_external
        URL https://ftp.gnu.org/gnu/gmp/gmp-6.3.0.tar.xz
        URL_HASH SHA256=a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898
        PREFIX ${CMAKE_BINARY_DIR}/gmp
        CONFIGURE_COMMAND <SOURCE_DIR>/configure 
            --prefix=<INSTALL_DIR>
            --enable-cxx
            --disable-shared
            --enable-static
        BUILD_COMMAND make -j4
        INSTALL_COMMAND make install
        BUILD_IN_SOURCE 0
    )
    set(GMP_INSTALL_DIR ${CMAKE_BINARY_DIR}/gmp/src/gmp_external-install)
    
    add_library(GMP::GMP STATIC IMPORTED GLOBAL)
    set_target_properties(GMP::GMP PROPERTIES
        IMPORTED_LOCATION ${GMP_INSTALL_DIR}/lib/libgmpxx.a
        INTERFACE_LINK_LIBRARIES ${GMP_INSTALL_DIR}/lib/libgmp.a
        INTERFACE_INCLUDE_DIRECTORIES ${GMP_INSTALL_DIR}/include
    )
    add_dependencies(GMP::GMP gmp_external)
endif()

find_package(Boost QUIET COMPONENTS system)

if(Boost_FOUND)
    message(STATUS "Found system Boost: ${Boost_INCLUDE_DIRS}")
    add_library(BoostAsio::BoostAsio INTERFACE IMPORTED)
    target_link_libraries(BoostAsio::BoostAsio INTERFACE Boost::system)
    target_include_directories(BoostAsio::BoostAsio INTERFACE ${Boost_INCLUDE_DIRS})
else()
    message(STATUS "Boost not found in system, downloading header-only Boost.Asio...")

    FetchContent_Declare(
        boost_asio
        GIT_REPOSITORY https://github.com/boostorg/asio.git
        GIT_TAG boost-1.84.0
    )
    FetchContent_Declare(
        boost_system
        GIT_REPOSITORY https://github.com/boostorg/system.git
        GIT_TAG boost-1.84.0
    )
    FetchContent_Declare(
        boost_config
        GIT_REPOSITORY https://github.com/boostorg/config.git
        GIT_TAG boost-1.84.0
    )
    FetchContent_Declare(
        boost_assert
        GIT_REPOSITORY https://github.com/boostorg/assert.git
        GIT_TAG boost-1.84.0
    )
    FetchContent_Declare(
        boost_throw_exception
        GIT_REPOSITORY https://github.com/boostorg/throw_exception.git
        GIT_TAG boost-1.84.0
    )
    FetchContent_MakeAvailable(boost_asio boost_system boost_config boost_assert boost_throw_exception)
    
    add_library(BoostAsio::BoostAsio INTERFACE IMPORTED)
    target_include_directories(BoostAsio::BoostAsio INTERFACE
        ${boost_asio_SOURCE_DIR}/include
        ${boost_system_SOURCE_DIR}/include
        ${boost_config_SOURCE_DIR}/include
        ${boost_assert_SOURCE_DIR}/include
        ${boost_throw_exception_SOURCE_DIR}/include
    )
endif()


find_package(PkgConfig REQUIRED)

set(WEBVIEW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(WEBVIEW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(WEBVIEW_BUILD_SHARED OFF CACHE BOOL "" FORCE)

pkg_check_modules(WEBKIT2GTK webkit2gtk-4.1)
if(NOT WEBKIT2GTK_FOUND)
    pkg_check_modules(WEBKIT2GTK REQUIRED webkit2gtk-4.0)
endif()

pkg_check_modules(GTK3 REQUIRED gtk+-3.0)

FetchContent_Declare(
    webview
    GIT_REPOSITORY https://github.com/webview/webview.git
    GIT_TAG master
)
FetchContent_MakeAvailable(webview)

# add_executable(client_gui interface/main.cpp)
add_executable(client async_client.cpp)
add_executable(serv test2.cpp)
# add_executable("${PROJECT_NAME}" main.cpp)

# target_link_libraries(client_gui
#     GMP::GMP
#     BoostAsio::BoostAsio
#     pthread
#     filesys
#     crypto
#     network
#     webview::core
# )

target_link_libraries(client
    GMP::GMP
    BoostAsio::BoostAsio
    pthread
    filesys
    crypto
    network
)

target_link_libraries(serv
    GMP::GMP
    BoostAsio::BoostAsio
    pthread
    filesys
    crypto
    network
)

file(COPY ${CMAKE_SOURCE_DIR}/interface/src DESTINATION ${CMAKE_BINARY_DIR})
