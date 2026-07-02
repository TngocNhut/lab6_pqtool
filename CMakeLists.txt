cmake_minimum_required(VERSION 3.20)

project(pqtool LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(pqtool
    src/main.cpp
    src/file_utils.cpp
    src/pq_crypto.cpp
)

target_include_directories(pqtool PRIVATE include)

target_link_libraries(pqtool PRIVATE OpenSSL::Crypto)

if (MSVC)
    target_compile_options(pqtool PRIVATE /W4)
else()
    target_compile_options(pqtool PRIVATE -Wall -Wextra -Wpedantic)
endif()
