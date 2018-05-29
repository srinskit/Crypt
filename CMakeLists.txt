cmake_minimum_required(VERSION 3.10)
project(Crypt)

set(CMAKE_CXX_STANDARD 11)

add_executable(Crypt main.cpp Crypt.cpp Crypt.h)
target_link_libraries(Crypt mbedtls mbedcrypto mbedx509)