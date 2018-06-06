cmake_minimum_required(VERSION 3.10)
project(Crypt)

set(CMAKE_CXX_STANDARD 11)
add_library(Crypt SHARED Crypt.cpp)
target_link_libraries(Crypt mbedtls mbedcrypto mbedx509)
set_target_properties(Crypt PROPERTIES PUBLIC_HEADER "Crypt.h")
INSTALL(TARGETS Crypt
        LIBRARY DESTINATION lib
        PUBLIC_HEADER DESTINATION include
        )