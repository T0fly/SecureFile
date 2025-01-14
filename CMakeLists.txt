cmake_minimum_required(VERSION 3.30)
project(SecureFile)

set(CMAKE_CXX_STANDARD 20)

find_package(OpenSSL REQUIRED)

add_executable(SecureFile main.cpp)

target_link_libraries(SecureFile PRIVATE OpenSSL::SSL)
target_link_libraries(SecureFile PRIVATE OpenSSL::Crypto)