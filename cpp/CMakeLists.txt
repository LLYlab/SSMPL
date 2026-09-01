cmake_minimum_required(VERSION 3.16)
project(ssmpl_cpp LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_library(ssmpl STATIC src/ssmpl.cpp)
target_include_directories(ssmpl PUBLIC src)
target_link_libraries(ssmpl PUBLIC OpenSSL::Crypto)

add_executable(ssmpl_cli src/ssmpl_cli.cpp)
target_link_libraries(ssmpl_cli PRIVATE ssmpl)

add_executable(test_ssmpl tests/test_ssmpl.cpp)
target_link_libraries(test_ssmpl PRIVATE ssmpl)

enable_testing()
add_test(NAME ssmpl_cpp COMMAND test_ssmpl)
