cmake_minimum_required(VERSION 3.10)
project(netfilter-test LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(netfilter-test
        main.cpp
        structure.h
        ip.h)

target_link_libraries(netfilter-test netfilter_queue)
