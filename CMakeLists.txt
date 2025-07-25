cmake_minimum_required(VERSION 3.16)  # 3.31 is very new; 3.16+ is widely supported

project(valloc C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(valloc SHARED valloc/mm/mm.c
        valloc/mm/mm.h)