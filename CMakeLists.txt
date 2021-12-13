cmake_minimum_required(VERSION 3.21)
project(tap-protocols C)

set(CMAKE_C_STANDARD 11)

add_library(globals globals.c)

add_executable(tap-protocols main.c parser.c parser.h)