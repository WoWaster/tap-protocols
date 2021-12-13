cmake_minimum_required(VERSION 3.21)
project(tap-protocols C)

set(CMAKE_C_STANDARD 11)

add_library(globals globals.c)
add_library(utils utils.c)
target_link_libraries(utils globals)
add_library(arp protocols/arp/arp.c)
target_link_libraries(arp globals utils)
add_library(dhcp protocols/ipv4/udp/dhcp/dhcp.c)
target_link_libraries(dhcp globals utils)

add_executable(tap-protocols main.c parser.c parser.h)
target_link_libraries(tap-protocols arp)