cmake_minimum_required(VERSION 3.22)
project(test-scapy VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(WIN32)
    find_package(npcap REQUIRED)
    add_executable(sniffer sniffer.c)
    target_link_libraries(sniffer PRIVATE npcap::npcap ws2_32)
else()
    find_package(libpcap REQUIRED)
    add_executable(sniffer sniffer.c)
    target_link_libraries(sniffer PRIVATE libpcap::libpcap)
endif()

add_custom_target(run-sniffer
    COMMAND sniffer
    DEPENDS sniffer
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
)
