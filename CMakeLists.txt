cmake_minimum_required(VERSION 3.16)

project(DISASSEMBLER
VERSION 0.1.0
LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(disassembler
src/main.cpp
src/pe/pe_image.cpp
)

target_include_directories(disassembler
PRIVATE
${PROJECT_SOURCE_DIR}/include
${PROJECT_SOURCE_DIR}/include/pe
)

if(MSVC)
target_compile_options(disassembler PRIVATE /W4 /permissive-)
else()
target_compile_options(disassembler PRIVATE -Wall -Wextra -Wpedantic)
endif()
