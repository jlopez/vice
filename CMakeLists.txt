cmake_minimum_required(VERSION 3.13)
project(vice)

set(CMAKE_CXX_STANDARD 14)

set(warning_cxx      "-Wstrict-prototypes ${warning_cxx}")
set(warning_c        "-Wall -Winline")
set(optimization_c   "-O3 -mmacosx-version-min=10.9")
set(optimization_cxx "-fno-exceptions ${optimization_c}")
set(additional_flags "-mdynamic-no-pic -Wno-unused-parameter -Wno-sign-compare -Wmissing-prototypes -Werror=implicit-function-declaration -Wfatal-errors -Wshadow")
set(CMAKE_C_FLAGS    "${CMAKE_C_FLAGS} -g ${optimization_c} ${warnings_c} ${additional_flags}")
set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -g ${optimization_cxx} ${warnings_cxx} ${additional_flags}")
include_directories(/usr/local/include)
link_directories(/usr/local/lib)

add_subdirectory(src)
