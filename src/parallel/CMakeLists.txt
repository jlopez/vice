include_directories(
        ../arch
        ../arch/sdl
        ..
        ../drive
        ../lib/p64
)

add_library(parallel
        parallel-trap.c
        parallel.c
)
