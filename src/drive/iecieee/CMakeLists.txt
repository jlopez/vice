include_directories(
        ../../arch
        ../../arch/sdl
        ../..
        ..
        ../../lib/p64
)

add_library(driveiecieee
        iecieee.c
        via2d.c
)
