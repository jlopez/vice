include_directories(
        ../arch/sdl
        ../arch
        ..
        ../vdrive
        ../lib/p64
)

add_library(imagecontents
        diskcontents-block.c
        diskcontents-iec.c
        diskcontents.c
        imagecontents.c
        tapecontents.c
)
