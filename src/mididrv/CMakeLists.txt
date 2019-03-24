include_directories(
        ../arch
        ../arch/sdl
        ..
        .
)

add_library(mididrv
        midi-osx-drv.c
        midi-unix-drv.c
        midi-win32-drv.c
)
