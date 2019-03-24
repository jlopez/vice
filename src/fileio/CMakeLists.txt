include_directories(
        ../arch
        ../arch/sdl
        ..
)

add_library(fileio
        cbmfile.c
        fileio.c
        p00.c
)
