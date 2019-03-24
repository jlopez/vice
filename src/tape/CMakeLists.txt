include_directories(
        ../arch
        ../arch/sdl
        ..
        .
)

add_library(tape
        t64.c
        tap.c
        tape-internal.c
        tape-snapshot.c
        tape.c
        tapeimage.c
)
