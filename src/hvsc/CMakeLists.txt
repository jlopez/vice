include_directories(
        ../arch
        ../arch/sdl
        ..
)

add_library(hvsc
        base.c
        bugs.c
        main.c
        psid.c
        sldb.c
        stil.c
)
