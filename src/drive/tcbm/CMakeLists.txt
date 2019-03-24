include_directories(
        ../../arch
        ../../arch/sdl
        ../..
        ..
        ../../lib/p64
)

add_library(drivetcbm
        glue1551.c
        mem1551.c
        tcbm-cmdline-options.c
        tcbm-resources.c
        tcbm.c
        tcbmrom.c
        tpid.c
)
