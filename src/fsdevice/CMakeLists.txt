include_directories(
        ../arch
        ../arch/sdl
        ..
        ../vdrive
        ../lib/p64
)

add_library(fsdevice
        fsdevice-close.c
        fsdevice-cmdline-options.c
        fsdevice-flush.c
        fsdevice-open.c
        fsdevice-read.c
        fsdevice-resources.c
        fsdevice-write.c
        fsdevice.c
)
