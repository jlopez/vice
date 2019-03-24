include_directories(
    ../arch/sdl
    ../arch
    ..
    ../lib/p64
)

add_library(vdrive
        vdrive-bam.c
        vdrive-command.c
        vdrive-dir.c
        vdrive-iec.c
        vdrive-internal.c
        vdrive-rel.c
        vdrive-snapshot.c
        vdrive.c
)
