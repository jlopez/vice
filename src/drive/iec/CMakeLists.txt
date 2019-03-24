add_subdirectory(c64exp)

include_directories(
        ../../arch
        ../../arch/sdl
        ../..
        ../../drive
        ../../lib/p64
)

add_library(driveiec
        cia1571d.c
        cia1581d.c
        fdd.c
        glue1571.c
        iec-cmdline-options.c
        iec-resources.c
        iec.c
        iecrom.c
        memiec.c
        pc8477.c
        via1d1541.c
        via4000.c
        wd1770.c
)
