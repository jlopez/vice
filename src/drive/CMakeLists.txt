add_subdirectory(iec)
# add_subdirectory(iec128dcr)
add_subdirectory(iecieee)
add_subdirectory(ieee)
add_subdirectory(tcbm)

include_directories(
        ../arch/sdl
        ../arch
        ..
        ../vdrive
        ../rtc
        ../lib/p64
        iec
        tcbm
        ieee
)

add_library(drive
        drive-check.c
        drive-cmdline-options.c
        drive-overflow.c
        drive-resources.c
        drive-snapshot.c
        drive-sound.c
        drive-writeprotect.c
        drive.c
        drivecpu.c
        drivecpu65c02.c
        driveimage.c
        drivemem.c
        driverom.c
        drivesync.c
        rotation.c
)
