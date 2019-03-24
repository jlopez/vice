include_directories(
        ../arch
        ../arch/sdl
        ..
)

add_library(iodrv
        io-beos-access.c
        io-unix-access.c
        pci-beos-drv.c
        pci-unix-drv.c
)
