include_directories(
        ../arch
        ../arch/sdl
        ..
        .
)

add_library(samplerdrv
        file_drv.c
        portaudio_drv.c
        sampler.c
)
