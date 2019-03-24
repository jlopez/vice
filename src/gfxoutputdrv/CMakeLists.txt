include_directories(
        ..
        ../sounddrv
        /usr/local/Cellar/ffmpeg/4.1.2/include
        ../arch/sdl
        ../arch
)

add_library(gfxoutputdrv
        bmpdrv.c
        doodledrv.c
        gfxoutput.c
        godotdrv.c
        iffdrv.c
        koaladrv.c
        nativedrv.c
        pcxdrv.c
        ppmdrv.c
        ppmdrv.h

        ffmpegdrv.c
        ffmpeglib.c
        gifdrv.c
        jpegdrv.c
        pngdrv.c
        #quicktimedrv.c
)
