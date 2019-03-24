include_directories(
        ../arch
        ../arch/sdl
        ..
)

add_library(sounddrv
        soundaiff.c
        sounddummy.c
        sounddump.c
        soundfs.c
        soundiff.c
        soundmovie.c
        soundvoc.c
        soundwav.c

        soundcoreaudio.c
        soundflac.c
        soundmp3.c
        soundsdl.c
        soundvorbis.c
        lamelib.c

        soundaiff.o
        sounddummy.o
        sounddump.o
        soundfs.o
        soundiff.o
        soundvoc.o
        soundwav.o
)
