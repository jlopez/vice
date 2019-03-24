include_directories(
        ../arch/sdl
	../arch
	..
        ../rtc
        ../diag
)

add_library(tapeport
        cp-clockf83.c
        dtl-basic-dongle.c
        sense-dongle.c
        tape_diag_586220_harness.c
        tapecart.c
        tapelog.c
        tapeport.c
)
