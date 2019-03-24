include_directories(
        ../arch/sdl
        ../arch
        ..
)

add_library(rtc
        bq4830y.c
        ds12c887.c
        ds1202_1302.c
        ds1216e.c
        ds1307.c
        ds1602.c
        pcf8583.c
        rtc.c
        rtc-58321a.c
        rtc-72421.c
)
