include_directories(
        ../arch
        ../arch/sdl
        ..
        .
)

add_library(rs232drv
        rs232.c
        rs232drv.c
        rs232net.c
        rsuser.c
)
