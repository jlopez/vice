include_directories(
        ../arch
        ../arch/sdl
        ..
        ../joyport
)

add_library(raster
        raster-cache.c
        raster-canvas.c
        raster-changes.c
        raster-cmdline-options.c
        raster-line-changes-sprite.c
        raster-line-changes.c
        raster-line.c
        raster-modes.c
        raster-resources.c
        raster-sprite.c
        raster-sprite-status.c
        raster-sprite-cache.c
        raster.c
)
