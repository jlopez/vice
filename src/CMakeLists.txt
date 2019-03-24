add_subdirectory(resid)
#add_subdirectory(resid-dtv))
add_subdirectory(samplerdrv)
add_subdirectory(joyport)
add_subdirectory(sounddrv)
add_subdirectory(mididrv)
add_subdirectory(socketdrv)
add_subdirectory(hwsiddrv)
add_subdirectory(iodrv)
add_subdirectory(drive)
add_subdirectory(vdrive)
add_subdirectory(fsdevice)
add_subdirectory(diskimage)
add_subdirectory(iecbus)
add_subdirectory(serial)
add_subdirectory(parallel)
add_subdirectory(tape)
add_subdirectory(imagecontents)
add_subdirectory(fileio)
add_subdirectory(video)
add_subdirectory(raster)
add_subdirectory(vicii)
#add_subdirectory(viciisc)
#add_subdirectory(viciivsid)
#add_subdirectory(vdc)
#add_subdirectory(crtc)
add_subdirectory(gfxoutputdrv)
add_subdirectory(printerdrv)
add_subdirectory(rs232drv)
add_subdirectory(sid)
add_subdirectory(monitor)
add_subdirectory(core)
add_subdirectory(rtc)
add_subdirectory(userport)
add_subdirectory(tapeport)
add_subdirectory(diag)
add_subdirectory(c64)
#add_subdirectory(scpu64)
#add_subdirectory(c64dtv)
#add_subdirectory(c128)
#add_subdirectory(vic20)
#add_subdirectory(pet)
#add_subdirectory(plus4)
#add_subdirectory(cbm2)
add_subdirectory(arch)
add_subdirectory(lib)
add_subdirectory(hvsc)

include_directories(
        arch/sdl
        arch
        .
        arch/unix/readline
        c64
        drive
        monitor
        plus4
        vic20
        vdrive
        diskimage
        imagecontents
        diag
        userport
        lib/p64
        joyport
        rtc
        tapeport
        tape
        socketdrv
        hvsc
)

set(base_sources
        alarm.c
        attach.c
        autostart.c
        autostart-prg.c
        cbmdos.c
        cbmimage.c
        charset.c
        clipboard.c
        clkguard.c
        cmdline.c
        color.c
        crc32.c
        datasette.c
        debug.c
        dma.c
        embedded.c
        event.c
        findpath.c
        fliplist.c
        gcr.c
        info.c
        init.c
        initcmdline.c
        interrupt.c
        ioutil.c
        kbdbuf.c
        keyboard.c
        lib.c
        libm_math.c
        log.c
        machine-bus.c
        machine.c
        main.c
        network.c
        opencbmlib.c
        palette.c
        ram.c
        rawfile.c
        rawnet.c
        resources.c
        romset.c
        screenshot.c
        snapshot.c
        socket.c
        sound.c
        sysfile.c
        traps.c
        util.c
        vicefeatures.c
        vsync.c
        zfile.c
        zipcode.c
)

set(midi_sources midi.c)

add_executable(x64 ${base_sources} ${midi_sources})

target_link_libraries(x64
        -lFLAC -lvorbisenc -lvorbisfile -lvorbis -logg -lm
        -L/usr/local/lib -lSDL2 "-framework CoreServices"
        -lvorbisfile -logg -lvorbis -lvorbisenc -lFLAC
        "-framework CoreMidi" "-framework CoreServices"
        -lportaudio -lmpg123

        "-framework CoreAudio"
        "-framework AudioToolbox"
        "-framework AudioUnit"
        -ljpeg
        -lgif
        -lpng
        -lz

        -lreadline

        arch
        archdep
        c64
        c64cart
        c64cartsystem
        c64commoncart
        diag
        drive
        driveiec
        driveiecieee
        driveiecc64exp
        driveieee
        drivetcbm
        hvsc
        iecbus
        imagecontents
        monitor
        p64
        parallel
        raster
        resid
        rtc
        sid
        tapeport
        userport
        vdrive
        vicii
        video

        core
        diskimage
        fileio
        fsdevice
        gfxoutputdrv
        hwsiddrv
        iodrv
        joyport
        mididrv
        printerdrv
        rs232drv
        samplerdrv
        serial
        socketdrv
        sounddrv
        tape
)
