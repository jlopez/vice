add_definitions(-DVERSION=\"1.0-pre2\")

add_library(resid
        sid.cc
        voice.cc
        wave.cc
        envelope.cc
        filter.cc
        dac.cc
        extfilt.cc
        pot.cc
        version.cc
)
