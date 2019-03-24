include_directories(
        ../arch/sdl
        ../arch/unix/readline
        ..
        .
        ../drive
        ../imagecontents
        ../vdrive
        ../lib/p64
)

find_package(BISON)
find_package(FLEX)

bison_target(monparser mon_parse.y ${CMAKE_CURRENT_BINARY_DIR}/mon_parse.c)
flex_target(monscanner mon_lex.l ${CMAKE_CURRENT_BINARY_DIR}/mon_lex.c)
add_flex_bison_dependency(monscanner monparser)

add_library(monitor
        asm6502.c
        asm6502dtv.c
        asm65816.c
        asm6809.c
        asmR65C02.c
        asmz80.c
        mon_analysis.c
        mon_assemble6502.c
        mon_assemble65816.c
        mon_assemble6809.c
        mon_assembleR65C02.c
        mon_assemblez80.c
        mon_breakpoint.c
        mon_command.c
        mon_disassemble.c
        mon_drive.c
        mon_file.c
        ${FLEX_monscanner_OUTPUTS}
        mon_memmap.c
        mon_memory.c
        ${BISON_monparser_OUTPUTS}
        mon_register.c
        mon_register6502.c
        mon_register6502dtv.c
        mon_register65816.c
        mon_register6809.c
        mon_registerR65C02.c
        mon_registerz80.c
        mon_ui.c
        mon_util.c
        monitor.c
        monitor_network.c
)
