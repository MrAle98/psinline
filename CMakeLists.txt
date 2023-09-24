cmake_minimum_required(VERSION 3.26)
project(psinline C)

# set compiler settings
set( CMAKE_C_STANDARD 11 )
set(CMAKE_BUILD_TYPE Debug)
set( CMAKE_C_COMPILER x86_64-w64-mingw32-gcc )

add_executable(psinline main.c
        badger_exports.h
        HwBpExceptions.h
        HwBpEngine.h
        HwBpExceptions.c
        utils.h
        HwBpEngine.c
        common.h
        Clr.h
        psinline.h
        psinline.c
        Native.h
        global.c)

#add_executable(psinline main.c)

#add_custom_target(mytest COMMAND make -C ${mytest_SOURCE_DIR}
#        CLION_EXE_DIR=${PROJECT_BINARY_DIR})

#add_executable(psinline main.c
#        )