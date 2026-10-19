cmake_minimum_required(VERSION 3.16)
project(ESurfingClient C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(PROGRAM_VERSION_MAJOR 2)
set(PROGRAM_VERSION_MINOR 0)
set(PROGRAM_VERSION_PATCH 0)
set(PROGRAM_VERSION_RELEASE 8)

set(PROGRAM_VERSION "${PROGRAM_VERSION_MAJOR}.${PROGRAM_VERSION_MINOR}.${PROGRAM_VERSION_PATCH}")
set(PROGRAM_FULL_VERSION "${PROGRAM_VERSION}-r${PROGRAM_VERSION_RELEASE}")

add_definitions(-DPROGRAM_VERSION="${PROGRAM_VERSION}")
add_definitions(-DPROGRAM_FULL_VERSION="${PROGRAM_FULL_VERSION}")

message(STATUS "Building version: ${PROGRAM_FULL_VERSION}")

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

if (WIN32)
    add_definitions(-DCURL_STATICLIB)

    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc")
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a .lib ${CMAKE_FIND_LIBRARY_SUFFIXES})
else ()
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")
endif ()

find_package(CURL REQUIRED)

add_executable(ESurfingClient
        third_party/7z/LzmaDec.c
        src/cipher/algo/aes_double_cbc.c
        src/cipher/algo/aes_double_ecb.c
        src/cipher/algo/des_ecb_six.c
        src/cipher/algo/desede_double_cbc.c
        src/cipher/algo/sm4_variant_cbc.c
        src/cipher/algo/sm4_variant_ecb.c
        src/cipher/algo/snow3g_variant.c
        src/cipher/algo/tea_triple_cbc.c
        src/cipher/algo/tea_triple_ecb.c
        src/cipher/algo/ios/ios_zsm.c
        src/cipher/algo/desede_ecb.c
        src/cipher/algo/mod_xtea_iv.c
        src/cipher/algo/sm4_cbc.c
        src/cipher/algo/sm4_ecb.c
        src/cipher/algo/zuc.c
        src/cipher/algo/mod_xtea_cbc_triple.c
        src/cipher/algo/des_ecb_six_keys.c
        src/cipher/algo/desede_cbc.c
        src/cipher/algo/mod_xtea.c
        src/cipher/algo/aes_ecb.c
        src/cipher/algo/aes_cbc.c
        src/cipher/algo/windows/win_zsm.c
        src/cipher/CipherFactory.c
        src/cipher/CipherUtils.c
        src/cipher/KeyData.c
        src/utils/sim/SimEvpAes.c
        src/utils/sim/SimEvpCipher.c
        src/utils/sim/SimEvpDes3.c
        src/utils/sim/SimEvpMd5.c
        src/utils/Utils.c
        src/NetClient.c
        src/AlgoFinder.c
        Main.c
)

target_include_directories(ESurfingClient PRIVATE
        ${CMAKE_SOURCE_DIR}/inc
        ${CMAKE_SOURCE_DIR}/third_party
)

target_link_libraries(ESurfingClient PRIVATE
        CURL::libcurl
)

if (WIN32)
    target_link_libraries(ESurfingClient PRIVATE
            ws2_32
            wldap32
            winmm
            crypt32
            normaliz
            secur32
            bcrypt
            iphlpapi
    )
endif ()

target_compile_options(ESurfingClient PRIVATE -Os)

if (WIN32)
    set_target_properties(ESurfingClient PROPERTIES LINK_FLAGS "-Wl,--strip-all")
endif ()

install(TARGETS ESurfingClient RUNTIME DESTINATION bin)
