cmake_minimum_required(VERSION 3.22)
project(FuseFixerNativeSafetyTests LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

find_package(ICU REQUIRED COMPONENTS uc)

set(CPP_ROOT ${CMAKE_CURRENT_LIST_DIR}/../../app/src/main/cpp)
add_library(elf_parser_test STATIC
    ${CPP_ROOT}/elf_parser/elf_parser.cc
    ${CPP_ROOT}/elf_parser/xz-embedded/xz_crc32.c
    ${CPP_ROOT}/elf_parser/xz-embedded/xz_crc64.c
    ${CPP_ROOT}/elf_parser/xz-embedded/xz_dec_lzma2.c
    ${CPP_ROOT}/elf_parser/xz-embedded/xz_dec_stream.c
)
target_compile_definitions(elf_parser_test PRIVATE FUSEFIXER_ENABLE_TEST_API)
target_include_directories(elf_parser_test PRIVATE
    ${CPP_ROOT}/include
    ${CPP_ROOT}/elf_parser/include
    ${CPP_ROOT}/elf_parser/xz-embedded
)

add_library(utf8_utils_test STATIC ${CPP_ROOT}/utf8_utils.cpp)
target_include_directories(utf8_utils_test PUBLIC ${CPP_ROOT}/include)
target_link_libraries(utf8_utils_test PUBLIC ICU::uc)

add_executable(native_safety_tests native_safety_tests.cpp)
target_include_directories(native_safety_tests PRIVATE
    ${CPP_ROOT}/elf_parser/include
    ${CPP_ROOT}/include
)
target_compile_definitions(native_safety_tests PRIVATE FUSEFIXER_ENABLE_TEST_API)
target_link_libraries(native_safety_tests PRIVATE elf_parser_test utf8_utils_test ${CMAKE_DL_LIBS})
target_link_options(native_safety_tests PRIVATE -Wl,--hash-style=both)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    foreach(target elf_parser_test utf8_utils_test native_safety_tests)
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    endforeach()
    target_link_options(native_safety_tests PRIVATE -fsanitize=address,undefined)
endif()

enable_testing()
add_test(NAME native_safety_tests COMMAND native_safety_tests)
