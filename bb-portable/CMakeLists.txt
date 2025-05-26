cmake_minimum_required(VERSION 3.12)

set(CMAKE_C_COMPILER gcc)

project(bb-lib C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin") 
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib") 



set(BB_LIB_SOURCES
    bb-lib/src/bbstate.c
    bb-lib/src/crypto.c
    bb-lib/src/crypto/blake2b.c
    bb-lib/src/crypto/chachapoly.c
    bb-lib/src/crypto/curve25519.c
    # bb-lib/src/crypto/ascon/*.c
)

add_library(
    bb-lib
    SHARED
    ${BB_LIB_SOURCES}
)

target_include_directories(bb-lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/bb-lib/include)

add_executable(tests tests.c)

target_link_libraries(tests PRIVATE bb-lib)

add_custom_target(run_tests ALL
    COMMAND $<TARGET_FILE:tests>
    DEPENDS tests # Ensure 'tests' executable is built before trying to run it
    COMMENT "Running unit tests"
)
