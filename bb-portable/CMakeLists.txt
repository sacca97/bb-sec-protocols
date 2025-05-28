cmake_minimum_required(VERSION 3.12)

set(CMAKE_C_COMPILER gcc)

project(bb-lib C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


find_package(PkgConfig REQUIRED)
pkg_check_modules(BLUEZ REQUIRED bluez)

include_directories(${BLUEZ_INCLUDE_DIRS})

# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")


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
add_executable(central central.c)
add_executable(peripheral peripheral.c)


target_link_libraries(tests bb-lib)
target_link_libraries(central bb-lib)
target_link_libraries(peripheral bb-lib)
target_link_libraries(central ${BLUEZ_LIBRARIES})
target_link_libraries(peripheral ${BLUEZ_LIBRARIES})



add_custom_target(run_tests ALL
    COMMAND $<TARGET_FILE:tests>
    DEPENDS tests # Ensure 'tests' executable is built before trying to run it
    COMMENT "Running unit tests"
)
