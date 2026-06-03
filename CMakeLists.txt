cmake_minimum_required(VERSION 3.20)

project(Detector LANGUAGES CXX)

# =========================
# C++ Standard
# =========================
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# =========================
# Default Build Type
# =========================
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# =========================
# Source Files
# =========================
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/src/*.cpp"
)

# =========================
# Executable
# =========================
add_executable(app ${SOURCES})

# =========================
# Include Directories
# =========================
target_include_directories(app PRIVATE
    "${CMAKE_SOURCE_DIR}/include"
)

# =========================
# Windows System Libraries
# =========================
target_link_libraries(app PRIVATE
    iphlpapi
    ws2_32
)

# =========================
# Static Runtime Linking
# =========================
if(MINGW)

    target_link_options(app PRIVATE
        -static
        -static-libgcc
        -static-libstdc++
    )

endif()

# =========================
# Compiler Warnings
# =========================
if(MSVC)

    target_compile_options(app PRIVATE
        /W4
    )

else()

    target_compile_options(app PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )

endif()