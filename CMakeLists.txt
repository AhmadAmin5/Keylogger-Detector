cmake_minimum_required(VERSION 3.20)

project(Detector)

set(CMAKE_CXX_STANDARD 20)

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS
    "src/*.cpp"
)

add_executable(app ${SOURCES})

target_include_directories(app PRIVATE include)