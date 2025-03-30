include(FetchContent)

cmake_minimum_required(VERSION 3.31)
project(epicxp)

set(CMAKE_CXX_STANDARD 20)

add_library(epicxp SHARED library.cpp)

function(download NAME REPO TAG)
    FetchContent_Declare(
            ${NAME}
            GIT_REPOSITORY ${REPO}
            GIT_TAG ${TAG}
    )
    FetchContent_MakeAvailable(${NAME})
endfunction()

download(libhat https://github.com/BasedInc/libhat.git 82de2e6f19d3a5c0123d32ef6a5059034312df7b)
download(minhook https://github.com/TsudaKageyu/minhook.git f5485b8454544c2f034c78f8f127c1d03dea3636)

target_link_libraries(epicxp PRIVATE minhook libhat)

set_property(
        # any target that is compiled (has source files) likely needs to be here
        TARGET epicxp libhat minhook
        PROPERTY MSVC_RUNTIME_LIBRARY
        # Use /MT (statically-linked runtime library)
        MultiThreaded
)