cmake_minimum_required(VERSION 3.20)

# An independent consumer of the installed Priority Fabric package. It knows nothing about the
# source tree: it finds the package, links the exported target and uses the public API only.
project(PriorityFabricConsumer
    VERSION 1.0.0
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PriorityFabric 1.0 REQUIRED)

add_executable(pf_consumer main.cpp)
target_link_libraries(pf_consumer PRIVATE PriorityFabric::priorityfabric)

if(MSVC)
    target_compile_options(pf_consumer PRIVATE /W4 /WX /permissive- /utf-8 /Zc:__cplusplus)
else()
    target_compile_options(pf_consumer PRIVATE -Wall -Wextra -Werror)
endif()

enable_testing()
add_test(NAME consumer.round_trip COMMAND pf_consumer)
