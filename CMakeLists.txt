cmake_minimum_required(VERSION 3.20)

project(PriorityFabric
    VERSION 1.0.0
    DESCRIPTION "Authoritative network priority classes, precedence, inheritance and policy-bound priority decisions"
    HOMEPAGE_URL "https://github.com/summonlabs/Priority-Fabric"
    LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(PRIORITY_FABRIC_IS_TOP_LEVEL ON)
else()
    set(PRIORITY_FABRIC_IS_TOP_LEVEL OFF)
endif()

option(PRIORITY_FABRIC_BUILD_SHARED "Build Priority Fabric as a shared library" OFF)
option(PRIORITY_FABRIC_BUILD_TESTS "Build the Priority Fabric test suites" ${PRIORITY_FABRIC_IS_TOP_LEVEL})
option(PRIORITY_FABRIC_BUILD_TOOLS "Build the pfctl, pf_node and pf_probe programs" ${PRIORITY_FABRIC_IS_TOP_LEVEL})
option(PRIORITY_FABRIC_BUILD_EXAMPLES "Build the Priority Fabric examples" ${PRIORITY_FABRIC_IS_TOP_LEVEL})
option(PRIORITY_FABRIC_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
option(PRIORITY_FABRIC_ENABLE_ASAN "Build with AddressSanitizer where the toolchain supports it" OFF)
option(PRIORITY_FABRIC_ENABLE_UBSAN "Build with UndefinedBehaviorSanitizer where the toolchain supports it" OFF)
option(PRIORITY_FABRIC_INSTALL "Generate install and package rules" ON)

if(PRIORITY_FABRIC_BUILD_SHARED)
    set(BUILD_SHARED_LIBS ON)
else()
    set(BUILD_SHARED_LIBS OFF)
endif()

if(NOT CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 20)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------------------
# Warning configuration
# ---------------------------------------------------------------------------------------

# Applied directly to every first-party target. Deliberately not an INTERFACE library:
# an exported interface target would leak into the installed package.
function(priority_fabric_apply_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE
            /W4 /permissive- /utf-8 /Zc:__cplusplus /Zc:preprocessor /EHsc /bigobj
            /w14242 /w14254 /w14263 /w14265 /w14287 /w14296 /w14311 /w14545 /w14546 /w14547
            /w14549 /w14555 /w14619 /w14640 /w14826 /w14905 /w14906 /w14928 /w15038)
        if(PRIORITY_FABRIC_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE /WX)
        endif()
        if(PRIORITY_FABRIC_ENABLE_ASAN)
            target_compile_options(${target} PRIVATE /fsanitize=address)
            target_link_options(${target} PRIVATE /fsanitize=address)
        endif()
    else()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wcast-qual
            -Wdouble-promotion -Wformat=2 -Wnull-dereference -Wnon-virtual-dtor -Wold-style-cast
            -Woverloaded-virtual -Wuseless-cast -Wzero-as-null-pointer-constant)
        if(PRIORITY_FABRIC_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
        if(PRIORITY_FABRIC_ENABLE_ASAN)
            target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
            target_link_options(${target} PRIVATE -fsanitize=address)
        endif()
        if(PRIORITY_FABRIC_ENABLE_UBSAN)
            target_compile_options(${target} PRIVATE -fsanitize=undefined -fno-sanitize-recover=all)
            target_link_options(${target} PRIVATE -fsanitize=undefined)
        endif()
    endif()
endfunction()

# ---------------------------------------------------------------------------------------
# The library
# ---------------------------------------------------------------------------------------

set(PRIORITY_FABRIC_SOURCES
    src/codec.cpp
    src/decision.cpp
    src/digest.cpp
    src/durability.cpp
    src/evaluate.cpp
    src/fsutil.cpp
    src/ident.cpp
    src/limits.cpp
    src/model.cpp
    src/model_codec.cpp
    src/runtime.cpp
    src/state.cpp
    src/status.cpp
    src/store.cpp
    src/text.cpp
    src/version.cpp
    src/net.cpp
    src/wire.cpp
    src/node.cpp
    src/client.cpp
)

set(PRIORITY_FABRIC_PUBLIC_HEADERS
    include/priority_fabric/checked.hpp
    include/priority_fabric/client.hpp
    include/priority_fabric/codec.hpp
    include/priority_fabric/decision.hpp
    include/priority_fabric/digest.hpp
    include/priority_fabric/durability.hpp
    include/priority_fabric/export.hpp
    include/priority_fabric/ident.hpp
    include/priority_fabric/limits.hpp
    include/priority_fabric/model.hpp
    include/priority_fabric/model_codec.hpp
    include/priority_fabric/node.hpp
    include/priority_fabric/runtime.hpp
    include/priority_fabric/status.hpp
    include/priority_fabric/text.hpp
    include/priority_fabric/version.hpp
    include/priority_fabric/wire.hpp
)

add_library(priorityfabric ${PRIORITY_FABRIC_SOURCES})
add_library(PriorityFabric::priorityfabric ALIAS priorityfabric)

target_include_directories(priorityfabric
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(priorityfabric PUBLIC Threads::Threads)
target_compile_features(priorityfabric PUBLIC cxx_std_20)
priority_fabric_apply_warnings(priorityfabric)

if(BUILD_SHARED_LIBS)
    target_compile_definitions(priorityfabric PUBLIC PRIORITY_FABRIC_SHARED)
endif()
target_compile_definitions(priorityfabric PRIVATE PRIORITY_FABRIC_BUILDING)

if(MSVC)
    # bcrypt: the operating system entropy source. ws2_32: the Winsock transport. Both are
    # part of the platform, and both are needed by a consumer that links the static archive.
    target_link_libraries(priorityfabric PUBLIC bcrypt ws2_32)
endif()

set_target_properties(priorityfabric PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    OUTPUT_NAME "priorityfabric"
    POSITION_INDEPENDENT_CODE ON
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${PRIORITY_FABRIC_SOURCES} ${PRIORITY_FABRIC_PUBLIC_HEADERS})

include(CTest)
enable_testing()

if(PRIORITY_FABRIC_BUILD_TOOLS)
    add_subdirectory(tools)
endif()

if(PRIORITY_FABRIC_BUILD_TESTS)
    add_subdirectory(tests)
endif()

if(PRIORITY_FABRIC_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# ---------------------------------------------------------------------------------------
# Install and package
# ---------------------------------------------------------------------------------------

if(PRIORITY_FABRIC_INSTALL)
    include(GNUInstallDirs)
    include(CMakePackageConfigHelpers)

    install(TARGETS priorityfabric
        EXPORT PriorityFabricTargets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

    install(FILES ${PRIORITY_FABRIC_PUBLIC_HEADERS}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/priority_fabric)

    install(EXPORT PriorityFabricTargets
        FILE PriorityFabricTargets.cmake
        NAMESPACE PriorityFabric::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PriorityFabric)

    configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/PriorityFabricConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/PriorityFabricConfig.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PriorityFabric)

    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/PriorityFabricConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
        ARCH_INDEPENDENT)

    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/PriorityFabricConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/PriorityFabricConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PriorityFabric)

    install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE
        DESTINATION ${CMAKE_INSTALL_DATADIR}/PriorityFabric)
endif()
