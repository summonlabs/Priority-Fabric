# Priority Fabric test suites. Every suite is registered with CTest as its own test so that a
# failure is attributed to the suite it came from.

set(PRIORITY_FABRIC_TEST_SOURCES
    main.cpp
    support.cpp
    test_identity.cpp
    test_precedence.cpp
    test_evaluation.cpp
    test_durability.cpp
    test_property.cpp
    test_adversarial.cpp
    test_concurrency.cpp
    test_restart.cpp
    test_transport.cpp
)

add_executable(pf_tests ${PRIORITY_FABRIC_TEST_SOURCES})
target_link_libraries(pf_tests PRIVATE PriorityFabric::priorityfabric)
target_include_directories(pf_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
priority_fabric_apply_warnings(pf_tests)
set_target_properties(pf_tests PROPERTIES OUTPUT_NAME "pf_tests")

set(PRIORITY_FABRIC_TEST_SUITES
    identity
    precedence
    evaluation
    durability
    property
    adversarial
    concurrency
    restart
    transport)

foreach(suite IN LISTS PRIORITY_FABRIC_TEST_SUITES)
    add_test(NAME pf.${suite} COMMAND pf_tests --suite ${suite})
endforeach()

# ---------------------------------------------------------------------------------------
# Real multiprocess suite: spawns pf_node and pf_probe as separate operating-system
# processes and drives them over the framed transport.
# ---------------------------------------------------------------------------------------

if(PRIORITY_FABRIC_BUILD_TOOLS)
    add_executable(pf_multiprocess_tests
        support.cpp
        multiprocess/main.cpp
        multiprocess/process.cpp
        multiprocess/test_multiprocess.cpp)
    target_link_libraries(pf_multiprocess_tests PRIVATE PriorityFabric::priorityfabric)
    target_include_directories(pf_multiprocess_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    priority_fabric_apply_warnings(pf_multiprocess_tests)
    target_compile_definitions(pf_multiprocess_tests PRIVATE
        PF_NODE_EXECUTABLE="$<TARGET_FILE:pf_node>"
        PF_PROBE_EXECUTABLE="$<TARGET_FILE:pf_probe>")
    add_test(NAME pf.multiprocess COMMAND pf_multiprocess_tests)

    add_executable(pf_bench bench/bench_priority.cpp)
    target_link_libraries(pf_bench PRIVATE PriorityFabric::priorityfabric)
    target_include_directories(pf_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    priority_fabric_apply_warnings(pf_bench)
    add_test(NAME pf.benchmark COMMAND pf_bench --quick)
endif()
