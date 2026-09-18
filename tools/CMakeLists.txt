add_executable(pfctl pfctl.cpp)
target_link_libraries(pfctl PRIVATE PriorityFabric::priorityfabric)
priority_fabric_apply_warnings(pfctl)

add_executable(pf_node pf_node.cpp)
target_link_libraries(pf_node PRIVATE PriorityFabric::priorityfabric)
priority_fabric_apply_warnings(pf_node)

add_executable(pf_probe pf_probe.cpp)
target_link_libraries(pf_probe PRIVATE PriorityFabric::priorityfabric)
priority_fabric_apply_warnings(pf_probe)
