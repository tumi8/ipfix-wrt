project(LInEx)
cmake_minimum_required(VERSION 2.6)

set(CMAKE_C_FLAGS "-Wall -Wstrict-aliasing=2 -fstrict-aliasing -O0")
add_definitions(-DDEBUG -DSUPPORT_SCTP)
SUBDIRS(ipfixlolib)

ADD_EXECUTABLE(LInEx
	core.c
	config_file.c
	ipfix_data.c
	ipfix_templates.c
	event_loop.c
	list.c
	load_data.c
	transform_rules.c
	flows/flows.c
	flows/olsr.c
	flows/mantissa.c
	flows/topology_set.c
	flows/export.c
	flows/olsr_protocol.h
)


TARGET_LINK_LIBRARIES(LInEx
	ipfixlolib
)
