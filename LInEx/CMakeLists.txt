PROJECT(LInEx)
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

OPTION(WITH_SCTP "Compile ipfixlolib with SCTP support." ON)
IF(WITH_SCTP)
	ADD_DEFINITIONS(-DSUPPORT_SCTP)
ENDIF(WITH_SCTP)

OPTION(WITH_COMPRESSION "Build compression support into ipfixlolib" ON)
IF(WITH_COMPRESSION)
	ADD_DEFINITIONS(-DSUPPORT_COMPRESSION)
ENDIF(WITH_COMPRESSION)

OPTION(WITH_PACKET_MMAP "Enable PACKET_MMAP support in network sniffer" ON)
IF(WITH_PACKET_MMAP)
	ADD_DEFINITIONS(-DSUPPORT_PACKET_MMAP)
ENDIF(WITH_PACKET_MMAP)

SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wstrict-aliasing=2 -fstrict-aliasing -Os")

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
	flows/hello_set.c
	flows/node_set.c
	flows/export.c
	flows/olsr_protocol.h
)


TARGET_LINK_LIBRARIES(LInEx
	ipfixlolib
	dl
)
