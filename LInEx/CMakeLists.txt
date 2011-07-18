project(LInEx)
cmake_minimum_required(VERSION 2.6)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/Modules)

find_package(PCAP REQUIRED)
include_directories(${PCAP_INCLUDE_DIR})

set(CMAKE_C_FLAGS "-Wall -Wstrict-aliasing=2 -fstrict-aliasing")

SUBDIRS(ipfixlolib)

ADD_EXECUTABLE(LInEx
	core.c
	config_file.c
	ipfix_data.c
	ipfix_templates.c
	list.c
	load_data.c
	transform_rules.c
	flows/flows.c
)


TARGET_LINK_LIBRARIES(LInEx
	ipfixlolib
	${PCAP_LIBRARIES}
)
