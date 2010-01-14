cmake_minimum_required(VERSION 2.6)
SUBDIRS(ipfixlolib)
ADD_EXECUTABLE(example_code
	list.c
	config_file.c
	core.c
	ipfix_data.c
	ipfix_templates.c
	load_data.c
	transform_rules.c
)

TARGET_LINK_LIBRARIES(example_code
	ipfixlolib
)
