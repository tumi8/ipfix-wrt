cmake_minimum_required(VERSION 2.6)
SUBDIRS(ipfixlolib)
ADD_EXECUTABLE(LInEx
	core.c
	config_file.c
	ipfix_data.c
	ipfix_templates.c
	list.c
	load_data.c
	transform_rules.c	
)


TARGET_LINK_LIBRARIES(LInEx
	ipfixlolib
)
