cmake_minimum_required(VERSION 2.6)
SUBDIRS(ipfixlolib)
ADD_EXECUTABLE(example_code
	test_everything.cc
)

TARGET_LINK_LIBRARIES(example_code
	ipfixlolib
)
