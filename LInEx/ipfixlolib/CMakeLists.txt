#
# VERMONT build scripts for CMake
# Copyright (C) 2007 Christoph Sommer <christoph.sommer@informatik.uni-erlangen.de>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#


ADD_LIBRARY(ipfixlolib
	encoding.c
	ipfixlolib.c
	msg.c
	ipfix_names.c
)

IF(WITH_COMPRESSION)
	ADD_LIBRARY(deflate SHARED
		compression/deflate.c
	)
	TARGET_LINK_LIBRARIES(deflate z)

	ADD_LIBRARY(bzip2 SHARED
		compression/bzip2.c
	)
	TARGET_LINK_LIBRARIES(bzip2 bz2)

	# Optimize QuickLZ for best compression ratio
	ADD_DEFINITIONS(-DQLZ_COMPRESSION_LEVEL=2 -DQLZ_STREAMING_BUFFER=65536)
	ADD_LIBRARY(quicklz SHARED
		compression/quicklz.c
		compression/ext/quicklz.c
	)
ENDIF(WITH_COMPRESSION)
