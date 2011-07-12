set(OPENWRT_SDK /path/to/openwrt/sdk)

# this one is important
SET(CMAKE_SYSTEM_NAME Linux)
#this one not so much
SET(CMAKE_SYSTEM_VERSION 1)

macro(READ_CONFIG VARIABLE_NAME VALUE)
	file(STRINGS "${OPENWRT_SDK}/.config" OUTPUT REGEX "${VARIABLE_NAME}=(.+)")
	string(REGEX REPLACE "${VARIABLE_NAME}=\"?([^\"]+)\"?" "\\1" ${ARGV1} "${OUTPUT}")
endmacro(READ_CONFIG)

read_config("CONFIG_ARCH" ARCH)
string(REGEX REPLACE "(i486|i586|i686)" "i386" ARCH "${ARCH}")
read_config("CONFIG_GCC_VERSION" GCCV)
read_config("CONFIG_LIBC" LIBC)
read_config("CONFIG_LIBC_VERSION" LIBCV)
read_config("CONFIG_EABI_SUPPORT" EABI_SUPPORT)
set(DIR_SUFFIX "_${LIBC}-${LIBCV}")
if (EABI_SUPPORT)
	set(DIR_SUFFIX "${DIR_SUFFIX}_eabi")
endif(EABI_SUPPORT)

set(STAGING_DIR "${OPENWRT_SDK}/staging_dir/target-${ARCH}${ARCH_SUFFIX}${DIR_SUFFIX}")
set(TOOLCHAIN_DIR "${OPENWRT_SDK}/staging_dir/toolchain-${ARCH}${ARCH_SUFFIX}_gcc-${GCCV}${DIR_SUFFIX}")

set(CCOMPILER "${ARCH}-openwrt-linux-gcc")
set(CXXCOMPILER "${ARCH}-openwrt-linux-g++")

link_directories(${TOOLCHAIN_DIR}/lib ${STAGING_DIR}/lib)

# Need to simulate default rpath for libs
# CMAKE_EXE_LINKER_FLAGS is override by the module CMakeCommonLanguageInclude.cmake 
# so the only way I found was to use this obscure variable :)
# Source: http://wikiri.upc.es/index.php/Installing_IRI_drivers_in_non_ROOT_locations
set(CMAKE_EXE_LINKER_FLAGS_INIT "-Wl,-rpath,${TOOLCHAIN_DIR}/lib")

# specify the cross compiler
SET(CMAKE_C_COMPILER   ${TOOLCHAIN_DIR}/usr/bin/${CCOMPILER})
SET(CMAKE_CXX_COMPILER ${TOOLCHAIN_DIR}/usr/bin/${CXXCOMPILER})

# where is the target environment 
SET(CMAKE_FIND_ROOT_PATH ${TOOLCHAIN_DIR} ${STAGING_DIR})

# search for programs in the build host directories
SET(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# for libraries and headers in the target directories
SET(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
SET(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
