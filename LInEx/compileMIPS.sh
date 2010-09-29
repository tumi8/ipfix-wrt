# Path to OpenWRT root directory
OPENWRT_ROOT=/home/muenz/openwrt/8.09
# Toolchain bin subdirectory
TOOLCHAIN_BIN=staging_dir/toolchain-mipsel_gcc3.4.6/bin
# uclibc gcc executable
CCOMPILER=mipsel-linux-uclibc-gcc
# uclibc g++ executable
CXXCOMPILER=mipsel-linux-uclibc-g++
rm CMakeCache.txt
cmake -DCMAKE_C_COMPILER=$OPENWRT_ROOT/$TOOLCHAIN_BIN/$CCOMPILER -DCMAKE_CXX_COMPILER=$OPENWRT_ROOT/$TOOLCHAIN_BIN/$CXXCOMPILER
make
