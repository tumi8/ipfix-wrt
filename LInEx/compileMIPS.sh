# Path to OpenWRT root directory
OPENWRT_ROOT=/home/muenz/openwrt/8.09
# Toolchain bin subdirectory
TOOLCHAIN_BIN=staging_dir/toolchain-mipsel_gcc3.4.6/bin
# uclibc gcc crosscompiler
CCOMPILER=mipsel-linux-uclibc-gcc
rm CMakeCache.txt
cmake -DCMAKE_C_COMPILER=$OPENWRT_ROOT/$TOOLCHAIN_BIN/$CCOMPILER 
make
