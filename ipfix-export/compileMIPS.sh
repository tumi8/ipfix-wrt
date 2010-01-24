rm CMakeCache.txt
rm ipfixlolib/CMakeCache.txt
cmake -DCMAKE_C_COMPILER=/home/kami/opt/OpenWrt-SDK-brcm47xx-2.6-for-Linux-i686/staging_dir_mipsel/bin/mipsel-linux-uclibc-gcc -DCMAKE_CXX_COMPILER=/home/kami/opt/OpenWrt-SDK-brcm47xx-2.6-for-Linux-i686/staging_dir_mipsel/bin/mipsel-linux-uclibc-g++ .
make