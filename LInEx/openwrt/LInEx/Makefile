# 
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
#
# Copyright (C) 2008 Frank Cervenka
#
# This is free software, licensed under the GNU General Public License v2.
#
# Copyright (C) 2011 Philip Lorenz
#
# This is free software, licensed under the GNU General Public License v2.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=LInEx
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=sctp zlib libbz2
include $(INCLUDE_DIR)/package.mk

define Package/LInEx
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=LInEx
	DEPENDS:=
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	rm -f $(PKG_BUILD_DIR)/CMakeCache.txt
	rm -fR $(PKG_BUILD_DIR)/CMakeFiles
	rm -f $(PKG_BUILD_DIR)/Makefile
	rm -f $(PKG_BUILD_DIR)/cmake_install.cmake
	rm -f $(PKG_BUILD_DIR)/progress.make
endef

define Build/Configure
	IN_OPENWRT=1 \
	AR="$(TOOLCHAIN_DIR)/usr/bin/$(TARGET_CROSS)ar" \
	AS="$(TOOLCHAIN_DIR)/usr/bin/$(TARGET_CC) -c $(TARGET_CFLAGS)" \
	LD="$(TOOLCHAIN_DIR)/usr/bin/$(TARGET_CROSS)ld" \
	NM="$(TOOLCHAIN_DIR)/usr/bin/$(TARGET_CROSS)nm" \
	CC="$(TOOLCHAIN_DIR)/usr/bin/$(TARGET_CC)" \
	GCC="$(TOOLCHAIN_DIR)/usr/bin/$(TARGET_CC)" \
	CXX="$(TOOLCHAIN_DIR)/usr/bin/$(TARGET_CROSS)g++" \
	RANLIB="$(TOOLCHAIN_DIR)/usr/bin/$(TARGET_CROSS)ranlib" \
	STRIP="$(TOOLCHAIN_DIR)/usr/bin/$(TARGET_CROSS)strip" \
	OBJCOPY="$(TOOLCHAIN_DIR)/usr/bin/$(TARGET_CROSS)objcopy" \
	OBJDUMP="$(TOOLCHAIN_DIR)/usr/bin/$(TARGET_CROSS)objdump" \
	cmake -DCMAKE_C_FLAGS="$(TARGET_CPPFLAGS)" -DCMAKE_SHARED_LINKER_FLAGS="$(TARGET_LDFLAGS)" $(PKG_BUILD_DIR)/CMakeLists.txt
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) VERBOSE=1
	$(STRIP) $(PKG_BUILD_DIR)/LInEx
endef

define Package/LInEx/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/LInEx $(1)/usr/bin/
endef

$(eval $(call BuildPackage,LInEx))

