#
# Copyright (C) 2006-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk

PKG_NAME:=restful
PKG_RELEASE:=1.0

define Package/restful
  DEPENDS:= +libevent2 +libiwinfo +libopenssl +libcurl
  SECTION:=utils
  CATEGORY:=Base system
  TITLE:=Support route restful api
endef

define Package/restful/description
 This package contains restful server and cgi
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/restful/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_DIR) $(1)/www/cgi-bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/server $(1)/sbin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cgi.cgi $(1)/www/cgi-bin
endef

$(eval $(call BuildPackage,restful))
