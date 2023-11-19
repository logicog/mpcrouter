MPCROUTER_VERSION = 0.2
BUILDDIR = ./build
DEBBUILD_DIR = $(BUILDDIR)/mpcrouter-$(MPCROUTER_VERSION)
INSTALL_DIR = /usr/share/mpcrouter
LAN_IP = 192.168.2.1

deb-pkg:
	test -d $(BUILDDIR) || mkdir $(BUILDDIR)
	test -d $(DEBBUILD_DIR) || mkdir $(DEBBUILD_DIR)
	cp -rp views $(DEBBUILD_DIR)
	cp -rp public $(DEBBUILD_DIR)
	cp -rp debian $(DEBBUILD_DIR)
	cp -rp scripts $(DEBBUILD_DIR)
	cp mpcrouter.rb puma.rb config.ru nftables_rw.rb dnsmasq_rw.rb $(DEBBUILD_DIR)
	( \
	cd $(DEBBUILD_DIR); \
	debuild  --no-tgz-check -us -uc \
	)

	cd 

install:
	cp scripts/mpcrouter.service /etc/systemd/system
	chmod +x /etc/systemd/system/mpcrouter.service
	cp scripts/mpcrouter /etc/default/
	echo "Creating random SESSION_SECRET"
	ruby -e 'require "securerandom"; puts "SESSION_SECRET=#{SecureRandom.hex(64)}\n"' >> /etc/default/mpcrouter
	test -d $(INSTALL_DIR) || mkdir -p $(INSTALL_DIR)
	cp -r views $(INSTALL_DIR)/views
	cp -r public $(INSTALL_DIR)/public
	test -d $(INSTALL_DIR)/local-certs || mkdir -p $(INSTALL_DIR)/local-certs
	mkcert -install
	mkcert -cert-file $(INSTALL_DIR)/local-certs/localhost.pem -key-file  $(INSTALL_DIR)/local-certs/localhost-key.pem localhost $(LAN_IP) ::1
	
