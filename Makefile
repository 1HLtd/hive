APACHE_DIR=/usr/local/apache
BUILD_DIR=$(APACHE_DIR)/build/
APXS=$(APACHE_DIR)/bin/apxs

all:
	sudo sed -i 's/\-g//' $(BUILD_DIR)/config_vars.mk; \
	$(APXS) -c mod_hive.c
	cp .libs/mod_hive.so ~

clean:
	sudo rm -rf .libs *.o *.lo *.so *.la *.a *.slo 

install:
	$(APXS) -ia -n hive mod_hive.so
