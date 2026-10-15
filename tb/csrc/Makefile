ASCON_C  ?= thirdparty/ascon-c
ASCON_DIR := $(ASCON_C)/crypto_auth/asconmacv13
ASCON_KAT := $(ASCON_DIR)/LWC_MAC_KAT_128_128.txt
VENV ?= $(abspath ../../.venv)
VLT_BIN  := $(firstword $(wildcard $(VENV)/lib/python3*/site-packages/verilator/bin))
CC        ?= cc
PKGCONFIG ?= pkg-config
VERILATOR ?= verilator

ifneq ($(MAKECMDGOALS),clean)
  ifeq ($(wildcard $(ASCON_DIR)/ref/prf.c),)
    $(error ascon-c not found: $(ASCON_DIR)/ref/prf.c is missing. \
      Run: git clone https://github.com/ascon/ascon-c $(ASCON_C)   (or set ASCON_C=<path>))
  endif
  ifeq ($(shell $(PKGCONFIG) --exists libcrypto 2>/dev/null && echo yes),yes)
    ifneq ($(shell $(PKGCONFIG) --atleast-version=3.0 libcrypto && echo yes),yes)
      $(error OpenSSL >= 3.0 is required (EVP_MAC API); pkg-config reports \
        libcrypto $(shell $(PKGCONFIG) --modversion libcrypto))
    endif
    SSL_CFLAGS := $(shell $(PKGCONFIG) --cflags libcrypto)
    SSL_LIBS   := $(shell $(PKGCONFIG) --libs libcrypto)
  else
    # No pkg-config data: fall back to the default search path. The
    # #error in ref_mac_core.c still rejects OpenSSL < 3.0 at compile time.
    $(warning pkg-config has no libcrypto entry; falling back to -lcrypto)
    SSL_CFLAGS :=
    SSL_LIBS   := -lcrypto
  endif
endif

MODE     ?= release
WARN     := -std=c11 -Wall -Wextra -Werror
CFLAGS_release := -O2
CFLAGS_debug   := -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined \
                  -fno-sanitize-recover=undefined
CFLAGS   := $(WARN) $(CFLAGS_$(MODE)) -fPIC $(SSL_CFLAGS) $(EXTRA_CFLAGS)
LDFLAGS_debug := -fsanitize=address,undefined
LDFLAGS  := $(LDFLAGS_$(MODE))
ASCON_INC := -I$(ASCON_DIR)/ref -I$(ASCON_C)/tests

MAC_SRC_DIR := mac

B := build/$(MODE)
CORE_OBJS := $(B)/ref_mac_core.o $(B)/ref_mac_ascon.o
HDRS := $(MAC_SRC_DIR)/ref_mac_core.h $(MAC_SRC_DIR)/ref_mac_ascon.h

.PHONY: kat_mac test clean FORCE

build/mode.stamp: FORCE
	@mkdir -p build
	@[ "$$(cat $@ 2>/dev/null)" = "$(MODE)" ] || echo "$(MODE)" > $@

$(B)/%.o: $(MAC_SRC_DIR)/%.c $(HDRS) Makefile | build/mode.stamp
	@mkdir -p $(B)
	$(CC) $(CFLAGS) -c $< -o $@

$(B)/ref_mac_ascon.o: $(MAC_SRC_DIR)/ref_mac_ascon.c $(HDRS) Makefile $(ASCON_DIR)/ref/prf.c
	@mkdir -p $(B)
	$(CC) $(CFLAGS) $(ASCON_INC) -c $< -o $@

kat_mac: $(B)/kat_test.o $(CORE_OBJS) build/mode.stamp
	$(CC) $(LDFLAGS) $(B)/kat_test.o $(CORE_OBJS) $(SSL_LIBS) -o $@

test: kat_mac 
	@./kat_mac $(ASCON_KAT) $(CAVP) > build/kat_test.log; rc=$$?; \
	  grep -E "^(FAIL|==|SUMMARY)" build/kat_test.log; exit $$rc
	
clean:
	rm -rf build
