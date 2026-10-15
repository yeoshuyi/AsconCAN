ASCON_C  ?= thirdparty/ascon-c
ASCON_DIR := $(ASCON_C)/crypto_auth/asconmacv13
ASCON_KAT := $(ASCON_DIR)/LWC_MAC_KAT_128_128.txt

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
