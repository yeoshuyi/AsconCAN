# SV Testbench Run Script
#
# make sim ALG=ascon
# make sim ALG=aes SUITE=kat
# make regress
# make kat-fetch

ALG ?= ascon
SUITE ?= all
SEED ?= 1
N_RAND ?= 1000
AEAD_EN ?= 1
GHASH_D ?= 4
PLUSARGS ?=

ALG_ID_ascon := 1
ALG_ID_aes := 0
ALG_ID := $(ALG_ID_$(ALG))
ifeq ($(ALG_ID),)
	$(error Invalid ALG)
endif

TB_DIR := $(abspath .)
ROOT := $(abspath ..)
SV_DIR := $(TB_DIR)/sv
KAT_DIR := $(SV_DIR)/kat
ASCON_C := $(TB_DIR)/csrc/thirdparty/ascon-c
DPI_DIR := $(TB_DIR)/csrc/build/release
DPI_LIB := $(DPI_DIR)/libref_dpi.so
BUILD := $(TB_DIR)/sim_build/$(ALG)

KATS := +KAT_ASCON_AEAD=$(ASCON_C)/crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt \
        +KAT_ASCON_MAC=$(ASCON_C)/crypto_auth/asconmacv13/LWC_MAC_KAT_128_128.txt \
        +KAT_GCM_SPEC=$(KAT_DIR)/aes_gcm_spec.txt \
        +KAT_CMAC_RFC=$(KAT_DIR)/aes_cmac_rfc4493.txt \
        +KAT_GCM_ENC=$(KAT_DIR)/nist/gcmEncryptExtIV128.rsp \
        +KAT_GCM_DEC=$(KAT_DIR)/nist/gcmDecrypt128.rsp \
        +KAT_CMAC_GEN=$(KAT_DIR)/nist/CMACGenAES128.rsp \
        +KAT_CMAC_VER=$(KAT_DIR)/nist/CMACVerAES128.rsp

ALL_ARGS := +SUITE=$(SUITE) +SEED=$(SEED) +N_RAND=$(N_RAND) \
            +TIMING_CSV=$(BUILD)/timing.csv $(KATS) $(PLUSARGS)
XSIM_ARGS := $(foreach a,$(ALL_ARGS),-testplusarg $(patsubst +%,%,$(a)))

SRCS := $(addprefix $(ROOT)/,$(shell sed -e 's/\#.*//' $(SV_DIR)/tb.f))
DEPS := $(SRCS) $(wildcard $(SV_DIR)/env/*.svh) $(SV_DIR)/tb.f

NIST_URL := https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac
NIST_RSP := gcmEncryptExtIV128.rsp gcmDecrypt128.rsp CMACGenAES128.rsp CMACVerAES128.rsp

.PHONY: sim elab regress dpi kat-fetch clean

dpi:
	$(MAKE) -C csrc dpi

$(BUILD)/xvlog.done: $(DEPS)
	@mkdir -p $(BUILD)
	cd $(BUILD) && xvlog -sv -i $(SV_DIR)/env $(SRCS) --log xvlog.log > /dev/null \
		|| { grep -E "ERROR|WARNING" $(BUILD)/xvlog.log; exit 1; }
	@touch $@

# Snapshot depends on the generics, so it is always re-elaborated
elab: dpi $(BUILD)/xvlog.done
	cd $(BUILD) && xelab tb_top -s tb_snap -timescale 1ns/1ps \
		-generic_top "ALG=$(ALG_ID)" -generic_top "AEAD_EN=$(AEAD_EN)" \
		-generic_top "GHASH_D=$(GHASH_D)" \
		-sv_root $(DPI_DIR) -sv_lib libref_dpi --log xelab.log > /dev/null \
		|| { grep -E "ERROR|WARNING" $(BUILD)/xelab.log; exit 1; }

sim: elab
	cd $(BUILD) && xsim tb_snap -R $(XSIM_ARGS) --log xsim.log > /dev/null; true
	@sed -n '/==== CAN XL/,$$p' $(BUILD)/xsim.log | grep -v "^INFO: \[" || true
	@grep -q "^TEST PASSED" $(BUILD)/xsim.log

regress:
	$(MAKE) sim ALG=ascon
	$(MAKE) sim ALG=aes

kat-fetch:
	@d=$$(mktemp -d) && trap 'rm -rf "$$d"' EXIT && \
	for z in gcmtestvectors cmactestvectors; do \
		curl -sSfL -o "$$d/$$z.zip" "$(NIST_URL)/$$z.zip" || exit 1; \
		unzip -q -o "$$d/$$z.zip" -d "$$d/x" || exit 1; \
	done && \
	mkdir -p $(KAT_DIR)/nist && \
	for f in $(NIST_RSP); do cp "$$d/x/$$f" $(KAT_DIR)/nist/ || exit 1; done && \
	cd $(KAT_DIR)/nist && sha256sum -c SHA256SUMS

clean:
	rm -rf $(TB_DIR)/sim_build
