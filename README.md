<div align="center">

# AsconCAN
**Ascon Cipher Suite for Third Generation CAN XL Networks.**

The purpose of this repository is to study Ascon as an alternate cipher suite for CANsec, focusing on low power and area optimization.

Ascon Core supporting AEAD and MAC for CANsec applications, compared against NIST KATs for verification.

An AES-GCM/CMAC Core with identical interface is also provided for comparison.

</div>

---

## Highlights

- **Security Cores using Ascon and AES.** Two cores built with the same AXI based interfaces, supporting AD and integrity mode.

- **C Golden Reference via DPI-C.** Comprehensive SystemVerilog testbench uses C based golden reference model produced by OpenSSL libcrypto (for AES) and c-ascon (for Ascon).

- **SV Testbench Against KATs.** Checks frames against both KATs and random-constrained test vectors through the DPI-C model. Tested on both positive and negative cases. Built in profiling with per-frame latency, cycles per byte and stall counts, with length accurate CAN XL vector generator.

## Repository layout

```
src/
  ascon/          ascon_pkg.sv, ascon_sec_axis.sv      Ascon core
  aes/            aes_pkg.sv, aes_sec_axis.sv          AES-GCM / CMAC core
  if/             axis_if, sec_ctrl_if, bram_if        shared interfaces
  harness/        on-chip test harness (WIP)
tb/
  csrc/           C reference models, C KAT runners, DPI-C shim (ref_dpi.c, ref_dpi_pkg.sv)
    thirdparty/ascon-c   git submodule
  sv/             SystemVerilog testbench (env/ classes, tb_top, checkers)
    kat/          KAT files (GCM spec, RFC 4493, NIST CAVP in nist/)
  Makefile        xsim flow
fpga/ArtyS7/      Arty S7-25 constraints and build (WIP)
```

## Core Interface

| Port | Dir | Description |
|---|---|---|
| `key_tdata[7:0]`, `key_tvalid`, `key_tready` | in | 16-byte key, loaded once. Expanded on load (AES ~1166 cycles, Ascon 16). |
| `s_axis_*` (`tdata[7:0]`, `tuser[1:0]`, `tvalid`, `tready`, `tlast`) | in | Frame input, one byte per beat. |
| `m_axis_*` (`tdata[7:0]`, `tvalid`, `tready`, `tlast`) | out | Ciphertext (TX) or plaintext (RX). |
| `tag[8*TAG_BYTES-1:0]`, `tag_valid` | out | Computed tag. |
| `tag_ok` | out | RX only: the received tag matched. |

`s_axis_tuser` marks the phase of each byte:

| `tuser` | Phase |
|---|---|
| 0 | Nonce (AES: 12 bytes, Ascon: 16 bytes) |
| 1 | Associated data, or the whole MAC message |
| 2 | Payload (PT on TX, CT on RX) |
| 3 | Received tag (RX only) |

Parameters: `TAG_BYTES` (16), `AEAD_EN` (0 builds a MAC-only core), and `GHASH_D` (AES only: GHASH multiplier bits per cycle, default 4).

## Installation
> Developed on Ubuntu 24.04 with Vivado 2025.1.1.

Requirements:
- Vivado (`xvlog`, `xelab`, `xsim` on `PATH`)
- A C compiler and OpenSSL >= 3.0 dev headers (`libssl-dev`)
- `make`, `pkg-config`

```bash
git clone --recurse-submodules <repo-url> AsconCAN
cd AsconCAN
# if you cloned without submodules:
git submodule update --init

make -C tb kat-fetch
```

## Quick Start
```bash
make -C tb/csrc test                        # C reference models vs. their own KATs
make -C tb regress                          # both cores, KAT + random suites
make -C tb sim ALG=aes SUITE=kat            # one core, one suite
make -C tb sim ALG=ascon PLUSARGS="+BP_PCT=50 +GAP_PCT=30 +NEG=0"
make -C tb sim ALG=ascon PLUSARGS=+INJECT_ERR   # TB self-test: must report TEST FAILED
```

| Plusarg | Default | Effect |
|---|---|---|
| `+N_RAND=<n>` | 300 | Number of random CAN XL frames |
| `+NEG=0\|1` | 1 | Tampered RX copies of each KAT record |
| `+BP_PCT` / `+GAP_PCT` | 0 / 0 | Output backpressure / input gaps, KAT suite |
| `+RAND_BP_PCT` / `+RAND_GAP_PCT` | 25 / 15 | Random suite |
| `+MAX_FRAMES=<n>` | – | Stop early (debugging) |
| `+VERBOSE` | – | Print every passing frame |
| `+CLK_MHZ=<f>` | 100 | Clock used for the µs figures |

## Results

### Regression results (Vivado xsim 2025.1.1, `SEED=1`)

| Core | pass | FAIL | REF | skip | SVA errors | wall time |
|---|---|---|---|---|---|---|
| Ascon | 9772 | 0 | 0 | 4 | 0 | ~2 min |
| AES | 3369 | 0 | 0 | 13046 | 0 | <1 min |


AES skips due to:
- 10500 Unsupported IV for CANsec.
- 2370 use a truncated tag (RX checks all 16 bytes).
- 16 Unsupported Length for CANsec.
- 160 Empty AD and PT, invalid for CANsec.

### Timing (full regression, 100 MHz, cycles, average)

| | Ascon | AES |
|---|---|---|
| Key setup | 16 | 1166 |
| AEAD TX, cycles/byte | 16.1 | 13.8 |
| AEAD RX, cycles/byte | 11.5 | 10.9 |
| AEAD tail (last byte in → tag) | 227 | 331 |
| MAC TX, cycles/byte | 8.8 | 20.0 |
| MAC RX, cycles/byte | 7.1 | 11.4 |

### Implementation Reports (On Spartan-7)
| | Ascon | AES | Ascon vs AES |
|---|---|---|---|
| Fmax (post-route) | **229.1 MHz** | 133.1 MHz | 1.72× |
| Critical path | 3 logic levels, 3.58 ns | 9 logic levels, 6.58 ns | |
| Dynamic power @ 100 MHz | **10 mW** | 12 mW | −17% |
| Total power @ 100 MHz (incl. 58 mW device static) | 68 mW | 70 mW | |
| Slice LUTs | **391** (2.68%) | 763 (5.23%) | −49% |
| ↳ LUT as memory | 61 (shift registers) | 44 (distributed RAM) | |
| Slice registers | **315** (1.08%) | 430 (1.47%) | −27% |
| Slices | **124** (3.40%) | 249 (6.82%) | −50% |
| F7 muxes | 0 | 35 | |
| BRAM / DSP | 0 / 0 | 0 / 0 | |

> Power report based on SAIF log estimates over 10,000 random test vectors.

## License

See [LICENSE](LICENSE).