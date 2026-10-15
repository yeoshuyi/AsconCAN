/*
 * KAT Test for MAC Modes
 * Ascon checked against ascon-c KAT file
 * AES-CMAC checked against RFC 4493 Section 4 test vectors
 */

#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ref_mac_core.h"

static unsigned n_pass, n_fail, n_skip;

static const char *alg_name(int alg) {
    return alg == REF_MAC_AES_CMAC ? "AES-128 CMAC" : "Ascon-MAC";
}

static void print_hex(const char *label, const uint8_t *b, size_t n) {
    printf("%s", label);
    for (size_t i = 0; i < n; ++i) printf("%02X", b[i]);
    printf("\n");
}

static void check_vector(const char *src, int alg, const uint8_t key[16],
                         const uint8_t *msg, size_t len, const uint8_t *exp,
                         size_t tag_len, int expect_match) {
    uint8_t tag[REF_MAC_TAG_BYTES] = {0};
    int rc = ref_mac_compute(alg, key, msg, len, tag, tag_len);
    int ok = rc == REF_MAC_OK &&
             (memcmp(tag, exp, tag_len) == 0) == (expect_match != 0);

    printf("%s  %-12s len=%-5zu tlen=%-2zu %s\n", ok ? "PASS" : "FAIL",
           alg_name(alg), len, tag_len, src);
    if (ok) {
        ++n_pass;
        return;
    }
    ++n_fail;
    if (rc != REF_MAC_OK) {
        printf("      ref_mac_compute returned %d (%s)\n", rc, ref_mac_strerror(rc));
    } else {
        print_hex(expect_match ? "expected: " : "expected anything but: ", exp, tag_len);
        print_hex("actual:   ", tag, tag_len);
    }
}

static void check_cond(int cond, const char *what) {
    printf("%s  %s\n", cond ? "PASS" : "FAIL", what);
    if (cond) ++n_pass; else ++n_fail;
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    c = tolower(c);
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static int hex_decode(const char *s, uint8_t **out, size_t *out_len) {
    size_t n = strlen(s), i;
    uint8_t *b;
    if (n % 2 != 0) return -1;
    b = malloc(n / 2 + 1);
    if (b == NULL) return -1;
    for (i = 0; i < n / 2; ++i) {
        int hi = hexval((unsigned char)s[2 * i]);
        int lo = hexval((unsigned char)s[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            free(b);
            return -1;
        }
        b[i] = (uint8_t)(hi << 4 | lo);
    }
    *out = b;
    *out_len = n / 2;
    return 0;
}

struct record {
    long count;
    uint8_t *key, *msg, *mac;
    size_t key_len, msg_len, mac_len;
    long klen, mlen, tlen; /* CAVP only; -1 when absent */
    int result_fail;       /* CAVP verify files: "Result = F" */
    int bad;               /* malformed hex in this record */
};

static void record_reset(struct record *r) {
    free(r->key);
    free(r->msg);
    free(r->mac);
    memset(r, 0, sizeof *r);
    r->count = r->klen = r->mlen = r->tlen = -1;
}

static void record_set(struct record *r, uint8_t **dst, size_t *dst_len, const char *hex) {
    free(*dst);
    *dst = NULL;
    if (hex_decode(hex, dst, dst_len) != 0) r->bad = 1;
}

enum file_kind { KIND_ASCON, KIND_CAVP };

static void record_flush(struct record *r, enum file_kind kind, const char *file) {
  char src[96];
  int alg = kind == KIND_ASCON ? REF_MAC_ASCON_MAC : REF_MAC_AES_CMAC;

  if (r->key == NULL && r->msg == NULL && r->mac == NULL) return;
  snprintf(src, sizeof src, "%s Count=%ld", file, r->count);

  if (r->bad || r->key == NULL || r->msg == NULL || r->mac == NULL) {
    printf("FAIL  %-12s malformed record: %s\n", alg_name(alg), src);
    ++n_fail;
  } else if (kind == KIND_ASCON) {
    if (r->key_len != 16 || r->mac_len != 16) {
      printf("FAIL  %-12s unexpected key/tag size: %s\n", alg_name(alg), src);
      ++n_fail;
    } else {
      check_vector(src, alg, r->key, r->msg, r->msg_len, r->mac, 16, 1);
    }
  } else {
    /* CAVP: Mlen/Tlen are in bytes; Mlen = 0 is written as "Msg = 00". */
    size_t mlen = r->mlen >= 0 ? (size_t)r->mlen : r->msg_len;
    size_t tlen = r->tlen >= 0 ? (size_t)r->tlen : r->mac_len;
    if (r->key_len != 16 || (r->klen >= 0 && r->klen != 16)) {
      printf("SKIP  %-12s not an AES-128 key: %s\n", alg_name(alg), src);
      ++n_skip;
    } else if (mlen > r->msg_len || tlen > r->mac_len || tlen == 0 || tlen > 16) {
      printf("FAIL  %-12s inconsistent Mlen/Tlen: %s\n", alg_name(alg), src);
      ++n_fail;
    } else if (mlen > REF_MAC_MAX_BYTES) {
      printf("SKIP  %-12s len=%zu > REF_MAC_MAX_BYTES: %s\n", alg_name(alg), mlen, src);
      ++n_skip;
    } else {
      check_vector(src, alg, r->key, r->msg, mlen, r->mac, tlen, !r->result_fail);
    }
  }
  record_reset(r);
}

/* Returns the number of records seen, or -1 if the file cannot be opened. */
static long run_record_file(const char *path, enum file_kind kind) {
  FILE *fp = fopen(path, "r");
  const char *base = strrchr(path, '/');
  struct record r;
  char *line = NULL;
  size_t cap = 0;
  long records = 0;

  if (fp == NULL) {
    perror(path);
    return -1;
  }
  base = base ? base + 1 : path;
  memset(&r, 0, sizeof r);
  record_reset(&r);

  while (getline(&line, &cap, fp) != -1) {
    char *name = line, *val, *end, *eq;

    while (isspace((unsigned char)*name)) ++name;
    if (*name == '\0' || *name == '#' || *name == '[') continue;
    eq = strchr(name, '=');
    if (eq == NULL) continue;
    /* trim name */
    end = eq;
    while (end > name && isspace((unsigned char)end[-1])) --end;
    *end = '\0';
    /* trim value */
    val = eq + 1;
    while (isspace((unsigned char)*val)) ++val;
    end = val + strlen(val);
    while (end > val && isspace((unsigned char)end[-1])) --end;
    *end = '\0';

    if (strcmp(name, "Count") == 0) {
      record_flush(&r, kind, base);
      r.count = strtol(val, NULL, 10);
      ++records;
    } else if (strcmp(name, "Key") == 0) {
      record_set(&r, &r.key, &r.key_len, val);
    } else if (strcmp(name, "Msg") == 0) {
      record_set(&r, &r.msg, &r.msg_len, val);
    } else if (strcmp(name, "Tag") == 0 || strcmp(name, "Mac") == 0) {
      record_set(&r, &r.mac, &r.mac_len, val);
    } else if (strcmp(name, "Klen") == 0) {
      r.klen = strtol(val, NULL, 10);
    } else if (strcmp(name, "Mlen") == 0) {
      r.mlen = strtol(val, NULL, 10);
    } else if (strcmp(name, "Tlen") == 0) {
      r.tlen = strtol(val, NULL, 10);
    } else if (strcmp(name, "Result") == 0) {
      r.result_fail = (val[0] == 'F');
    }
  }
  record_flush(&r, kind, base);
  free(line);
  fclose(fp);
  return records;
}

/* ---- RFC 4493 ---- */

static void run_rfc4493(void) {
  /*
   * RFC 4493, section 4 "Test Vectors" (AES-128). The RFC states these are
   * the same as NIST SP 800-38B (Appendix D.1, AES-128 examples 1-4: Mlen
   * 0, 128, 320, 512 bits), so the NIST examples are not listed separately.
   *
   *   K              2b7e1516 28aed2a6 abf71588 09cf4f3c
   */
  static const uint8_t key[16] = {
      0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
      0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  /*
   *   M (Example 4)  6bc1bee2 2e409f96 e93d7e11 7393172a
   *                  ae2d8a57 1e03ac9c 9eb76fac 45af8e51
   *                  30c81c46 a35ce411 e5fbc119 1a0a52ef
   *                  f69f2445 df4f9b17 ad2b417b e66c3710
   * Examples 1-3 use the first 0, 16 and 40 bytes of the same message.
   */
  static const uint8_t m[64] = {
      0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
      0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
      0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
      0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
      0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
      0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
      0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
      0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
  static const struct {
    const char *name;
    size_t len;
    uint8_t tag[16];
  } v[] = {
      /* Example 1: len = 0   (padded final block, K2)
       *   AES-CMAC   bb1d6929 e9593728 7fa37d12 9b756746 */
      {"RFC4493 sec.4 Example 1", 0,
       {0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
        0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46}},
      /* Example 2: len = 16  (complete final block, K1)
       *   AES-CMAC   070a16b4 6b4d4144 f79bdd9d d04a287c */
      {"RFC4493 sec.4 Example 2", 16,
       {0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
        0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c}},
      /* Example 3: len = 40  (multi-block, padded final block, K2)
       *   AES-CMAC   dfa66747 de9ae630 30ca3261 1497c827 */
      {"RFC4493 sec.4 Example 3", 40,
       {0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
        0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27}},
      /* Example 4: len = 64  (multi-block, complete final block, K1)
       *   AES-CMAC   51f0bebf 7e3b9d92 fc497417 79363cfe */
      {"RFC4493 sec.4 Example 4", 64,
       {0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
        0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe}},
  };
  size_t i;
  for (i = 0; i < sizeof v / sizeof v[0]; ++i)
    check_vector(v[i].name, REF_MAC_AES_CMAC, key, m, v[i].len, v[i].tag, 16, 1);
}

/* ---- argument checking, consistency, truncation ---- */

static uint64_t prng_state = 0x9E3779B97F4A7C15ULL; /* fixed seed: reproducible */

static uint8_t prng_byte(void) {
  prng_state ^= prng_state << 13;
  prng_state ^= prng_state >> 7;
  prng_state ^= prng_state << 17;
  return (uint8_t)(prng_state >> 32);
}

static void run_arg_checks(void) {
  uint8_t key[16] = {0}, msg[4] = {0}, tag[16];
  static uint8_t big[REF_MAC_MAX_BYTES + 1];

  check_cond(ref_mac_selftest_core() == REF_MAC_OK, "built-in self-test");
  check_cond(ref_mac_compute(2, key, msg, 4, tag, 16) == REF_MAC_ERR_ALG, "reject alg=2");
  check_cond(ref_mac_compute(-1, key, msg, 4, tag, 16) == REF_MAC_ERR_ALG, "reject alg=-1");
  for (int alg = 0; alg <= 1; ++alg) {
    check_cond(ref_mac_compute(alg, key, big, sizeof big, tag, 16) == REF_MAC_ERR_LEN,
               "reject len = REF_MAC_MAX_BYTES + 1");
    check_cond(ref_mac_compute(alg, key, msg, 4, tag, 0) == REF_MAC_ERR_TAG_LEN,
               "reject tag_len = 0");
    check_cond(ref_mac_compute(alg, key, msg, 4, tag, 17) == REF_MAC_ERR_TAG_LEN,
               "reject tag_len = 17");
    check_cond(ref_mac_compute(alg, NULL, msg, 4, tag, 16) == REF_MAC_ERR_ARG,
               "reject NULL key");
    check_cond(ref_mac_compute(alg, key, NULL, 4, tag, 16) == REF_MAC_ERR_ARG,
               "reject NULL msg with len > 0");
    check_cond(ref_mac_compute(alg, key, msg, 4, NULL, 16) == REF_MAC_ERR_ARG,
               "reject NULL tag");
    check_cond(ref_mac_compute(alg, key, NULL, 0, tag, 16) == REF_MAC_OK,
               "accept NULL msg with len = 0");
  }
}

static void run_consistency_one(int alg, size_t len) {
  /* Exact-size heap buffer so ASan catches any over-read past msg[len-1]. */
  uint8_t *msg = malloc(len ? len : 1);
  uint8_t key[16], t1[16], t2[16], tr[16 + 1];
  int ok = msg != NULL;
  size_t i, tl;

  for (i = 0; i < 16; ++i) key[i] = prng_byte();
  for (i = 0; ok && i < len; ++i) msg[i] = prng_byte();

  ok = ok && ref_mac_compute(alg, key, msg, len, t1, 16) == REF_MAC_OK;
  ok = ok && ref_mac_compute(alg, key, msg, len, t2, 16) == REF_MAC_OK;
  ok = ok && memcmp(t1, t2, 16) == 0;
  for (tl = 1; ok && tl <= 16; ++tl) {
    memset(tr, 0xA5, sizeof tr);
    ok = ref_mac_compute(alg, key, msg, len, tr, tl) == REF_MAC_OK &&
         memcmp(tr, t1, tl) == 0;
    /* nothing written past tag_len */
    for (i = tl; ok && i < sizeof tr; ++i) ok = tr[i] == 0xA5;
  }
  printf("%s  %-12s len=%-5zu consistency + truncation 1..16\n",
         ok ? "PASS" : "FAIL", alg_name(alg), len);
  if (ok) ++n_pass; else ++n_fail;
  free(msg);
}

static void run_consistency(void) {
  static const size_t extra[] = {65, 127, 128, 129, 1023, 1024, 2048,
                                 REF_MAC_MAX_BYTES - 1, REF_MAC_MAX_BYTES};
  for (int alg = 0; alg <= 1; ++alg) {
    size_t len, i;
    for (len = 0; len <= 64; ++len) run_consistency_one(alg, len);
    for (i = 0; i < sizeof extra / sizeof extra[0]; ++i)
      run_consistency_one(alg, extra[i]);
  }
}

int main(int argc, char **argv) {
  long n;

  if (argc < 2 || argc > 3) {
    fprintf(stderr, "usage: %s <LWC_MAC_KAT_128_128.txt> [CMACGenAES128.rsp]\n", argv[0]);
    return 2;
  }

  printf("== Ascon-Mac: official ascon-c KAT file %s\n", argv[1]);
  n = run_record_file(argv[1], KIND_ASCON);
  if (n <= 0) {
    printf("FAIL  no Ascon-Mac KAT records read from %s\n", argv[1]);
    ++n_fail;
  }

  printf("== AES-128-CMAC: RFC 4493 section 4 (= NIST SP 800-38B AES-128 examples)\n");
  run_rfc4493();

  if (argc == 3) {
    printf("== AES-128-CMAC: NIST CAVP file %s\n", argv[2]);
    n = run_record_file(argv[2], KIND_CAVP);
    if (n <= 0) {
      printf("FAIL  no CAVP records read from %s\n", argv[2]);
      ++n_fail;
    }
  } else {
    printf("== AES-128-CMAC: NIST CAVP file not given, skipped\n");
  }

  printf("== Self-test and argument checks\n");
  run_arg_checks();

  printf("== Consistency and truncation (REF_MAC_MAX_BYTES = %d)\n", REF_MAC_MAX_BYTES);
  run_consistency();

  printf("\nSUMMARY: %u passed, %u failed, %u skipped\n", n_pass, n_fail, n_skip);
  return n_fail == 0 ? 0 : 1;
}

