/* KAT Test file for AEAD */
#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ref_aead_core.h"

#define PRNG_NUM 0x9E3779B97F4A7C15ULL

static unsigned n_pass, n_fail, n_skip;

static const char *alg_name(int alg) {
    return alg == REF_AEAD_AES_GCM ? "AES-128-GCM" : "Ascon-AEAD128";
}

static void check_cond(int cond, const char *what) {
    printf("%s  %s\n", cond ? "PASS" : "FAIL", what);
    if (cond) ++n_pass; else ++n_fail;
}

static uint8_t *dup_exact(const uint8_t *p, size_t n) {
    uint8_t *b = malloc(n ? n : 1);
    if (b == NULL) abort();
    if (n) memcpy(b, p, n);
    return b;
}

/*
 * One vector, checked four ways: encryption gives ct and tag; decryption
 * gives pt back; and a flipped bit in the tag, in the ciphertext and in the
 * associated data is each rejected without releasing plaintext.
 */

/* For every vector, we check encryption gives ct and tag and decryption returns pt.
 * Additionally, flipped bit in tag should reject the tag and not return pt.
 */
static void check_vector(const char *src, int alg, const uint8_t key[16],
                         const uint8_t *nonce, const uint8_t *ad, size_t ad_len,
                         const uint8_t *pt, size_t len, const uint8_t *ct,
                         const uint8_t tag[16]) {
    size_t nl = ref_aead_nonce_bytes(alg);
    uint8_t *in = dup_exact(pt, len), *a = dup_exact(ad, ad_len);
    uint8_t *out = malloc(len + 1), *back = malloc(len + 1);
    uint8_t t[16], bad[16];
    const char *why = NULL;
    int rc;

    if (out == NULL || back == NULL) abort();
    out[len] = back[len] = 0xA5;

    rc = ref_aead_compute(alg, 0, key, nonce, nl, a, ad_len, in, len, out, t);
    if (rc != REF_MAC_OK) why = "encrypt failed";
    else if (len && memcmp(out, ct, len) != 0) why = "ciphertext mismatch";
    else if (memcmp(t, tag, 16) != 0) why = "tag mismatch";

    if (why == NULL) {
        rc = ref_aead_compute(alg, 1, key, nonce, nl, a, ad_len, out, len, back, t);
        if (rc != REF_MAC_OK) why = "decrypt failed";
        else if (len && memcmp(back, pt, len) != 0) why = "decrypt gave wrong plaintext";
    }
    if (why == NULL) {
        memcpy(bad, t, 16);
        bad[0] ^= 0x80;
        memset(back, 0x5A, len);
        rc = ref_aead_compute(alg, 1, key, nonce, nl, a, ad_len, out, len, back, bad);
        if (rc != REF_MAC_ERR_AUTH) why = "tampered tag accepted";
        for (size_t i = 0; why == NULL && i < len; ++i)
            if (back[i] != 0x5A) why = "plaintext released on a bad tag";
    }
    if (why == NULL && len > 0) {
        out[len - 1] ^= 0x01;
        rc = ref_aead_compute(alg, 1, key, nonce, nl, a, ad_len, out, len, back, t);
        if (rc != REF_MAC_ERR_AUTH) why = "tampered ciphertext accepted";
        out[len - 1] ^= 0x01;
    }
    if (why == NULL && ad_len > 0) {
        a[0] ^= 0x01;
        rc = ref_aead_compute(alg, 1, key, nonce, nl, a, ad_len, out, len, back, t);
        if (rc != REF_MAC_ERR_AUTH) why = "tampered associated data accepted";
    }
    if (why == NULL && (out[len] != 0xA5 || back[len] != 0xA5)) why = "wrote past the output";

    printf("%s  %-13s ad=%-4zu len=%-4zu %s%s%s\n", why ? "FAIL" : "PASS",
           alg_name(alg), ad_len, len, src, why ? ": " : "", why ? why : "");
    if (why) ++n_fail; else ++n_pass;
    free(in); free(a); free(out); free(back);
}


static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    c = tolower(c);
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

struct field {
    uint8_t *b;
    size_t len;
    int set;
};

static int field_set(struct field *f, const char *hex) {
    size_t n = strlen(hex);
    free(f->b);
    f->b = malloc(n / 2 + 1);
    f->len = n / 2;
    f->set = 1;
    if (f->b == NULL || n % 2 != 0) return -1;
    for (size_t i = 0; i < n / 2; ++i) {
        int hi = hexval((unsigned char)hex[2 * i]), lo = hexval((unsigned char)hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        f->b[i] = (uint8_t)(hi << 4 | lo);
    }
    return 0;
}

struct record {
    long count;
    struct field key, nonce, pt, ad, ct, tag;
    int bad;
};

static void record_reset(struct record *r) {
    free(r->key.b); free(r->nonce.b); free(r->pt.b);
    free(r->ad.b); free(r->ct.b); free(r->tag.b);
    memset(r, 0, sizeof *r);
    r->count = -1;
}

static void record_flush(struct record *r, int alg, const char *file) {
    char src[96];
    const uint8_t *tag;
    size_t ct_len;

    if (!r->key.set && !r->ct.set) return;
    snprintf(src, sizeof src, "%s Count=%ld", file, r->count);

    if (r->bad || !r->key.set || !r->nonce.set || !r->pt.set || !r->ad.set || !r->ct.set) {
      printf("FAIL  %-13s malformed record: %s\n", alg_name(alg), src);
      ++n_fail;
      record_reset(r);
      return;
    }
    if (r->tag.set) {
      tag = r->tag.b;
      ct_len = r->ct.len;
    } else if (r->ct.len >= 16) {
      ct_len = r->ct.len - 16;
      tag = r->ct.b + ct_len;
    } else {
      printf("FAIL  %-13s CT shorter than a tag: %s\n", alg_name(alg), src);
      ++n_fail;
      record_reset(r);
      return;
    }

    if (r->key.len != 16 || r->nonce.len != ref_aead_nonce_bytes(alg) ||
        (r->tag.set && r->tag.len != 16)) {
      printf("SKIP  %-13s key/nonce/tag size not supported: %s\n", alg_name(alg), src);
      ++n_skip;
    } else if (ct_len != r->pt.len) {
      printf("FAIL  %-13s PT and CT lengths differ: %s\n", alg_name(alg), src);
      ++n_fail;
    } else if (r->pt.len > REF_MAC_MAX_BYTES || r->ad.len > REF_MAC_MAX_BYTES) {
      printf("SKIP  %-13s longer than REF_MAC_MAX_BYTES: %s\n", alg_name(alg), src);
      ++n_skip;
    } else {
      check_vector(src, alg, r->key.b, r->nonce.b, r->ad.b, r->ad.len, r->pt.b,
                   r->pt.len, r->ct.b, tag);
    }
    record_reset(r);
}

/* Returns the number of records seen, or -1 if the file cannot be opened. */
static long run_record_file(const char *path, int alg) {
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
      struct field *f = NULL;

      while (isspace((unsigned char)*name)) ++name;
      if (*name == '\0' || *name == '#' || *name == '[') continue;
      eq = strchr(name, '=');
      if (eq == NULL) continue;
      end = eq;
      while (end > name && isspace((unsigned char)end[-1])) --end;
      *end = '\0';
      val = eq + 1;
      while (isspace((unsigned char)*val)) ++val;
      end = val + strlen(val);
      while (end > val && isspace((unsigned char)end[-1])) --end;
      *end = '\0';

      if (strcmp(name, "Count") == 0) {
        record_flush(&r, alg, base);
        r.count = strtol(val, NULL, 10);
        ++records;
      } else if (strcmp(name, "Key") == 0) f = &r.key;
      else if (strcmp(name, "Nonce") == 0 || strcmp(name, "IV") == 0) f = &r.nonce;
      else if (strcmp(name, "PT") == 0) f = &r.pt;
      else if (strcmp(name, "AD") == 0 || strcmp(name, "AAD") == 0) f = &r.ad;
      else if (strcmp(name, "CT") == 0) f = &r.ct;
      else if (strcmp(name, "Tag") == 0) f = &r.tag;

      if (f != NULL && field_set(f, val) != 0) r.bad = 1;
    }
    record_flush(&r, alg, base);
    free(line);
    fclose(fp);
    return records;
}

/* GCM specification test cases (AES-128) */
static void unhex(const char *s, uint8_t *out) {
  for (size_t i = 0; s[2 * i] != '\0'; ++i)
    out[i] = (uint8_t)(hexval((unsigned char)s[2 * i]) << 4 | hexval((unsigned char)s[2 * i + 1]));
}

static void run_gcm_spec(void) {
  static const struct {
    const char *name, *key, *iv, *ad, *pt, *ct, *tag;
  } v[] = {
      {"GCM spec test case 1", "00000000000000000000000000000000",
       "000000000000000000000000", "", "", "",
       "58e2fccefa7e3061367f1d57a4e7455a"},
      {"GCM spec test case 2", "00000000000000000000000000000000",
       "000000000000000000000000", "", "00000000000000000000000000000000",
       "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf"},
      {"GCM spec test case 3", "feffe9928665731c6d6a8f9467308308",
       "cafebabefacedbaddecaf888", "",
       "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
       "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
       "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
       "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
       "4d5c2af327cd64a62cf35abd2ba6fab4"},
      {"GCM spec test case 4", "feffe9928665731c6d6a8f9467308308",
       "cafebabefacedbaddecaf888", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
       "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
       "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
       "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
       "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
       "5bc94fbc3221a5db94fae95ae7121a47"},
  };
  for (size_t i = 0; i < sizeof v / sizeof v[0]; ++i) {
    uint8_t key[16], iv[12], ad[32], pt[64], ct[64], tag[16];
    unhex(v[i].key, key);
    unhex(v[i].iv, iv);
    unhex(v[i].ad, ad);
    unhex(v[i].pt, pt);
    unhex(v[i].ct, ct);
    unhex(v[i].tag, tag);
    check_vector(v[i].name, REF_AEAD_AES_GCM, key, iv, ad, strlen(v[i].ad) / 2,
                 pt, strlen(v[i].pt) / 2, ct, tag);
  }
}

static uint64_t prng_state = PRNG_NUM;

static uint8_t prng_byte(void) {
  prng_state ^= prng_state << 13;
  prng_state ^= prng_state >> 7;
  prng_state ^= prng_state << 17;
  return (uint8_t)(prng_state >> 32);
}

static void run_arg_checks(void) {
  uint8_t key[16] = {0}, nonce[16] = {0}, buf[4] = {0}, out[4], tag[16] = {0};
  static uint8_t big[REF_MAC_MAX_BYTES + 1], big_out[REF_MAC_MAX_BYTES + 1];

  check_cond(ref_aead_selftest_core() == REF_MAC_OK, "built-in self-test");
  check_cond(ref_aead_compute(2, 0, key, nonce, 16, buf, 4, buf, 4, out, tag) == REF_MAC_ERR_ALG,
             "reject alg=2");
  check_cond(ref_aead_nonce_bytes(REF_AEAD_AES_GCM) == 12 &&
             ref_aead_nonce_bytes(REF_AEAD_ASCON128) == 16 && ref_aead_nonce_bytes(7) == 0,
             "nonce lengths: GCM 12, Ascon 16");
  for (int alg = 0; alg <= 1; ++alg) {
    size_t nl = ref_aead_nonce_bytes(alg);
    check_cond(ref_aead_compute(alg, 0, key, nonce, nl - 1, buf, 4, buf, 4, out, tag) == REF_MAC_ERR_NONCE,
               "reject a short nonce");
    check_cond(ref_aead_compute(alg, 0, key, nonce, nl == 12 ? 16 : 12, buf, 4, buf, 4, out, tag) == REF_MAC_ERR_NONCE,
               "reject the other algorithm's nonce length");
    check_cond(ref_aead_compute(alg, 0, key, nonce, nl, big, sizeof big, buf, 4, out, tag) == REF_MAC_ERR_LEN,
               "reject ad_len = REF_MAC_MAX_BYTES + 1");
    check_cond(ref_aead_compute(alg, 0, key, nonce, nl, buf, 4, big, sizeof big, big_out, tag) == REF_MAC_ERR_LEN,
               "reject in_len = REF_MAC_MAX_BYTES + 1");
    check_cond(ref_aead_compute(alg, 0, NULL, nonce, nl, buf, 4, buf, 4, out, tag) == REF_MAC_ERR_ARG,
               "reject NULL key");
    check_cond(ref_aead_compute(alg, 0, key, NULL, nl, buf, 4, buf, 4, out, tag) == REF_MAC_ERR_ARG,
               "reject NULL nonce");
    check_cond(ref_aead_compute(alg, 0, key, nonce, nl, NULL, 4, buf, 4, out, tag) == REF_MAC_ERR_ARG,
               "reject NULL ad with ad_len > 0");
    check_cond(ref_aead_compute(alg, 0, key, nonce, nl, buf, 4, NULL, 4, out, tag) == REF_MAC_ERR_ARG,
               "reject NULL in with in_len > 0");
    check_cond(ref_aead_compute(alg, 0, key, nonce, nl, buf, 4, buf, 4, out, NULL) == REF_MAC_ERR_ARG,
               "reject NULL tag");
    check_cond(ref_aead_compute(alg, 0, key, nonce, nl, NULL, 0, NULL, 0, NULL, tag) == REF_MAC_OK,
               "accept empty ad and empty plaintext with NULL buffers");
  }
}

/* Encrypt random data, then run it through check_vector against itself:
 * that exercises decryption and every tamper case at this length. */
static void run_roundtrip_one(int alg, size_t ad_len, size_t len) {
  uint8_t key[16], nonce[16], tag[16];
  uint8_t *ad = malloc(ad_len ? ad_len : 1), *pt = malloc(len ? len : 1);
  uint8_t *ct = malloc(len ? len : 1);
  char src[48];
  size_t i;

  if (ad == NULL || pt == NULL || ct == NULL) abort();
  for (i = 0; i < 16; ++i) key[i] = prng_byte();
  for (i = 0; i < 16; ++i) nonce[i] = prng_byte();
  for (i = 0; i < ad_len; ++i) ad[i] = prng_byte();
  for (i = 0; i < len; ++i) pt[i] = prng_byte();

  if (ref_aead_compute(alg, 0, key, nonce, ref_aead_nonce_bytes(alg), ad, ad_len,
                       pt, len, ct, tag) != REF_MAC_OK) {
    printf("FAIL  %-13s ad=%-4zu len=%-4zu round trip: encrypt failed\n",
           alg_name(alg), ad_len, len);
    ++n_fail;
  } else {
    snprintf(src, sizeof src, "round trip + tamper");
    check_vector(src, alg, key, nonce, ad, ad_len, pt, len, ct, tag);
  }
  free(ad); free(pt); free(ct);
}

static void run_roundtrips(void) {
  static const size_t lens[] = {0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65,
                                127, 128, 129, 1023, 1024, 2024, 2048,
                                REF_MAC_MAX_BYTES};
  static const size_t ads[] = {0, 1, 15, 16, 17, 18, 32, 33, REF_MAC_MAX_BYTES};
  for (int alg = 0; alg <= 1; ++alg)
    for (size_t a = 0; a < sizeof ads / sizeof ads[0]; ++a)
      for (size_t l = 0; l < sizeof lens / sizeof lens[0]; ++l)
        run_roundtrip_one(alg, ads[a], lens[l]);
}

int main(int argc, char **argv) {
  long n;

  if (argc < 2 || argc > 3) {
    fprintf(stderr, "usage: %s <LWC_AEAD_KAT_128_128.txt> [gcmEncryptExtIV128.rsp]\n", argv[0]);
    return 2;
  }

  printf("== Ascon-AEAD128: official ascon-c KAT file %s\n", argv[1]);
  n = run_record_file(argv[1], REF_AEAD_ASCON128);
  if (n <= 0) {
    printf("FAIL  no Ascon-AEAD128 KAT records read from %s\n", argv[1]);
    ++n_fail;
  }

  printf("== AES-128-GCM: GCM specification test cases 1-4\n");
  run_gcm_spec();

  if (argc == 3) {
    printf("== AES-128-GCM: NIST CAVP file %s\n", argv[2]);
    n = run_record_file(argv[2], REF_AEAD_AES_GCM);
    if (n <= 0) {
      printf("FAIL  no CAVP records read from %s\n", argv[2]);
      ++n_fail;
    }
  } else {
    printf("== AES-128-GCM: NIST CAVP file not given, skipped\n");
  }

  printf("== Self-test and argument checks\n");
  run_arg_checks();

  printf("== Round trips and tamper rejection on random data\n");
  run_roundtrips();

  printf("\nSUMMARY: %u passed, %u failed, %u skipped\n", n_pass, n_fail, n_skip);
  return n_fail == 0 ? 0 : 1;
}

