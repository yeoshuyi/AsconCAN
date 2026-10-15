/*
 * MAC Tag Reference Model.
 */

#include "ref_mac_core.h"
#include "ref_mac_ascon.h"

#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/params.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "OpenSLL required version >= 3.0"
#endif

/* AES Reference Genrator */
static int aes_cmac_full(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t out[REF_MAC_TAG_BYTES]) {
    int rc = REF_MAC_ERR_OPENSSL;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    char cipher[] = "AES-128-CBC";
    OSSL_PARAM params[2];
    size_t outl = 0;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cipher, 0);
    params[1] = OSSL_PARAM_construct_end();

    mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (mac == NULL) goto cleanup;
    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL) goto cleanup;
    if (EVP_MAC_init(ctx, key, REF_MAC_KEY_BYTES, params) != 1) goto cleanup;
    if (len > 0 && EVP_MAC_update(ctx, msg, len) != 1) goto cleanup;
    if (EVP_MAC_final(ctx, out, &outl, REF_MAC_TAG_BYTES) != 1) goto cleanup;
    if (outl != REF_MAC_TAG_BYTES) goto cleanup;
    rc = REF_MAC_OK;

cleanup:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return rc;
}

int ref_mac_compute(int alg, const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t *tag, size_t tag_len) {
    uint8_t full[REF_MAC_TAG_BYTES];
    int rc;

    /* Errors */
    if (alg != REF_MAC_AES_CMAC && alg != REF_MAC_ASCON_MAC) return REF_MAC_ERR_ALG;
    if (key == NULL || tag == NULL) return REF_MAC_ERR_ARG;
    if (len > REF_MAC_MAX_BYTES) return REF_MAC_ERR_LEN;
    if (msg == NULL && len > 0) return REF_MAC_ERR_ARG;
    if (tag_len == 0 || tag_len > REF_MAC_TAG_BYTES) return REF_MAC_ERR_TAG_LEN;

    if (alg == REF_MAC_AES_CMAC) {
        rc = aes_cmac_full(key, msg, len, full);
    } else {
        rc = ref_mac_ascon(full, msg, len, key) == 0 ? REF_MAC_OK : REF_MAC_ERR_ASCON;
    }
    if (rc != REF_MAC_OK) return rc;

    /* Truncation: first tag_len bytes of the full tag. */
    memcpy(tag, full, tag_len);
    return REF_MAC_OK;
}

int ref_mac_selftest_core(void) {
  /* RFC 4493 section 4: key, message M (first 40 bytes), examples 1 and 3. */
  static const uint8_t cmac_key[16] = {
      0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
      0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  static const uint8_t cmac_msg[40] = {
      0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
      0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
      0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
      0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11};
  static const uint8_t cmac_tag0[16] = {
      0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
      0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46};
  static const uint8_t cmac_tag40[16] = {
      0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
      0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27};
  /* ascon-c LWC_MAC_KAT_128_128.txt: Count 1 (empty) and Count 34 (33 bytes,
   * i.e. one full 32-byte rate block plus one byte). Key = 00..0F,
   * Msg = 10 11 12 ... */
  static const uint8_t ascon_tag0[16] = {
      0xEA, 0xC9, 0xD7, 0x4B, 0xBE, 0xDF, 0x8B, 0xF1,
      0xEB, 0xA2, 0x86, 0x2B, 0x26, 0xAA, 0x6D, 0x39};
  static const uint8_t ascon_tag33[16] = {
      0x29, 0x31, 0x32, 0x84, 0x67, 0x0B, 0x54, 0xF0,
      0x56, 0x4F, 0x9C, 0x73, 0xF2, 0x71, 0x31, 0xF1};

  uint8_t ascon_key[16], ascon_msg[33], tag[REF_MAC_TAG_BYTES];
  const struct {
    int alg;
    const uint8_t *key, *msg;
    size_t len;
    const uint8_t *exp;
    size_t tag_len;
  } v[] = {
      {REF_MAC_AES_CMAC, cmac_key, cmac_msg, 0, cmac_tag0, 16},
      {REF_MAC_AES_CMAC, cmac_key, cmac_msg, 40, cmac_tag40, 16},
      {REF_MAC_AES_CMAC, cmac_key, cmac_msg, 40, cmac_tag40, 8},
      {REF_MAC_ASCON_MAC, ascon_key, ascon_msg, 0, ascon_tag0, 16},
      {REF_MAC_ASCON_MAC, ascon_key, ascon_msg, 33, ascon_tag33, 16},
      {REF_MAC_ASCON_MAC, ascon_key, ascon_msg, 33, ascon_tag33, 8},
  };
  size_t i;

  for (i = 0; i < sizeof ascon_key; ++i) ascon_key[i] = (uint8_t)i;
  for (i = 0; i < sizeof ascon_msg; ++i) ascon_msg[i] = (uint8_t)(0x10 + i);

  for (i = 0; i < sizeof v / sizeof v[0]; ++i) {
    int rc = ref_mac_compute(v[i].alg, v[i].key, v[i].msg, v[i].len, tag,
                             v[i].tag_len);
    if (rc != REF_MAC_OK) return rc;
    if (memcmp(tag, v[i].exp, v[i].tag_len) != 0) return REF_MAC_ERR_SELFTEST;
  }
  return REF_MAC_OK;
}

const char *ref_mac_strerror(int err) {
  switch (err) {
    case REF_MAC_OK: return "ok";
    case REF_MAC_ERR_ALG: return "unknown algorithm";
    case REF_MAC_ERR_ARG: return "NULL argument";
    case REF_MAC_ERR_LEN: return "message length out of range";
    case REF_MAC_ERR_TAG_LEN: return "tag length must be 1..16";
    case REF_MAC_ERR_OPENSSL: return "OpenSSL failure";
    case REF_MAC_ERR_ASCON: return "ascon-c failure";
    case REF_MAC_ERR_DPI: return "bad DPI array shape or size";
    case REF_MAC_ERR_SELFTEST: return "self-test vector mismatch";
    case REF_MAC_ERR_AUTH: return "authentication tag mismatch";
    case REF_MAC_ERR_NONCE: return "wrong nonce length";
    default: return "unknown error";
  }
}

