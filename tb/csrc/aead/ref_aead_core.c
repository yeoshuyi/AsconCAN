/* C Reference for AEAD */

#include "ref_aead_core.h"
#include "ref_aead_ascon.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "Requires OpenSSL Version >= 3.0"
#endif

size_t ref_aead_nonce_bytes(int alg) {
    if (alg == REF_AEAD_AES_GCM) return REF_AEAD_GCM_NONCE_BYTES;
    if (alg == REF_AEAD_ASCON128) return REF_AEAD_ASCON_NONCE_BYTES;
    return 0;
}

static int aes_gcm(int decrypt, const uint8_t key[16], const uint8_t *nonce,
                   const uint8_t *ad, size_t ad_len, const uint8_t *in,
                   size_t in_len, uint8_t *out, uint8_t tag[16]) {
    int rc = REF_MAC_ERR_OPENSSL;
    int n = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) return rc;
    if (EVP_CipherInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL, !decrypt) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, REF_AEAD_GCM_NONCE_BYTES, NULL) != 1) goto cleanup;
    if (EVP_CipherInit_ex(ctx, NULL, NULL, key, nonce, !decrypt) != 1) goto cleanup;
    if (ad_len > 0 && EVP_CipherUpdate(ctx, NULL, &n, ad, (int)ad_len) != 1) goto cleanup;
    if (in_len > 0 && EVP_CipherUpdate(ctx, out, &n, in, (int)in_len) != 1) goto cleanup;
    if (decrypt) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, REF_MAC_TAG_BYTES, tag) != 1) goto cleanup;
        rc = EVP_CipherFinal_ex(ctx, out + in_len, &n) == 1 ? REF_MAC_OK : REF_MAC_ERR_AUTH;
    } else {
        if (EVP_CipherFinal_ex(ctx, out + in_len, &n) != 1) goto cleanup;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, REF_MAC_TAG_BYTES, tag) != 1) goto cleanup;
        rc = REF_MAC_OK;
    }

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

int ref_aead_compute(int alg, int decrypt, const uint8_t key[16],
                     const uint8_t *nonce, size_t nonce_len,
                     const uint8_t *ad, size_t ad_len,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, uint8_t tag[16]) {
    uint8_t *buf, *res;
    uint8_t tag_buf[REF_MAC_TAG_BYTES];
    int rc;

    /* Input validation */
    if (alg != REF_AEAD_AES_GCM && alg != REF_AEAD_ASCON128) return REF_MAC_ERR_ALG;
    if (key == NULL || nonce == NULL || tag == NULL) return REF_MAC_ERR_ARG;
    if (ad_len > REF_MAC_MAX_BYTES || in_len > REF_MAC_MAX_BYTES) return REF_MAC_ERR_LEN;
    if (ad == NULL && ad_len > 0) return REF_MAC_ERR_ARG;
    if ((in == NULL || out == NULL) && in_len > 0) return REF_MAC_ERR_ARG;
    if (nonce_len != ref_aead_nonce_bytes(alg)) return REF_MAC_ERR_NONCE;

    buf = malloc(2 * (in_len + REF_MAC_TAG_BYTES));
    if (buf == NULL) return REF_MAC_ERR_ARG;
    res = buf + in_len + REF_MAC_TAG_BYTES;
    memcpy(tag_buf, tag, sizeof tag_buf);

    /* Result generation */
    if (alg == REF_AEAD_AES_GCM) {
        rc = aes_gcm(decrypt, key, nonce, ad, ad_len, in, in_len, res, tag_buf);
    } else if (decrypt) {
        if (in_len > 0) memcpy(buf, in, in_len);
        memcpy(buf + in_len, tag_buf, REF_MAC_TAG_BYTES);
        rc = ref_aead_ascon_decrypt(res, buf, in_len, ad, ad_len, nonce, key) == 0
                 ? REF_MAC_OK : REF_MAC_ERR_AUTH;
    } else {
        rc = ref_aead_ascon_encrypt(buf, in, in_len, ad, ad_len, nonce, key) == 0
                 ? REF_MAC_OK : REF_MAC_ERR_ASCON;
        if (rc == REF_MAC_OK) {
            memcpy(res, buf, in_len);
            memcpy(tag_buf, buf + in_len, REF_MAC_TAG_BYTES);
        }
    }

    if (rc == REF_MAC_OK) {
        if (in_len > 0) memcpy(out, res, in_len);
        if (!decrypt) memcpy(tag, tag_buf, REF_MAC_TAG_BYTES);
    }
    free(buf);
    return rc;
}

int ref_aead_selftest_core(void) {
    /* GCM specification (McGrew & Viega), AES-128 test cases 2 and 4. */
    static const uint8_t zero[16] = {0};
    static const uint8_t gcm2_ct[16] = {
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78};
    static const uint8_t gcm2_tag[16] = {
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf};
    static const uint8_t gcm4_key[16] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
    static const uint8_t gcm4_iv[12] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
    static const uint8_t gcm4_ad[20] = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed,
        0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2};
    static const uint8_t gcm4_pt[60] = {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5,
        0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95,
        0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39};
    static const uint8_t gcm4_ct[60] = {
        0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7,
        0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
        0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2,
        0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
        0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91};
    static const uint8_t gcm4_tag[16] = {
        0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
        0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47};
    /* ascon-c LWC_AEAD_KAT_128_128.txt, Count 35 and 600. Key = 00..0F,
     * Nonce = 10..1F, PT = 20 21 .., AD = 30 31 .. */
    static const uint8_t ascon35_ct[1] = {0x96};
    static const uint8_t ascon35_tag[16] = {
        0x2B, 0x80, 0x16, 0x83, 0x6C, 0x75, 0xA7, 0xD8,
        0x68, 0x66, 0x58, 0x8C, 0xA2, 0x45, 0xD8, 0x86};
    static const uint8_t ascon600_ct[18] = {
        0x30, 0x76, 0x65, 0x8C, 0xBA, 0x8B, 0xF3, 0xBB, 0x6D,
        0xCC, 0xAA, 0x2F, 0x12, 0x55, 0xEE, 0x2E, 0x7D, 0xB6};
    static const uint8_t ascon600_tag[16] = {
        0xF6, 0x49, 0x3C, 0x76, 0x98, 0xF6, 0x5F, 0x68,
        0x60, 0xA7, 0x43, 0x3A, 0x0F, 0x56, 0x1E, 0x6C};

    uint8_t a_key[16], a_nonce[16], a_pt[18], a_ad[5];
    uint8_t out[64], back[64], tag[16];
    const struct {
        int alg;
        const uint8_t *key, *nonce, *ad;
        size_t ad_len;
        const uint8_t *pt;
        size_t len;
        const uint8_t *ct, *tag;
    } v[] = {
        {REF_AEAD_AES_GCM, zero, zero, NULL, 0, zero, 16, gcm2_ct, gcm2_tag},
        {REF_AEAD_AES_GCM, gcm4_key, gcm4_iv, gcm4_ad, 20, gcm4_pt, 60, gcm4_ct, gcm4_tag},
        {REF_AEAD_ASCON128, a_key, a_nonce, a_ad, 1, a_pt, 1, ascon35_ct, ascon35_tag},
        {REF_AEAD_ASCON128, a_key, a_nonce, a_ad, 5, a_pt, 18, ascon600_ct, ascon600_tag},
    };
    size_t i;

    for (i = 0; i < 16; ++i) a_key[i] = (uint8_t)i;
    for (i = 0; i < 16; ++i) a_nonce[i] = (uint8_t)(0x10 + i);
    for (i = 0; i < sizeof a_pt; ++i) a_pt[i] = (uint8_t)(0x20 + i);
    for (i = 0; i < sizeof a_ad; ++i) a_ad[i] = (uint8_t)(0x30 + i);

    for (i = 0; i < sizeof v / sizeof v[0]; ++i) {
        size_t nl = ref_aead_nonce_bytes(v[i].alg);
        int rc = ref_aead_compute(v[i].alg, 0, v[i].key, v[i].nonce, nl, v[i].ad,
                                  v[i].ad_len, v[i].pt, v[i].len, out, tag);
        if (rc != REF_MAC_OK) return rc;
        if (memcmp(out, v[i].ct, v[i].len) != 0 || memcmp(tag, v[i].tag, 16) != 0)
          return REF_MAC_ERR_SELFTEST;

        rc = ref_aead_compute(v[i].alg, 1, v[i].key, v[i].nonce, nl, v[i].ad,
                              v[i].ad_len, out, v[i].len, back, tag);
        if (rc != REF_MAC_OK) return rc;
        if (memcmp(back, v[i].pt, v[i].len) != 0) return REF_MAC_ERR_SELFTEST;

        tag[15] ^= 0x01;
        rc = ref_aead_compute(v[i].alg, 1, v[i].key, v[i].nonce, nl, v[i].ad,
                              v[i].ad_len, out, v[i].len, back, tag);
        if (rc != REF_MAC_ERR_AUTH) return REF_MAC_ERR_SELFTEST;
    }
    return REF_MAC_OK;
}

