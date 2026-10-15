/*
 * MAC Tag Reference Model.
 */

#include "ref_mac_core.h"

#include <string.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/params.h>

#if OPENSSL_VERSION_NUMBNER < 0x30000000L
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

