/*
 * MAC Tag Reference Model Core Layer
 * AES-128-CMAC uses OpenSSL 3
 * Ascon-MAC uses ascon-c library
 */

#ifndef REF_MAC_CORE_H_
#define REF_MAC_CORE_H_

#include <stddef.h>
#include <stdint.h>

#ifndef REF_MAC_MAX_BYTES
#define REF_MAC_MAX_BYTES 4096
#endif

#define REF_MAC_KEY_BYTES 16
#define REF_MAC_TAG_BYTES 16

enum ref_mac_alg {
    REF_MAC_AES_CMAC = 0,
    REF_MAC_ASCON_MAC = 1
};

enum ref_mac_err {
    REF_MAC_OK = 0,
    REF_MAC_ERR_ALG = -1,      /* unknown alg */
    REF_MAC_ERR_ARG = -2,      /* NULL key/tag, or NULL msg with len > 0 */
    REF_MAC_ERR_LEN = -3,      /* len > REF_MAC_MAX_BYTES (or negative via DPI) */
    REF_MAC_ERR_TAG_LEN = -4,  /* tag_len == 0 or > REF_MAC_TAG_BYTES */
    REF_MAC_ERR_OPENSSL = -5,  /* an OpenSSL call failed */
    REF_MAC_ERR_ASCON = -6,    /* ascon-c crypto_auth returned nonzero */
    REF_MAC_ERR_DPI = -7,      /* DPI layer: bad open-array shape or size */
    REF_MAC_ERR_SELFTEST = -8, /* a built-in vector mismatched */
    REF_MAC_ERR_AUTH = -9,     /* AEAD decrypt: the tag did not verify */
    REF_MAC_ERR_NONCE = -10    /* AEAD: wrong nonce length for the algorithm */
}; 

/* Compute 16 byte MAC tag, writes *tag and returns error code */
int ref_mac_compute(int alg, const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t *tag, size_t tag_len);

/* KATs self test */
int ref_mac_selftest_core(void);

/* Static tag for error code */
const char *ref_mac_strerror(int err);

#endif
