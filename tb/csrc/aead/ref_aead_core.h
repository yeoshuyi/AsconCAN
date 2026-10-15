#ifndef REF_AEAD_CORE_H_
#define REF_AEAD_CORE_H_

#include <stddef.h>
#include <stdint.h>

#include "../mac/ref_mac_core.h"

enum ref_aead_alg {
    REF_AEAD_AES_GCM = 0,
    REF_AEAD_ASCON128 = 1
};

#define REF_AEAD_GCM_NONCE_BYTES 12
#define REF_AEAD_ASCON_NONCE_BYTES 16
#define REF_AEAD_MAX_NONCE_BYTES 16

size_t ref_aead_nonce_bytes(int alg);

/* Encrypt (decrypt == 0) or decrypt and verify.
 * Nonce is from ref_aead_nonce_bytes(alg)
 * AD is the associated data
 * In/out is the plaintext to ciphertext
 * Tag is the 16 byte tag
 *
 * Returns error code, and writes to out and tag
 */

int ref_aead_compute(int alg, int decrypt, const uint8_t key[16], 
                     const uint8_t *nonce, size_t nonce_len,
                     const uint8_t *ad, size_t ad_len,
                     const uint8_t *in, size_t in_len,
                     uint8_t *out, uint8_t tag[16]);

/* KATs Self test */
int ref_aead_selftest_core(void);

#endif
