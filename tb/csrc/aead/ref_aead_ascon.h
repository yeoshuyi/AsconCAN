#ifndef REF_AEAD_ASCON_H_
#define REF_AEAD_ASCON_H_

#include <stddef.h>
#include <stdint.h>

/* Encrypt and decrypt functions binded to ascon-c, *m is message, *c is ciphertext */
int ref_aead_ascon_encrypt(uint8_t *c, const uint8_t *m, size_t mlen,
                           const uint8_t *ad, size_t adlen,
                           const uint8_t nonce[16], const uint8_t key[16]);

int ref_aead_ascon_decrypt(uint8_t *m, const uint8_t *c, size_t mlen,
                           const uint8_t *ad, size_t adlen,
                           const uint8_t nonce[16], const uint8_t key[16]);
#endif
