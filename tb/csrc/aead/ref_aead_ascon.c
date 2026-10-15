/* ascon-c based reference for AEAD */

#include "ref_aead_ascon.h"

#define crypto_aead_encrypt ref_ascon_crypto_aead_encrypt
#define crypto_aead_decrypt ref_ascon_crypto_aead_decrypt

static int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                               const unsigned char *m, unsigned long long mlen,
                               const unsigned char *ad, unsigned long long adlen,
                               const unsigned char *nsec, const unsigned char *npub,
                               const unsigned char *k);
static int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                               unsigned char *nsec, const unsigned char *c,
                               unsigned long long clen, const unsigned char *ad,
                               unsigned long long adlen, const unsigned char *npub,
                               const unsigned char *k);

/* Resolved through -I$(ASCON_C)/crypto_aead/asconaead128/ref and
 * -I$(ASCON_C)/tests (for crypto_aead.h). */
#include "aead.c"


_Static_assert(CRYPTO_KEYBYTES == 16, "ascon-c variant must use a 128-bit key");
_Static_assert(CRYPTO_NPUBBYTES == 16, "ascon-c variant must use a 128-bit nonce");
_Static_assert(CRYPTO_ABYTES == 16, "ascon-c variant must produce a 128-bit tag");
_Static_assert(ASCON_AEAD_RATE == 16, "ASCON_AEAD_C must point at Ascon-AEAD128");

/* aead.c forms `ad + adlen` style pointers; never hand it NULL. */
static const uint8_t empty;

int ref_aead_ascon_encrypt(uint8_t *c, const uint8_t *m, size_t mlen,
                           const uint8_t *ad, size_t adlen,
                           const uint8_t nonce[16], const uint8_t key[16]) {
    unsigned long long clen = 0;
    int rc = crypto_aead_encrypt(c, &clen, m ? m : &empty, mlen,
                                 ad ? ad : &empty, adlen, NULL, nonce, key);
    return (rc == 0 && clen == mlen + CRYPTO_ABYTES) ? 0 : -1;
}

int ref_aead_ascon_decrypt(uint8_t *m, const uint8_t *c, size_t mlen,
                           const uint8_t *ad, size_t adlen,
                           const uint8_t nonce[16], const uint8_t key[16]) {
    unsigned long long out_len = 0;
    int rc = crypto_aead_decrypt(m, &out_len, NULL, c, mlen + CRYPTO_ABYTES,
                                 ad ? ad : &empty, adlen, nonce, key);
    return (rc == 0 && out_len == mlen) ? 0 : -1;
}

