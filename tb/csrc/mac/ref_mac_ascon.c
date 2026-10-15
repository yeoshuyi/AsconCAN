/* Uses https://github.com/ascon/ascon-c official ascon library */

#include "ref_mac_ascon.h"

#define crypto_auth ref_ascon_crypto_auth
#define crypto_prf ref_ascon_crypto_prf
#define crypto_auth_verify ref_ascon_crypto_auth_verify


static int crypto_prf(unsigned char *out, unsigned long long outlen,
                      const unsigned char *in, unsigned long long inlen,
                      const unsigned char *k);
static int crypto_auth(unsigned char *out, const unsigned char *in,
                       unsigned long long len, const unsigned char *k);
static int crypto_auth_verify(const unsigned char *h, const unsigned char *in,
                              unsigned long long len, const unsigned char *k);

/* Resolved through -I$(ASCON_C)/crypto_auth/asconmacv13/ref and
 * -I$(ASCON_C)/tests (for crypto_auth.h). */
#include "prf.c"

_Static_assert(CRYPTO_KEYBYTES == 16, "ascon-c variant must use a 128-bit key");
_Static_assert(CRYPTO_BYTES == 16, "ascon-c variant must produce a 128-bit tag");
_Static_assert(ASCON_VARIANT == 5, "ASCON_C must point at Ascon-Mac (variant 5)");

int ref_mac_ascon(uint8_t tag[16], const uint8_t *msg, size_t len, const uint8_t key[16]) {
    (void)crypto_auth_verify; // Cast unused to void
    
    const uint8_t empty = 0;
    return crypto_auth(tag, msg ? msg : &empty, (unsigned long long)len, key);
}

