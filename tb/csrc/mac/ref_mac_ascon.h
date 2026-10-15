#ifndef REF_MAC_ASCON_H_
#define REF_MAC_ASCON_H_

#include <stddef.h>
#include <stdint.h>

/* Ascon MAC Tag Generator, writes to tag and returns error code */
int ref_mac_ascon(uint8_t tag[16], const uint8_t *msg, size_t len, const uint8_t key[16]);

#endif
