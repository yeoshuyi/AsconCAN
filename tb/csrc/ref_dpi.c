/* DPI-C Hook for C Reference to SystemVerilog Testbench
 * Binds to ref_aead_core.h and ref_mac_core.h
 */

#include <stdio.h>
#include <string.h>

#include "svdpi.h"

#include "./mac/ref_mac_core.h"
#include "./aead/ref_aead_core.h"

/* svOpenArrayHandle Helpers */

// Get 1D Arr Size
static int arr_size(const svOpenArrayHandle h) {
    if (h == NULL || svDimensions(h) != 1) return -1;
    return svSize(h, 1);
}

// Read Arr
static int arr_read(const svOpenArrayHandle h, uint8_t *dst, int n) {
    const int low = svLow(h, 1);
    for (int i = 0; i < n; ++i) {
        const uint8_t *p = (const uint8_t *)svGetArrElemPtr1(h, low + i);
        if (p == NULL) return -1;
        dst[i] = *p;
    }
    return 0;
}

// Get Arr till n (Read arr with size guard)
static int arr_get(const svOpenArrayHandle h, uint8_t *dst, int n) {
    if (n==0) return 0;
    if (arr_size(h) < n) return -1;
    return arr_read(h, dst, n);
}

// Write Arr
static int arr_write(const svOpenArrayHandle h, uint8_t *src, int n) {
    const int low = svLow(h, 1);
    for (int i = 0; i < n; ++i) {
        uint8_t *p = (uint8_t *)svGetArrElemPtr1(h, low + i);
        if (p == NULL) return -1;
        *p = src[i];
    }
    return 0; 
}

/* Reference Models */
int ref_mac_dpi(int alg, const svOpenArrayHandle key, const svOpenArrayHandle msg,
                int msg_len, const svOpenArrayHandle tag, int tag_len) {
    uint8_t key_buf[REF_MAC_KEY_BYTES];
    uint8_t tag_buf[REF_MAC_TAG_BYTES];
    uint8_t msg_buf[REF_MAC_MAX_BYTES];
    const uint8_t *msg_p = NULL;
    int rc;

    /* Input Validation */
    if (msg_len < 0 || msg_len > REF_MAC_MAX_BYTES) return REF_MAC_ERR_LEN;
    if (tag_len < 1 || tag_len > REF_MAC_TAG_BYTES) return REF_MAC_ERR_TAG_LEN;
    if (arr_size(key) != REF_MAC_KEY_BYTES) return REF_MAC_ERR_DPI;
    if (arr_size(tag) < tag_len) return REF_MAC_ERR_DPI;

    if (arr_read(key, key_buf, REF_MAC_KEY_BYTES) != 0) return REF_MAC_ERR_DPI;

    if (msg_len > 0) {
        if (arr_size(msg) < msg_len) return REF_MAC_ERR_DPI;
        if (arr_read(msg, msg_buf, msg_len) != 0) return REF_MAC_ERR_DPI;
        msg_p = msg_buf;
    }

    rc = ref_mac_compute(alg, key_buf, msg_p, (size_t)msg_len, tag_buf, (size_t)tag_len);
    if (rc != REF_MAC_OK) return rc;
    if (arr_write(tag, tag_buf, tag_len) != 0) return REF_MAC_ERR_DPI;

    return REF_MAC_OK;
}

int ref_aead_dpi(int alg, int decrypt, const svOpenArrayHandle key,
                 const svOpenArrayHandle nonce, int nonce_len,
                 const svOpenArrayHandle ad, int ad_len,
                 const svOpenArrayHandle din, int in_len,
                 const svOpenArrayHandle tag_in,
                 const svOpenArrayHandle dout, const svOpenArrayHandle tag_out) {

    uint8_t key_buf[REF_MAC_KEY_BYTES];
    uint8_t nonce_buf[REF_AEAD_MAX_NONCE_BYTES];
    uint8_t tag_buf[REF_MAC_TAG_BYTES] = {0};
    static uint8_t ad_buf[REF_MAC_MAX_BYTES], in_buf[REF_MAC_MAX_BYTES], out_buf[REF_MAC_MAX_BYTES];
    int rc;

    if (ad_len < 0 || ad_len > REF_MAC_MAX_BYTES) return REF_MAC_ERR_LEN;
    if (in_len < 0 || in_len > REF_MAC_MAX_BYTES) return REF_MAC_ERR_LEN;
    if (nonce_len < 0 || nonce_len > REF_AEAD_MAX_NONCE_BYTES) return REF_MAC_ERR_NONCE;
    if (arr_size(key) != REF_MAC_KEY_BYTES) return REF_MAC_ERR_DPI;
    if (arr_size(tag_out) < REF_MAC_TAG_BYTES) return REF_MAC_ERR_DPI;
    if (in_len > 0 && arr_size(dout) < in_len) return REF_MAC_ERR_DPI;

    if (arr_read(key, key_buf, REF_MAC_KEY_BYTES) != 0) return REF_MAC_ERR_DPI;
    if (arr_get(nonce, nonce_buf, nonce_len) != 0) return REF_MAC_ERR_DPI;
    if (arr_get(ad, ad_buf, ad_len) != 0) return REF_MAC_ERR_DPI;
    if (arr_get(din, in_buf, in_len) != 0) return REF_MAC_ERR_DPI;
    if (decrypt && arr_get(tag_in, tag_buf, REF_MAC_TAG_BYTES) != 0) return REF_MAC_ERR_DPI;

    rc = ref_aead_compute(alg, decrypt, key_buf, nonce_buf, (size_t)nonce_len,
                          ad_buf, (size_t)ad_len, in_buf, (size_t)in_len,
                          out_buf, tag_buf);
    if (rc != REF_MAC_OK) return rc;

    if (in_len > 0 && arr_write(dout, out_buf, in_len) != 0) return REF_MAC_ERR_DPI;
    if (arr_write(tag_out, tag_buf, REF_MAC_TAG_BYTES) != 0) return REF_MAC_ERR_DPI;
    return REF_MAC_OK;
}

int ref_aead_selftest(void) {
    int rc = ref_aead_selftest_core();
    if (rc != REF_MAC_OK)
        fprintf(stderr, "ref_aead_selftest: FAILED (%d: %s)\n", rc, ref_mac_strerror(rc));
    return rc;
}

int ref_mac_selftest(void) {
    int rc = ref_mac_selftest_core();
    if (rc != REF_MAC_OK)
        fprintf(stderr, "ref_mac_selftest: FAILED (%d: %s)\n", rc, ref_mac_strerror(rc));
    return rc;
}

int ref_mac_max_bytes(void) { return REF_MAC_MAX_BYTES; }

