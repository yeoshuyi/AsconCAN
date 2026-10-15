// SystemVerilog Helper for MAC and AEAD C-Reference via DPI-C

package ref_mac_pkg;
    localparam int REF_MAC_MAX_BYTES = 4096;
    localparam int REF_MAC_KEY_BYTES = 16;
    localparam int REF_MAC_TAG_BYTES = 16;

    typedef enum int {
        REF_MAC_AES_CMAC  = 0,
        REF_MAC_ASCON_MAC = 1
    } ref_mac_alg_e;

    localparam int REF_MAC_OK           = 0;
    localparam int REF_MAC_ERR_ALG      = -1;  // unknown alg
    localparam int REF_MAC_ERR_ARG      = -2;  // NULL pointer (C side only)
    localparam int REF_MAC_ERR_LEN      = -3;  // msg_len < 0 or > REF_MAC_MAX_BYTES
    localparam int REF_MAC_ERR_TAG_LEN  = -4;  // tag_len not in 1..16
    localparam int REF_MAC_ERR_OPENSSL  = -5;
    localparam int REF_MAC_ERR_ASCON    = -6;
    localparam int REF_MAC_ERR_DPI      = -7;  // key size != 16, msg/tag array too small
    localparam int REF_MAC_ERR_SELFTEST = -8;
    localparam int REF_MAC_ERR_AUTH     = -9;  // AEAD decrypt: tag did not verify
    localparam int REF_MAC_ERR_NONCE    = -10; // AEAD: wrong nonce length

    typedef enum int {
        REF_AEAD_AES_GCM  = 0,
        REF_AEAD_ASCON128 = 1
    } ref_aead_alg_e;

    localparam int REF_AEAD_GCM_NONCE_BYTES   = 12;
    localparam int REF_AEAD_ASCON_NONCE_BYTES = 16;
    localparam int REF_AEAD_MAX_NONCE_BYTES   = 16;

    function automatic int ref_aead_nonce_bytes(input ref_aead_alg_e alg);
       return (alg == REF_AEAD_AES_GCM) ? REF_AEAD_GCM_NONCE_BYTES : REF_AEAD_ASCON_NONCE_BYTES;
    endfunction

    // MAC reference model
    import "DPI-C" function int ref_mac_dpi(
        input int               alg,
        input byte unsigned     key[],
        input byte unsigned     msg[],
        input int               msg_len,
        output byte unsigned    tag[],
        input int               tag_len
    );

    // AEAD reference model
    // decrypt = 0: dout = ciphertext, tag_out = tag
    // decrypt = 1: dout = plaintext, tag_out = tag_in
    import "DPI-C" function int ref_aead_dpi(
        input int               alg,
        input int               decrypt,
        input byte unsigned     key[],
        input byte unsigned     nonce[],
        input int               nonce_len,
        input byte unsigned     ad[],
        input int               ad_len,
        input byte unsigned     din[],
        input int               in_len,
        output byte unsigned    dout[],
        output byte unsigned    tag_out[]
    );

    import "DPI-C" function int ref_mac_selftest();
    import "DPI-C" function int ref_aead_selftest();
    import "DPI-C" function int ref_mac_max_bytes();
    
    function automatic int ref_mac_init_check();
        if (ref_mac_max_bytes() != REF_MAC_MAX_BYTES) begin
            $display("ref_mac_pkg: REF_MAC_MAX_BYTES is %0d in SV but %0d in the C library",
                     REF_MAC_MAX_BYTES, ref_mac_max_bytes());
            return REF_MAC_ERR_DPI;
        end
        if (ref_mac_selftest() != 0) return REF_MAC_ERR_SELFTEST;
        return ref_aead_selftest();
    endfunction

    function automatic int ref_mac_tag(
        input  ref_mac_alg_e alg,
        input  byte unsigned key[REF_MAC_KEY_BYTES],
        input  byte unsigned msg[],
        input  int           tag_len,
        output byte unsigned tag[REF_MAC_TAG_BYTES]
    );    
        byte unsigned msg_buf[REF_MAC_MAX_BYTES];
        foreach (tag[i]) tag[i] = 8'h00;
        if (msg.size() > REF_MAC_MAX_BYTES) return REF_MAC_ERR_LEN;
        foreach (msg[i]) msg_buf[i] = msg[i];
        return ref_mac_dpi(alg, key, msg_buf, msg.size(), tag, tag_len);
  endfunction
endpackage
