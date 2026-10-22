// One secured frame through the core, and what was seen coming back

typedef enum int {
    NEG_NONE,       // genuine frame
    NEG_TAG,        // RX: one tag bit flipped
    NEG_DATA,       // RX: one payload / MAC message byte flipped
    NEG_AD,         // RX: one associated data byte flipped
    NEG_KAT         // RX: the KAT file itself marks it as a failure
} neg_e;

class sec_frame;
    int             id;
    int             alg;
    bit             mode;               // 0 MAC, 1 AEAD
    bit             dir;                // 0 TX, 1 RX
    byte unsigned   key [16];
    bq_t            nonce;
    bq_t            ad;                 // AEAD only
    bq_t            data;               // AEAD: PT (TX) / CT (RX); MAC: the message
    bq_t            tag_in;             // RX: tag sent after the frame

    string          suite;              // "kat", "rand"
    string          src;                // where it came from, for messages
    neg_e           neg = NEG_NONE;
    string          skip_why = "";      // non-empty: counted, not run

    // From the KAT file
    bit             has_kat = 1'b0;
    bq_t            kat_out;            // AEAD: CT (TX) or PT (RX, when kat_ok)
    bq_t            kat_tag;            // TX: may be truncated
    int             kat_ok = -1;        // RX: 1 / 0, -1 unknown

    // From the evaluator (DPI-C model)
    int             ref_rc;
    bq_t            exp_stream;         // expected m_axis bytes
    bit             exp_care [$];       // 0: byte not compared
    byte unsigned   exp_tag [16];
    bit             exp_ok;
    bq_t            ref_out;            // CT (TX) or PT (RX) from the model
    string          ref_err = "";

    function string kind();
        return {mode ? "AEAD" : "MAC", "/", dir ? "RX" : "TX"};
    endfunction

    function string cat();
        return {suite, "/", kind(), (neg != NEG_NONE) ? "-neg" : ""};
    endfunction

    function int in_bytes();
        return nonce.size() + ad.size() + data.size() + tag_in.size();
    endfunction

    function sec_frame clone();
        sec_frame c = new this;
        return c;
    endfunction

    function string describe();
        return $sformatf("#%0d %s %s %s ad=%0d len=%0d%s", id, cat(), mode_name(alg, mode),
                         src, ad.size(), data.size(),
                         (neg != NEG_NONE) ? $sformatf(" neg=%s", neg.name()) : "");
    endfunction
endclass

class sec_obs;
    bq_t            out;
    int             tlast_idx [$];
    bit             got_tag;
    logic [127:0]   tag;
    logic           tag_ok;
    bit             timeout;

    // Cycle stamps, from the monitor's own counter
    longint         t_offer     = -1;   // first cycle s_axis_tvalid was up
    longint         t_first     = -1;   // first s_axis handshake
    longint         t_last_data = -1;   // handshake of the data byte with tlast
    longint         t_last_in   = -1;   // last s_axis handshake (incl. RX tag)
    longint         t_last_out  = -1;   // last m_axis handshake
    longint         t_tag       = -1;   // tag_valid rose
    int             s_stall;            // s_axis tvalid & !tready
    int             m_stall;            // m_axis tvalid & !tready
    int             s_beats;

    function byte unsigned tag_byte(int i);
        return tag[127 - 8*i -: 8];
    endfunction
endclass
