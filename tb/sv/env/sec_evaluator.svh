// Evaluator: the expected DUT behaviour for a frame, from the DPI-C model
// (OpenSSL for AES-GCM / AES-CMAC, ascon-c for Ascon).
//
//   AEAD TX  m_axis = AD | CT | TAG          tag port = TAG
//   AEAD RX  m_axis = AD | PT                tag_ok   = model verified
//   MAC  TX  m_axis = MSG | TAG              tag port = TAG
//   MAC  RX  m_axis = MSG                    tag_ok   = (sent tag == model tag)
//
// On an AEAD RX frame that fails authentication the model releases no
// plaintext, so the payload bytes are not compared, only AD, length and tlast.
// The buffers are fixed size, as ref_mac_tag() in ref_dpi_pkg.sv does.

class sec_evaluator;
    byte unsigned k_b  [REF_MAC_KEY_BYTES];
    byte unsigned n_b  [REF_AEAD_MAX_NONCE_BYTES];
    byte unsigned ad_b [REF_MAC_MAX_BYTES];
    byte unsigned in_b [REF_MAC_MAX_BYTES];
    byte unsigned out_b[REF_MAC_MAX_BYTES];
    byte unsigned ti_b [REF_MAC_TAG_BYTES];
    byte unsigned to_b [REF_MAC_TAG_BYTES];

    // Library size check and the C side's own self tests
    function int init();
        return ref_mac_init_check();
    endfunction

    // Fills the exp_* and ref_* fields. Returns 0 if the model refused.
    function bit compute(sec_frame f);
        int rc;

        f.exp_stream = {};
        f.exp_care   = {};
        f.ref_out    = {};
        f.ref_err    = "";
        f.exp_ok     = 1'b0;
        foreach (f.exp_tag[i]) f.exp_tag[i] = 8'h00;

        if ((f.ad.size() > REF_MAC_MAX_BYTES) || (f.data.size() > REF_MAC_MAX_BYTES)) begin
            f.ref_err = "frame longer than REF_MAC_MAX_BYTES";
            return 1'b0;
        end

        foreach (f.key[i])   k_b[i]  = f.key[i];
        foreach (n_b[i])     n_b[i]  = (i < f.nonce.size()) ? f.nonce[i] : 8'h00;
        foreach (f.ad[i])    ad_b[i] = f.ad[i];
        foreach (f.data[i])  in_b[i] = f.data[i];
        foreach (ti_b[i])    ti_b[i] = (i < f.tag_in.size()) ? f.tag_in[i] : 8'h00;
        foreach (to_b[i])    to_b[i] = 8'h00;

        if (f.mode == 1'b1) begin
            rc = ref_aead_dpi(f.alg, int'(f.dir), k_b, n_b, f.nonce.size(), ad_b, f.ad.size(),
                              in_b, f.data.size(), ti_b, out_b, to_b);
            f.ref_rc = rc;

            if ((rc != REF_MAC_OK) && !((f.dir == 1'b1) && (rc == REF_MAC_ERR_AUTH))) begin
                f.ref_err = $sformatf("ref_aead_dpi returned %0d", rc);
                return 1'b0;
            end

            foreach (f.ad[i]) begin
                f.exp_stream.push_back(f.ad[i]);
                f.exp_care.push_back(1'b1);
            end

            if (f.dir == 1'b0) begin
                for (int i = 0; i < f.data.size(); i++) begin
                    f.ref_out.push_back(out_b[i]);
                    f.exp_stream.push_back(out_b[i]);
                    f.exp_care.push_back(1'b1);
                end
                foreach (to_b[i]) begin
                    f.exp_tag[i] = to_b[i];
                    f.exp_stream.push_back(to_b[i]);
                    f.exp_care.push_back(1'b1);
                end
            end else begin
                f.exp_ok = (rc == REF_MAC_OK);
                for (int i = 0; i < f.data.size(); i++) begin
                    if (f.exp_ok) f.ref_out.push_back(out_b[i]);
                    f.exp_stream.push_back(f.exp_ok ? out_b[i] : 8'h00);
                    f.exp_care.push_back(f.exp_ok);
                end
            end
        end else begin
            rc = ref_mac_dpi(f.alg, k_b, in_b, f.data.size(), to_b, REF_MAC_TAG_BYTES);
            f.ref_rc = rc;
            if (rc != REF_MAC_OK) begin
                f.ref_err = $sformatf("ref_mac_dpi returned %0d", rc);
                return 1'b0;
            end

            foreach (f.data[i]) begin
                f.exp_stream.push_back(f.data[i]);
                f.exp_care.push_back(1'b1);
            end
            foreach (to_b[i]) f.exp_tag[i] = to_b[i];

            if (f.dir == 1'b0) begin
                foreach (to_b[i]) begin
                    f.exp_stream.push_back(to_b[i]);
                    f.exp_care.push_back(1'b1);
                end
            end else begin
                f.exp_ok = (f.tag_in.size() == REF_MAC_TAG_BYTES);
                foreach (f.tag_in[i]) if (f.tag_in[i] != to_b[i]) f.exp_ok = 1'b0;
            end
        end
        return 1'b1;
    endfunction
endclass
