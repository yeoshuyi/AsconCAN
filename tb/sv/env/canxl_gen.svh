// CAN XL frame generator.
//
// 1. KAT records -> frames, for every KAT format in use. Each AEAD/MAC KAT
//    record makes a TX frame and an RX frame, plus tampered RX copies when
//    negative tests are on.
//
// 2. Random CANsec-protected CAN XL frames. The header serialisation is a
//    testbench convention modelled on CiA 610-3 (CAN XL) and CiA 613-2
//    (CANsec), not a bit-exact implementation of either:
//
//      AD (14 bytes)
//        [0]     {SEC, 4'b0, PRIO[10:8]}
//        [1]     PRIO[7:0]
//        [2]     SDT
//        [3]     VCID
//        [4]     {5'b0, DLC[10:8]}       payload length = DLC + 1 (1..2048)
//        [5]     DLC[7:0]
//        [6:9]   AF, big endian
//        [10:13] FV (CANsec freshness value), big endian
//      Payload   DLC + 1 bytes
//      Nonce     SCI (8) | FV (4)               AES-GCM, 12 bytes
//                SCI (8) | FV (4) | 4'h0 bytes  Ascon,   16 bytes
//
//    Authenticated encryption: AD = header, PT = payload.
//    Authentication only:      MAC message = header | payload.

class canxl_frame;
    rand bit [10:0] prio;
    rand bit        sec;
    rand bit [7:0]  sdt;
    rand bit [7:0]  vcid;
    rand bit [10:0] dlc;
    rand bit [31:0] af;
    bit [31:0]      fv;
    bit [63:0]      sci;
    bq_t            payload;

    function bq_t header();
        bq_t h;
        h.push_back({sec, 4'b0, prio[10:8]});
        h.push_back(prio[7:0]);
        h.push_back(sdt);
        h.push_back(vcid);
        h.push_back({5'b0, dlc[10:8]});
        h.push_back(dlc[7:0]);
        for (int i = 3; i >= 0; i--) h.push_back(af[8*i +: 8]);
        for (int i = 3; i >= 0; i--) h.push_back(fv[8*i +: 8]);
        return h;
    endfunction

    function bq_t nonce(int alg);
        bq_t n;
        for (int i = 7; i >= 0; i--) n.push_back(sci[8*i +: 8]);
        for (int i = 3; i >= 0; i--) n.push_back(fv[8*i +: 8]);
        if (alg == ALG_ASCON) repeat (4) n.push_back(8'h00);
        return n;
    endfunction
endclass

class canxl_gen;
    int             alg;
    bit             aead_en;
    bit             neg_en;
    int             rx_bad_pct = 25;
    sec_evaluator   eval;
    int             next_id = 0;

    function new(int alg, bit aead_en, bit neg_en, sec_evaluator eval);
        this.alg     = alg;
        this.aead_en = aead_en;
        this.neg_en  = neg_en;
        this.eval    = eval;
    endfunction

    function int nonce_bytes();
        return (alg == ALG_AES) ? REF_AEAD_GCM_NONCE_BYTES : REF_AEAD_ASCON_NONCE_BYTES;
    endfunction

    function sec_frame new_frame(string suite, string src, bit mode, bit dir, bq_t key);
        sec_frame f = new();
        f.id    = next_id++;
        f.alg   = alg;
        f.suite = suite;
        f.src   = src;
        f.mode  = mode;
        f.dir   = dir;
        foreach (f.key[i]) f.key[i] = (i < key.size()) ? key[i] : 8'h00;
        if (key.size() != 16) f.skip_why = "key is not 128 bits";
        return f;
    endfunction

    // Frames the cores cannot be given: both need at least one data byte
    // after the nonce, because tlast rides on a data byte.
    function void check_framing(sec_frame f);
        if (f.skip_why != "") return;
        if (f.mode && !aead_en)
            f.skip_why = "core built MAC-only (AEAD_EN=0)";
        else if (f.mode && (f.ad.size() == 0) && (f.data.size() == 0))
            f.skip_why = "unframeable: empty AD and empty payload";
        else if (!f.mode && (f.data.size() == 0))
            f.skip_why = "unframeable: empty MAC message";
        else if ((f.ad.size() > REF_MAC_MAX_BYTES) || (f.data.size() > REF_MAC_MAX_BYTES))
            f.skip_why = "longer than REF_MAC_MAX_BYTES";
    endfunction

    function void push(sec_frame f, ref sec_frame q[$]);
        check_framing(f);
        q.push_back(f);
    endfunction

    // Tampered copies of a genuine RX frame
    function void add_negs(sec_frame rx, ref sec_frame q[$]);
        sec_frame c;
        if (!neg_en || (rx.skip_why != "")) return;

        c = rx.clone();
        c.id      = next_id++;
        c.neg     = NEG_TAG;
        c.kat_ok  = 0;
        c.kat_out = {};
        flip_bit(c.tag_in);
        push(c, q);

        if (rx.data.size() > 0) begin
            c = rx.clone();
            c.id      = next_id++;
            c.neg     = NEG_DATA;
            c.kat_ok  = 0;
            c.kat_out = {};
            flip_bit(c.data);
            push(c, q);
        end

        if (rx.mode && (rx.ad.size() > 0)) begin
            c = rx.clone();
            c.id      = next_id++;
            c.neg     = NEG_AD;
            c.kat_ok  = 0;
            c.kat_out = {};
            flip_bit(c.ad);
            push(c, q);
        end
    endfunction

    function sec_frame bad_record(string suite, kat_rec r, bit mode, bit dir, string why);
        bq_t none;
        sec_frame f = new_frame(suite, r.src, mode, dir, none);
        f.skip_why = "";
        f.ref_err  = {"malformed KAT record: ", why};
        return f;
    endfunction

    // ascon-c / NIST LWC AEAD file: CT carries the 16 byte tag on the end.
    // The AES GCM spec file uses the same layout.
    function int lwc_aead(string path, ref sec_frame q[$]);
        kat_rec recs[$];
        int n = kat_reader::read(path, recs);
        if (n <= 0) return n;

        foreach (recs[k]) begin
            kat_rec   r = recs[k];
            bq_t      key, nonce, pt, ad, ct, tag;
            sec_frame tx, rx;

            if (!(r.bytes("Key", key) && r.bytes("Nonce", nonce) && r.bytes("PT", pt)
                  && r.bytes("AD", ad) && r.bytes("CT", ct)) || (ct.size() != pt.size() + 16)) begin
                q.push_back(bad_record("kat", r, 1'b1, 1'b0, "fields missing or CT != PT + 16"));
                continue;
            end
            tag = bq_slice(ct, pt.size(), 16);
            ct  = bq_slice(ct, 0, pt.size());

            tx = new_frame("kat", r.src, 1'b1, 1'b0, key);
            tx.nonce   = nonce;
            tx.ad      = ad;
            tx.data    = pt;
            tx.has_kat = 1'b1;
            tx.kat_out = ct;
            tx.kat_tag = tag;
            if (nonce.size() != nonce_bytes()) tx.skip_why = "nonce length is not this core's";

            rx = tx.clone();
            rx.id      = next_id++;
            rx.dir     = 1'b1;
            rx.data    = ct;
            rx.tag_in  = tag;
            rx.kat_out = pt;
            rx.kat_tag = {};
            rx.kat_ok  = 1;

            push(tx, q);
            push(rx, q);
            add_negs(rx, q);
        end
        return n;
    endfunction

    // ascon-c LWC MAC file, or the RFC 4493 file in the same layout
    function int lwc_mac(string path, ref sec_frame q[$]);
        kat_rec recs[$];
        int n = kat_reader::read(path, recs);
        if (n <= 0) return n;

        foreach (recs[k]) begin
            kat_rec   r = recs[k];
            bq_t      key, msg, tag;
            sec_frame tx, rx;

            if (!(r.bytes("Key", key) && r.bytes("Msg", msg) && r.bytes("Tag", tag))
                || (tag.size() != 16)) begin
                q.push_back(bad_record("kat", r, 1'b0, 1'b0, "fields missing or tag != 16 bytes"));
                continue;
            end

            tx = new_frame("kat", r.src, 1'b0, 1'b0, key);
            tx.data    = msg;
            tx.has_kat = 1'b1;
            tx.kat_tag = tag;

            rx = tx.clone();
            rx.id      = next_id++;
            rx.dir     = 1'b1;
            rx.tag_in  = tag;
            rx.kat_tag = {};
            rx.kat_ok  = 1;

            push(tx, q);
            push(rx, q);
            add_negs(rx, q);
        end
        return n;
    endfunction

    // CAVP gcmEncryptExtIV128.rsp: TX. A truncated Tag is checked as a prefix.
    function int cavp_gcm_enc(string path, ref sec_frame q[$]);
        kat_rec recs[$];
        int n = kat_reader::read(path, recs);
        if (n <= 0) return n;

        foreach (recs[k]) begin
            kat_rec   r = recs[k];
            bq_t      key, iv, pt, aad, ct, tag;
            sec_frame tx;

            if (!(r.bytes("Key", key) && r.bytes("IV", iv) && r.bytes("PT", pt) && r.bytes("AAD", aad)
                  && r.bytes("CT", ct) && r.bytes("Tag", tag)) || (ct.size() != pt.size())
                || (tag.size() == 0) || (tag.size() > 16)) begin
                q.push_back(bad_record("kat", r, 1'b1, 1'b0, "fields missing or inconsistent"));
                continue;
            end

            tx = new_frame("kat", r.src, 1'b1, 1'b0, key);
            tx.nonce   = iv;
            tx.ad      = aad;
            tx.data    = pt;
            tx.has_kat = 1'b1;
            tx.kat_out = ct;
            tx.kat_tag = tag;
            if (iv.size() != REF_AEAD_GCM_NONCE_BYTES) tx.skip_why = "IV is not 96 bits";
            push(tx, q);
        end
        return n;
    endfunction

    // CAVP gcmDecrypt128.rsp: RX. FAIL records must be rejected.
    function int cavp_gcm_dec(string path, ref sec_frame q[$]);
        kat_rec recs[$];
        int n = kat_reader::read(path, recs);
        if (n <= 0) return n;

        foreach (recs[k]) begin
            kat_rec   r = recs[k];
            bq_t      key, iv, pt, aad, ct, tag;
            sec_frame rx;

            if (!(r.bytes("Key", key) && r.bytes("IV", iv) && r.bytes("AAD", aad)
                  && r.bytes("CT", ct) && r.bytes("Tag", tag))
                || (!r.fail && !(r.bytes("PT", pt) && (pt.size() == ct.size())))) begin
                q.push_back(bad_record("kat", r, 1'b1, 1'b1, "fields missing or inconsistent"));
                continue;
            end

            rx = new_frame("kat", r.src, 1'b1, 1'b1, key);
            rx.nonce   = iv;
            rx.ad      = aad;
            rx.data    = ct;
            rx.tag_in  = tag;
            rx.has_kat = 1'b1;
            rx.kat_ok  = r.fail ? 0 : 1;
            rx.kat_out = {};
            if (!r.fail) rx.kat_out = pt;
            rx.neg     = r.fail ? NEG_KAT : NEG_NONE;
            if (iv.size() != REF_AEAD_GCM_NONCE_BYTES)
                rx.skip_why = "IV is not 96 bits";
            else if (tag.size() != TB_TAG_BYTES)
                rx.skip_why = "truncated tag: RX verifies TAG_BYTES";
            push(rx, q);
        end
        return n;
    endfunction

    // CAVP CMACGenAES128.rsp: TX. Mlen = 0 is written as "Msg = 00".
    function int cavp_cmac_gen(string path, ref sec_frame q[$]);
        kat_rec recs[$];
        int n = kat_reader::read(path, recs);
        if (n <= 0) return n;

        foreach (recs[k]) begin
            kat_rec   r = recs[k];
            bq_t      key, msg, mac;
            int       mlen = r.num("Mlen");
            int       tlen = r.num("Tlen");
            sec_frame tx;

            if (!(r.bytes("Key", key) && r.bytes("Msg", msg) && r.bytes("Mac", mac))
                || (mlen < 0) || (mlen > msg.size()) || (tlen < 1) || (tlen > 16)
                || (tlen > mac.size())) begin
                q.push_back(bad_record("kat", r, 1'b0, 1'b0, "fields missing or inconsistent"));
                continue;
            end

            tx = new_frame("kat", r.src, 1'b0, 1'b0, key);
            tx.data    = bq_slice(msg, 0, mlen);
            tx.has_kat = 1'b1;
            tx.kat_tag = bq_slice(mac, 0, tlen);
            push(tx, q);
        end
        return n;
    endfunction

    // CAVP CMACVerAES128.rsp: RX, Result = P / F (reason)
    function int cavp_cmac_ver(string path, ref sec_frame q[$]);
        kat_rec recs[$];
        int n = kat_reader::read(path, recs);
        if (n <= 0) return n;

        foreach (recs[k]) begin
            kat_rec   r = recs[k];
            bq_t      key, msg, mac;
            int       mlen = r.num("Mlen");
            int       tlen = r.num("Tlen");
            string    res  = r.str("Result");
            bit       ok;
            sec_frame rx;

            if (!(r.bytes("Key", key) && r.bytes("Msg", msg) && r.bytes("Mac", mac))
                || (mlen < 0) || (mlen > msg.size()) || (tlen != mac.size()) || (res.len() == 0)) begin
                q.push_back(bad_record("kat", r, 1'b0, 1'b1, "fields missing or inconsistent"));
                continue;
            end
            ok = (res.getc(0) == "P");

            rx = new_frame("kat", r.src, 1'b0, 1'b1, key);
            rx.data    = bq_slice(msg, 0, mlen);
            rx.tag_in  = mac;
            rx.has_kat = 1'b1;
            rx.kat_ok  = ok;
            rx.neg     = ok ? NEG_NONE : NEG_KAT;
            if (tlen != TB_TAG_BYTES) rx.skip_why = "truncated tag: RX verifies TAG_BYTES";
            push(rx, q);
        end
        return n;
    endfunction

    // Payload lengths: block boundaries for both cores, then uniform
    function int pick_len();
        int edges[] = '{1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65,
                        127, 128, 129, 255, 256, 511, 512, 1023, 1024, 2047, 2048};
        int p = $urandom_range(99);
        if (p < 50) return edges[$urandom_range(edges.size() - 1)];
        if (p < 80) return $urandom_range(64, 1);
        return $urandom_range(2048, 1);
    endfunction

    function void rand_key(ref bq_t key, ref bit [63:0] sci);
        key = {};
        repeat (16) key.push_back(8'($urandom));
        sci = {$urandom, $urandom};
    endfunction

    // Random CANsec traffic. RX frames are built from what the model
    // transmits, and rx_bad_pct of them are tampered with in transit.
    function void random_frames(int n, ref sec_frame q[$]);
        bq_t        key;
        bit [63:0]  sci;
        bit [31:0]  fv = $urandom;

        rand_key(key, sci);
        for (int k = 0; k < n; k++) begin
            canxl_frame cf = new();
            sec_frame   tx, rx;
            bq_t        hdr, msg;
            bit         mode = aead_en ? 1'($urandom_range(1)) : 1'b0;
            bit         dir  = 1'($urandom_range(1));
            string      src;

            if ((k > 0) && ($urandom_range(99) < 10)) rand_key(key, sci);

            void'(cf.randomize());
            cf.dlc = 11'(pick_len() - 1);
            cf.sec = 1'b1;
            cf.fv  = fv++;
            cf.sci = sci;
            repeat (int'(cf.dlc) + 1) cf.payload.push_back(8'($urandom));
            hdr = cf.header();
            src = $sformatf("RAND %0d prio=%03h vcid=%02h dlc=%0d fv=%08h", k, cf.prio, cf.vcid,
                            cf.dlc, cf.fv);

            tx = new_frame("rand", src, mode, 1'b0, key);
            if (mode) begin
                tx.nonce = cf.nonce(alg);
                tx.ad    = hdr;
                tx.data  = cf.payload;
            end else begin
                msg = hdr;
                foreach (cf.payload[i]) msg.push_back(cf.payload[i]);
                tx.data = msg;
            end

            if (dir == 1'b0) begin
                push(tx, q);
                continue;
            end

            // What the far end would have put on the bus
            rx = tx.clone();
            rx.dir = 1'b1;
            if (!eval.compute(tx)) begin
                rx.ref_err = {"cannot build RX frame: ", tx.ref_err};
                q.push_back(rx);
                continue;
            end
            if (mode) rx.data = tx.ref_out;
            rx.tag_in = {};
            foreach (tx.exp_tag[i]) rx.tag_in.push_back(tx.exp_tag[i]);

            if ($urandom_range(99) < rx_bad_pct) begin
                int which = $urandom_range(mode ? 2 : 1);
                if (which == 0) begin
                    rx.neg = NEG_TAG;
                    flip_bit(rx.tag_in);
                end else if (which == 1) begin
                    rx.neg = NEG_DATA;
                    flip_bit(rx.data);
                end else begin
                    rx.neg = NEG_AD;
                    flip_bit(rx.ad);
                end
            end
            push(rx, q);
        end
    endfunction
endclass
