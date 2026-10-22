// Scoreboard: DUT against the DPI-C model, and the model against the KAT.
// The two kinds of failure are counted apart: "FAIL" is the DUT disagreeing
// with the model, "REF" is the model disagreeing with the KAT file (or
// refusing the frame), which says nothing about the DUT.

class sec_scoreboard;
    int unsigned    n_pass [string];
    int unsigned    n_fail [string];
    int unsigned    n_skip [string];
    int unsigned    n_ref  [string];
    int unsigned    skip_why [string];
    string          cats [$];

    int             max_print = 25;
    int unsigned    n_printed = 0;
    bit             verbose = 1'b0;

    function void touch(string c);
        if (!n_pass.exists(c)) begin
            n_pass[c] = 0;
            n_fail[c] = 0;
            n_skip[c] = 0;
            n_ref[c]  = 0;
            cats.push_back(c);
        end
    endfunction

    function void note(string tag, sec_frame f, string why);
        if (n_printed < max_print) begin
            $display("%s  %s: %s", tag, f.describe(), why);
            if (tag != "SKIP") begin
                $display("        key=%s nonce=%s", bq2hex(f.key), bq2hex(f.nonce));
                $display("        ad=%s", bq2hex(f.ad));
                $display("        data=%s tag_in=%s", bq2hex(f.data), bq2hex(f.tag_in));
            end
        end else if (n_printed == max_print) begin
            $display("....  further failure details suppressed");
        end
        n_printed++;
    endfunction

    function void skip(sec_frame f);
        touch(f.cat());
        n_skip[f.cat()]++;
        if (!skip_why.exists(f.skip_why)) skip_why[f.skip_why] = 0;
        skip_why[f.skip_why]++;
    endfunction

    function void ref_fail(sec_frame f, string why);
        touch(f.cat());
        n_ref[f.cat()]++;
        note("REF ", f, why);
    endfunction

    // Model against the KAT expectation. Returns 0 on a mismatch.
    function bit ref_check(sec_frame f);
        if (f.ref_err != "") begin
            ref_fail(f, f.ref_err);
            return 1'b0;
        end
        if ((f.neg != NEG_NONE) && f.exp_ok) begin
            ref_fail(f, "model accepted a tampered frame");
            return 1'b0;
        end
        if (!f.has_kat) return 1'b1;

        if (f.dir == 1'b0) begin
            if (f.mode && (f.ref_out != f.kat_out)) begin
                ref_fail(f, $sformatf("model CT %s, KAT %s", bq2hex(f.ref_out), bq2hex(f.kat_out)));
                return 1'b0;
            end
            foreach (f.kat_tag[i]) begin
                if (f.exp_tag[i] != f.kat_tag[i]) begin
                    bq_t t;
                    foreach (f.exp_tag[j]) t.push_back(f.exp_tag[j]);
                    ref_fail(f, $sformatf("model tag %s, KAT %s", bq2hex(t), bq2hex(f.kat_tag)));
                    return 1'b0;
                end
            end
        end else begin
            if ((f.kat_ok >= 0) && (int'(f.exp_ok) != f.kat_ok)) begin
                ref_fail(f, $sformatf("model verify=%0d, KAT says %0d", f.exp_ok, f.kat_ok));
                return 1'b0;
            end
            if (f.mode && f.exp_ok && (f.kat_out.size() > 0) && (f.ref_out != f.kat_out)) begin
                ref_fail(f, $sformatf("model PT %s, KAT %s", bq2hex(f.ref_out), bq2hex(f.kat_out)));
                return 1'b0;
            end
        end
        return 1'b1;
    endfunction

    function string region(sec_frame f, int i);
        int n_ad = f.mode ? f.ad.size() : 0;
        if (i < n_ad) return "AD";
        if (i < n_ad + f.data.size()) return f.mode ? "payload" : "message";
        return "tag";
    endfunction

    // DUT against the model. Returns 1 on a pass.
    function bit check(sec_frame f, sec_obs o);
        string why = "";
        int    n   = f.exp_stream.size();

        touch(f.cat());

        if (o.timeout) begin
            why = $sformatf("timeout: %0d of %0d input bytes taken, %0d output bytes, tag_valid=%0d",
                            o.s_beats, f.in_bytes(), o.out.size(), o.got_tag);
        end else if (!o.got_tag) begin
            why = "tag_valid never rose";
        end else if (o.out.size() != n) begin
            why = $sformatf("m_axis carried %0d bytes, expected %0d", o.out.size(), n);
        end else begin
            for (int i = 0; i < n; i++) begin
                if (f.exp_care[i] && (o.out[i] != f.exp_stream[i])) begin
                    why = $sformatf("m_axis byte %0d (%s) is %02x, expected %02x", i, region(f, i),
                                    o.out[i], f.exp_stream[i]);
                    break;
                end
            end
            if (why != "") begin
            end else if ((o.tlast_idx.size() != 1) || (o.tlast_idx[0] != n - 1)) begin
                why = $sformatf("m_axis tlast at %p, expected only at %0d", o.tlast_idx, n - 1);
            end else if (f.dir == 1'b0) begin
                for (int i = 0; i < TB_TAG_BYTES; i++) begin
                    if (o.tag_byte(i) != f.exp_tag[i]) begin
                        why = $sformatf("tag port byte %0d is %02x, expected %02x (tag=%032h)",
                                        i, o.tag_byte(i), f.exp_tag[i], o.tag);
                        break;
                    end
                end
                if ((why == "") && (o.tag_ok !== 1'b0)) why = "tag_ok raised on a transmit frame";
            end else if (o.tag_ok !== f.exp_ok) begin
                why = $sformatf("tag_ok=%0b, expected %0b", o.tag_ok, f.exp_ok);
            end
        end

        if (why == "") begin
            n_pass[f.cat()]++;
            if (verbose) $display("PASS  %s", f.describe());
            return 1'b1;
        end
        n_fail[f.cat()]++;
        note("FAIL", f, why);
        return 1'b0;
    endfunction

    function int unsigned total(ref int unsigned a [string]);
        int unsigned t = 0;
        foreach (a[k]) t += a[k];
        return t;
    endfunction

    // Prints the table; returns 1 if the run passed
    function bit report();
        int unsigned tp = total(n_pass);
        int unsigned tf = total(n_fail);
        int unsigned ts = total(n_skip);
        int unsigned tr = total(n_ref);
        bit ok;

        $display("");
        $display("==================== SCOREBOARD ====================");
        $display("%s %7s %7s %7s %7s", pad("category", 22), "pass", "FAIL", "REF", "skip");
        foreach (cats[i]) begin
            string c = cats[i];
            $display("%s %7d %7d %7d %7d", pad(c, 22), n_pass[c], n_fail[c], n_ref[c], n_skip[c]);
        end
        $display("%s %7d %7d %7d %7d", pad("total", 22), tp, tf, tr, ts);
        if (skip_why.size() > 0) begin
            $display("skipped records, by reason:");
            foreach (skip_why[w]) $display("  %6d  %s", skip_why[w], w);
        end
        $display("SVA protocol errors: %0d", g_sva_errors);

        ok = (tf == 0) && (tr == 0) && (g_sva_errors == 0) && (tp > 0);
        $display("====================================================");
        $display("%s", ok ? "TEST PASSED" : "TEST FAILED");
        return ok;
    endfunction
endclass
