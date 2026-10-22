// Environment: builds the components, reads the plusargs, runs the suites.
//
//   +SUITE=kat|rand|all     (all)
//   +SEED=<n>               (1)
//   +N_RAND=<n>             (300)    random CAN XL frames
//   +NEG=0|1                (1)      tampered RX copies of the KAT records
//   +BP_PCT / +GAP_PCT      (0 / 0)  m_axis backpressure / s_axis gaps, KAT suite
//   +RAND_BP_PCT / +RAND_GAP_PCT  (25 / 15)  the same, random suite
//   +VERBOSE                         print every passing frame
//   +INJECT_ERR[=<frame>]            TB self-test: corrupt one output byte (frame 2)
//   +MAX_FRAMES=<n>                  stop after n frames (debug)
//   +CLK_MHZ=<f>            (100)    for the us figures in the timer report
//   +TIMING_CSV=<path>
//   +KAT_ASCON_AEAD +KAT_ASCON_MAC +KAT_GCM_SPEC +KAT_CMAC_RFC
//   +KAT_GCM_ENC +KAT_GCM_DEC +KAT_CMAC_GEN +KAT_CMAC_VER     file paths

class sec_env;
    int             alg;
    bit             aead_en;

    sec_driver      drv;
    sec_monitor     mon;
    sec_evaluator   eval;
    sec_scoreboard  sb;
    sec_timer       tmr;
    canxl_gen       gen;

    virtual tb_ctrl_if t_vif;

    string          suite = "all";
    int             n_rand = 300;
    bit             neg_en = 1'b1;
    int             bp_pct = 0, gap_pct = 0;
    int             rand_bp_pct = 25, rand_gap_pct = 15;
    int             max_frames = -1;
    int             n_run = 0;
    int             n_timeouts = 0;

    bit             key_loaded = 1'b0;
    byte unsigned   cur_key [16];

    function new(int alg, bit aead_en,
                 virtual axis_if #(8, 2) s_vif, virtual axis_if #(8, 2) m_vif,
                 virtual axis_if #(8, 2) k_vif, virtual sec_ctrl_if #(.TAG_BYTES(16)) c_vif,
                 virtual tb_ctrl_if t_vif);
        this.alg     = alg;
        this.aead_en = aead_en;
        this.t_vif   = t_vif;

        drv = new();
        drv.s_vif = s_vif;
        drv.k_vif = k_vif;
        drv.c_vif = c_vif;
        drv.t_vif = t_vif;

        mon = new();
        mon.s_vif = s_vif;
        mon.m_vif = m_vif;
        mon.k_vif = k_vif;
        mon.c_vif = c_vif;
        mon.t_vif = t_vif;

        eval = new();
        sb   = new();
        tmr  = new();
    endfunction

    function string path_arg(string name, string dflt);
        string v;
        return $value$plusargs({name, "=%s"}, v) ? v : dflt;
    endfunction

    function void configure();
        int    v;
        real   r;
        string s;

        if ($value$plusargs("SUITE=%s", s)) suite = s;
        if ($value$plusargs("SEED=%d", v)) process::self().srandom(v);
        if ($value$plusargs("N_RAND=%d", v)) n_rand = v;
        if ($value$plusargs("NEG=%d", v)) neg_en = (v != 0);
        if ($value$plusargs("BP_PCT=%d", v)) bp_pct = v;
        if ($value$plusargs("GAP_PCT=%d", v)) gap_pct = v;
        if ($value$plusargs("RAND_BP_PCT=%d", v)) rand_bp_pct = v;
        if ($value$plusargs("RAND_GAP_PCT=%d", v)) rand_gap_pct = v;
        if ($value$plusargs("MAX_FRAMES=%d", v)) max_frames = v;
        if ($value$plusargs("CLK_MHZ=%f", r)) tmr.clk_mhz = r;
        if ($test$plusargs("VERBOSE")) sb.verbose = 1'b1;
        if ($value$plusargs("INJECT_ERR=%d", v)) mon.inject_frame = v;
        else if ($test$plusargs("INJECT_ERR")) mon.inject_frame = 2;
        tmr.open_csv(path_arg("TIMING_CSV", ""));

        gen = new(alg, aead_en, neg_en, eval);
    endfunction

    task reset_dut();
        drv.idle();
        t_vif.rst <= 1'b1;
        repeat (8) @(posedge t_vif.clk);
        t_vif.rst <= 1'b0;
        repeat (2) @(posedge t_vif.clk);
        key_loaded = 1'b0;
    endtask

    task ensure_key(sec_frame f);
        int n = 0;
        if (key_loaded && (cur_key == f.key)) return;

        mon.arm_key();
        drv.load_key(f.key);
        while (!mon.key_done && (n < 20000)) begin
            @(posedge t_vif.clk);
            n++;
        end
        if (!mon.key_done) begin
            $display("ERROR: have_key never rose after a key load (frame %s)", f.describe());
            mon.key_armed = 1'b0;
            return;
        end
        tmr.key_load(alg, mon.key_t1 - mon.key_t0);
        cur_key    = f.key;
        key_loaded = 1'b1;
    endtask

    task run_frame(sec_frame f);
        int n = 0;
        int tmo;

        if ((max_frames >= 0) && (n_run >= max_frames)) return;

        if (f.skip_why != "") begin
            sb.skip(f);
            return;
        end
        if (f.ref_err != "") begin
            sb.ref_fail(f, f.ref_err);
            return;
        end
        if (!eval.compute(f)) begin
            sb.ref_fail(f, f.ref_err);
            return;
        end
        void'(sb.ref_check(f));

        ensure_key(f);
        @(posedge t_vif.clk);

        tmo = 20000 + 64 * f.in_bytes();
        mon.arm(n_run);
        fork begin
            fork
                drv.send(f);
            join_none
            while (!mon.done && (n < tmo)) begin
                @(posedge t_vif.clk);
                n++;
            end
            disable fork;
        end join

        if (!mon.done) begin
            mon.obs.timeout = 1'b1;
            mon.armed       = 1'b0;
            n_timeouts++;
        end

        tmr.record(f, mon.obs, sb.check(f, mon.obs));
        if (mon.obs.timeout) reset_dut();

        n_run++;
        if ((n_run % 1000) == 0) $display("[%0t] %0d frames run", $time, n_run);
    endtask

    task run_queue(string name, sec_frame q[$]);
        $display("---- %s: %0d frames", name, q.size());
        foreach (q[i]) run_frame(q[i]);
    endtask

    // Reads one KAT source; a file that will not open is a failure
    task kat_file(string name, string path, int kind);
        sec_frame q[$];
        int n;
        case (kind)
            0: n = gen.lwc_aead(path, q);
            1: n = gen.lwc_mac(path, q);
            2: n = gen.cavp_gcm_enc(path, q);
            3: n = gen.cavp_gcm_dec(path, q);
            4: n = gen.cavp_cmac_gen(path, q);
            default: n = gen.cavp_cmac_ver(path, q);
        endcase
        if (n <= 0) begin
            sec_frame f = gen.new_frame("kat", path, kind != 1 && kind < 4, 1'b0, {});
            f.skip_why = "";
            sb.ref_fail(f, (n < 0) ? "cannot open KAT file" : "no records in KAT file");
            return;
        end
        run_queue({name, " (", str_basename(path), ", ", $sformatf("%0d records", n), ")"}, q);
    endtask

    task run_kat();
        mon.bp_pct  = bp_pct;
        drv.gap_pct = gap_pct;
        if (alg == ALG_ASCON) begin
            kat_file("Ascon-AEAD128 KAT", path_arg("KAT_ASCON_AEAD", ""), 0);
            kat_file("Ascon-MAC KAT", path_arg("KAT_ASCON_MAC", ""), 1);
        end else begin
            kat_file("AES-GCM spec", path_arg("KAT_GCM_SPEC", ""), 0);
            kat_file("AES-CMAC RFC 4493", path_arg("KAT_CMAC_RFC", ""), 1);
            kat_file("AES-GCM CAVP encrypt", path_arg("KAT_GCM_ENC", ""), 2);
            kat_file("AES-GCM CAVP decrypt", path_arg("KAT_GCM_DEC", ""), 3);
            kat_file("AES-CMAC CAVP generate", path_arg("KAT_CMAC_GEN", ""), 4);
            kat_file("AES-CMAC CAVP verify", path_arg("KAT_CMAC_VER", ""), 5);
        end
    endtask

    task run_rand();
        sec_frame q[$];
        mon.bp_pct  = rand_bp_pct;
        drv.gap_pct = rand_gap_pct;
        gen.random_frames(n_rand, q);
        run_queue($sformatf("random CAN XL (bp %0d%%, gaps %0d%%)", rand_bp_pct, rand_gap_pct), q);
    endtask

    task run();
        int rc;
        bit ok;

        configure();
        $display("==== CAN XL sec testbench: %s core, AEAD_EN=%0d, suite=%s",
                 alg_name(alg), aead_en, suite);

        rc = eval.init();
        if (rc != REF_MAC_OK) begin
            $display("ERROR: DPI-C reference model self-test failed (%0d)", rc);
            $display("TEST FAILED");
            return;
        end

        fork
            mon.run();
        join_none
        reset_dut();

        if ((suite == "kat") || (suite == "all")) run_kat();
        if ((suite == "rand") || (suite == "all")) run_rand();

        repeat (10) @(posedge t_vif.clk);
        tmr.report();
        tmr.close_csv();
        if (n_timeouts > 0) $display("timeouts: %0d (DUT reset after each)", n_timeouts);
        ok = sb.report();
    endtask
endclass
