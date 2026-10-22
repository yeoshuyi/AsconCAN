// Watches every port once per clock edge (values as they were before the
// edge), collects m_axis beats and the tag result of the armed frame, and
// stamps the cycle of each event for the timer. It also drives m_axis_tready,
// with random backpressure when bp_pct > 0.

class sec_monitor;
    virtual axis_if #(8, 2)                 s_vif;
    virtual axis_if #(8, 2)                 m_vif;
    virtual axis_if #(8, 2)                 k_vif;
    virtual sec_ctrl_if #(.TAG_BYTES(16))   c_vif;
    virtual tb_ctrl_if                      t_vif;

    longint     cyc = 0;
    int         bp_pct = 0;
    int         inject_frame = -1;      // TB self-test: corrupt this frame's first byte

    sec_obs     obs;
    bit         armed;
    bit         done;
    int         frame_no;

    bit         key_armed;
    bit         key_done;
    longint     key_t0, key_t1;

    bit         prev_tv, prev_hk;

    function void arm(int frame_no);
        obs           = new();
        this.frame_no = frame_no;
        done          = 1'b0;
        armed         = 1'b1;
    endfunction

    function void arm_key();
        key_t0    = -1;
        key_t1    = -1;
        key_done  = 1'b0;
        key_armed = 1'b1;
    endfunction

    task run();
        m_vif.tready <= 1'b1;
        forever begin
            @(posedge t_vif.clk);
            cyc++;
            if (t_vif.rst !== 1'b0) begin
                prev_tv = 1'b0;
                prev_hk = 1'b0;
            end else begin
                sample();
                prev_tv = (c_vif.tag_valid === 1'b1);
                prev_hk = (t_vif.have_key === 1'b1);
            end
            m_vif.tready <= (bp_pct <= 0) || ($urandom_range(99) >= bp_pct);
        end
    endtask

    function void sample();
        if (key_armed) begin
            if ((k_vif.tvalid === 1'b1) && (k_vif.tready === 1'b1) && (key_t0 < 0)) key_t0 = cyc;
            if ((t_vif.have_key === 1'b1) && !prev_hk && (key_t0 >= 0)) begin
                key_t1    = cyc;
                key_done  = 1'b1;
                key_armed = 1'b0;
            end
        end

        if (!armed) return;

        if ((s_vif.tvalid === 1'b1) && (obs.t_offer < 0)) obs.t_offer = cyc;
        if (s_vif.tvalid === 1'b1) begin
            if (s_vif.tready === 1'b1) begin
                if (obs.t_first < 0) obs.t_first = cyc;
                obs.t_last_in = cyc;
                obs.s_beats++;
                if ((s_vif.tuser !== TU_TAG) && (s_vif.tlast === 1'b1)) obs.t_last_data = cyc;
            end else begin
                obs.s_stall++;
            end
        end

        if (m_vif.tvalid === 1'b1) begin
            if (m_vif.tready === 1'b1) begin
                byte unsigned b = m_vif.tdata;
                if ((frame_no == inject_frame) && (obs.out.size() == 0)) b ^= 8'h01;
                obs.out.push_back(b);
                if (m_vif.tlast === 1'b1) obs.tlast_idx.push_back(obs.out.size() - 1);
                obs.t_last_out = cyc;
            end else begin
                obs.m_stall++;
            end
        end

        if ((c_vif.tag_valid === 1'b1) && !prev_tv) begin
            obs.got_tag = 1'b1;
            obs.t_tag   = cyc;
            obs.tag     = c_vif.tag;
            obs.tag_ok  = c_vif.tag_ok;
        end

        // Done once the result is in and the output stream has ended, or a
        // while after the result if the stream never ends (the scoreboard
        // reports the missing tlast)
        if (obs.got_tag && ((obs.tlast_idx.size() > 0) || (cyc - obs.t_tag > 64))) begin
            done  = 1'b1;
            armed = 1'b0;
        end
    endfunction
endclass
