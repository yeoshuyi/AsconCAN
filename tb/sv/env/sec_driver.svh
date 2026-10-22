// Drives the key stream and the frame on s_axis.
//
// The usual edge discipline: each beat is driven with a nonblocking
// assignment straight after a clock edge, and taken at the first later edge
// where tready is seen high (sampled before that edge's updates land).

class sec_driver;
    virtual axis_if #(8, 2)                 s_vif;
    virtual axis_if #(8, 2)                 k_vif;
    virtual sec_ctrl_if #(.TAG_BYTES(16))   c_vif;
    virtual tb_ctrl_if                      t_vif;

    int gap_pct = 0;    // chance of 1..3 idle cycles before a beat

    typedef struct {
        byte unsigned   data;
        logic [1:0]     user;
        bit             last;
    } beat_t;

    task idle();
        s_vif.tvalid    <= 1'b0;
        s_vif.tlast     <= 1'b0;
        s_vif.tdata     <= 8'h00;
        s_vif.tuser     <= TU_NONCE;
        k_vif.tvalid    <= 1'b0;
        k_vif.tdata     <= 8'h00;
        k_vif.tlast     <= 1'b0;
        k_vif.tuser     <= '0;
    endtask

    task load_key(byte unsigned key [16]);
        for (int i = 0; i < 16; i++) begin
            k_vif.tdata  <= key[i];
            k_vif.tvalid <= 1'b1;
            k_vif.tlast  <= (i == 15);
            do @(posedge t_vif.clk); while (k_vif.tready !== 1'b1);
        end
        k_vif.tvalid <= 1'b0;
        k_vif.tlast  <= 1'b0;
    endtask

    function void build(sec_frame f, ref beat_t q[$]);
        int n_data = f.ad.size() + f.data.size();
        int k = 0;
        q = {};
        foreach (f.nonce[i]) q.push_back('{f.nonce[i], TU_NONCE, 1'b0});
        foreach (f.ad[i]) begin
            k++;
            q.push_back('{f.ad[i], TU_AD, (k == n_data)});
        end
        foreach (f.data[i]) begin
            k++;
            q.push_back('{f.data[i], f.mode ? TU_PT : TU_AD, (k == n_data)});
        end
        foreach (f.tag_in[i]) q.push_back('{f.tag_in[i], TU_TAG, (i == f.tag_in.size() - 1)});
    endfunction

    task send(sec_frame f);
        beat_t q[$];
        build(f, q);

        c_vif.mode <= f.mode;
        c_vif.dir  <= f.dir;

        foreach (q[i]) begin
            if ((gap_pct > 0) && (i > 0) && ($urandom_range(99) < gap_pct)) begin
                s_vif.tvalid <= 1'b0;
                repeat ($urandom_range(3, 1)) @(posedge t_vif.clk);
            end
            s_vif.tdata  <= q[i].data;
            s_vif.tuser  <= q[i].user;
            s_vif.tlast  <= q[i].last;
            s_vif.tvalid <= 1'b1;
            do @(posedge t_vif.clk); while (s_vif.tready !== 1'b1);
        end
        s_vif.tvalid <= 1'b0;
        s_vif.tlast  <= 1'b0;
    endtask
endclass
