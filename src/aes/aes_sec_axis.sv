module aes_sec_axis #(
    parameter int TAG_BYTES = 16,

    // 0 is MAC only
    parameter bit AEAD_EN = 1'b1,

    // bitrate of GHASH multiplier
    parameter int GHASH_D = 4
)(

    // same interface as ascon core
    input wire                      clk,
    input wire                      rst,

    input wire [7:0]                key_tdata,
    input wire                      key_tvalid,
    output wire                     key_tready,

    input wire                      mode,
    input wire                      dir,

    input wire [7:0]                s_axis_tdata,
    input wire [1:0]                s_axis_tuser,
    input wire                      s_axis_tvalid,
    output wire                     s_axis_tready,
    input wire                      s_axis_tlast,

    output wire [7:0]               m_axis_tdata,
    output wire                     m_axis_tvalid,
    input wire                      m_axis_tready,
    output wire                     m_axis_tlast,

    output wire [8*TAG_BYTES-1:0]   tag,
    output wire                     tag_valid,
    output wire                     tag_ok
);
    
    localparam int D        = GHASH_D;
    localparam int GS       = 8 / D; // cycles per byte
    localparam int MS       = 128 / D; // cycles per multiplication
    localparam int GS_BITS  = (GS > 1) ? $clog2(GS) : 1;
    localparam int TAG_BITS = 8 * TAG_BYTES;

    if ((GHASH_D != 1) && (GHASH_D != 2) && (GHASH_D != 4) && (GHASH_D != 8)) begin
        $error("GHASH_D must be 1, 2, 4 or 8");
    end

    localparam logic [3:0] ROW_RK10X    = 4'd10;
    localparam logic [3:0] ROW_RK10     = 4'd11;
    localparam logic [3:0] ROW_K1       = 4'd12;
    localparam logic [3:0] ROW_CTR      = 4'd15;

    localparam logic [127:0] ALPHA_254 = 128'he6080000000000000000000000000003;

    localparam logic [1:0] TUSER_PAYLOAD = 2'd2;

    // States
    typedef enum logic [4:0] {
        M_IDLE,
        // key
        M_KLOAD,        // 16 key bytes into row 0
        M_KEXP,         // expand rows 1..10
        M_KFIX,         // rows 11 and 15, and fold rk0 into row 10
        M_KL,           // L = E(0)
        M_KH,           // L into the hash key RAM
        M_KHOUT,        // H * alpha^127 back out of Z into the hash key RAM
        M_KDBL,         // K1 = dbl(L), K2 = dbl(K1)
        M_INIT,         // state := rk0, the standing offset
        M_INITW,
        // AES-CMAC frame
        M_STREAM,
        M_WAITBLK,
        M_SUBKEY,
        // AES-GCM frame
        M_NONCE,
        M_GSTREAM,
        M_GPAD,         // zero-fill the GHASH block
        M_GWAIT,        // E(J0) and the last multiplication
        // both
        M_WAITFIN,
        M_FEED,         // 16 bytes into Z
        M_FEEDW,
        M_RESTORE,      // row 15 back to rk0
        M_RESULT
    } mstate_t;

    typedef enum logic [1:0] {
        E_IDLE,
        E_INIT,
        E_ROUND
    } estate_t;

    typedef enum logic [1:0] {
        G_IDLE,
        G_ROT,          // rotate Z by a byte, XORing one in
        G_LOAD,
        G_MUL
    } gstate_t;

    typedef enum logic [1:0] {
        F_STATE,        // CMAC tag, or E(J0) onto the GHASH
        F_LEN,          // GCM length block
        F_CONST         // alpha^254, at key load
    } feed_t;

    // Mem block
    (* ram_style = "distributed" *)
    logic [7:0]         mem  [0:31];            // AES state
    (* ram_style = "distributed" *)
    logic [7:0]         kram [0:255];           // key store
    (* ram_style = "distributed" *)
    logic [7:0]         hram [0:15];            // hash key

    logic [127:0]       z;                      // GHASH accumulator / tag, z[k] = alpha^k
    logic [127:0]       a_reg;                  // GHASH operand

    // Signal
    mstate_t            m_state, next_m;
    estate_t            e_state;
    gstate_t            g_state;
    feed_t              feed_src, next_feed;

    // AES engine
    logic               half;                   // half of mem holding the state
    logic [3:0]         rnd;                    // round, 1..10
    logic [4:0]         cnt;                    // cycle within the round, 0..19
    logic [23:0]        col_a;
    logic [31:0]        col_b;
    logic               e_row_ctr, e_last_plain, e_rounds;
    logic               aes_go, aes_init, aes_row_ctr, aes_last_plain, aes_rounds;
    logic               aes_busy;

    logic [4:0]         mem_raddr, mem_waddr;
    logic [7:0]         rd, mem_wdata;
    logic               mem_we;
    logic [7:0]         k_addr;
    logic [7:0]         kq, k_wdata;
    logic               k_we;

    logic [3:0]         sr_idx, w_idx, rk_row;
    logic [7:0]         mc_byte, sbox_in;
    logic [7:0]         col_byte [0:3];
    logic [7:0]         b_cur, b_nxt, b_sum;
    logic               last_round, round_we;

    // One S-box, in LUT
    (* rom_style = "distributed" *)
    logic [7:0]         sbox_y;

    // GHASH engine
    logic [7:0]         gbyte;
    logic [6:0]         gstep;
    logic               gh_absorb, gh_mult, gh_clear, gh_busy;
    logic               z_clr, z_en;
    logic [7:0]         gh_data, hq, z_low, z_top;
    logic [D-1:0]       h_digit, d_digit;
    logic               h_we;

    // Sequencer
    logic [3:0]         idx, next_idx;          // byte index
    logic [2:0]         ms, next_ms;            // micro step
    logic [7:0]         kp, next_kp;            // key expansion pointer
    logic [7:0]         tmp, next_tmp;
    logic [7:0]         rcon;
    logic [7:0]         ctr, next_ctr;          // GCM block counter
    logic [11:0]        ad_cnt, next_ad_cnt;
    logic [11:0]        ct_cnt, next_ct_cnt;
    logic [3:0]         gcnt, next_gcnt;        // bytes in the GHASH block
    logic [3:0]         pad_idx, next_pad_idx;
    logic               pad_r, next_pad;        // final CMAC block was padded: K2
    logic               final_r, next_final;
    logic               mode_r, next_mode;
    logic               dir_r, next_dir;            // frame is being received
    logic               tag_bad, next_tag_bad;      // a received tag byte differed
    logic               have_key, next_have_key;
    logic               key_run, next_key_run;  // sequencer is loading a key
    logic [1:0]         dbl_top, next_dbl_top;      // top two bits of L
    logic [1:0]         dbl_c, next_dbl_c;          // bits carried up from the byte below
    logic               dbl_k2, next_dbl_k2;
    logic               in_pt, next_in_pt;      // payload has started
    logic               last_r, next_last;      // tlast has been accepted
    logic               blk_pend, next_blk_pend;    // GHASH block waits to be multiplied
    logic               need_j0, next_need_j0;      // E(J0) still to be started
    logic               tag_valid_reg, next_tag_valid;

    logic               is_payload;
    logic [7:0]         len_byte, dbl_out;

    logic               w_rnd, w_rd, w_k, w_s;      // state RAM write: round byte, itself, key store, s_axis
    logic [7:0]         w_small;                    // ... and a counter or pad byte
    logic               g_s, g_rd;                  // GHASH byte: s_axis, state RAM
    logic [7:0]         g_k;                        // ... or a constant
    logic               o_s, o_rd, o_z;             // m_axis: s_axis, state RAM, Z
    logic [14:0]        len_a, len_c;
    logic [TAG_BITS-1:0] tag_trunc;
    logic [127:0]       tag_full;

    logic               s_axis_tready_reg, key_tready_reg;
    logic               m_axis_tvalid_reg, m_axis_tlast_reg;
    logic [7:0]         m_axis_tdata_reg;

    // End flags
    assign is_payload   = (s_axis_tuser == TUSER_PAYLOAD);
    assign aes_busy     = (e_state != E_IDLE);
    assign gh_busy      = (g_state != G_IDLE);
    assign last_round   = (rnd == 4'd10);

    // AES Combinational Engine

    // Shift rows
    assign sr_idx   = {cnt[3:2] + cnt[1:0], cnt[1:0]};

    // Column c is written while column c+1 is read, so four cycles behind
    assign w_idx    = 4'(cnt - 5'd4);
    assign round_we = (e_state == E_ROUND) & (cnt >= 5'd4);

    // The S-box also serves the key expansion
    assign sbox_in  = (m_state == M_KEXP) ? tmp : rd;
    assign sbox_y   = aes_pkg::SBOX[sbox_in];

    // Round Constants
    always_comb begin
        unique case (kp[7:4])
            4'd1:    rcon = 8'h01;
            4'd2:    rcon = 8'h02;
            4'd3:    rcon = 8'h04;
            4'd4:    rcon = 8'h08;
            4'd5:    rcon = 8'h10;
            4'd6:    rcon = 8'h20;
            4'd7:    rcon = 8'h40;
            4'd8:    rcon = 8'h80;
            4'd9:    rcon = 8'h1b;
            default: rcon = 8'h36;
        endcase
    end

    // Mix Columns
    always_comb begin
        for (int j = 0; j < 4; j++) begin
            col_byte[j] = col_b[8*(3-j) +: 8];
        end
        b_cur   = col_byte[cnt[1:0]];
        b_nxt   = col_byte[cnt[1:0] + 2'd1];
        b_sum   = col_byte[0] ^ col_byte[1] ^ col_byte[2] ^ col_byte[3];
        mc_byte = b_sum ^ b_cur ^ aes_pkg::xtime(b_cur ^ b_nxt);
    end

    assign rk_row = (last_round == 1'b0) ? rnd
                  : (e_last_plain == 1'b1) ? ROW_RK10 : ROW_RK10X;

    assign rd = mem[mem_raddr];
    assign kq = kram[k_addr];
    assign hq = hram[(g_state == G_MUL) ? 4'(gstep >> $clog2(GS)) : idx];

    // AES Sequential
    always_ff @(posedge(clk)) begin
        if (mem_we == 1'b1) begin
            mem[mem_waddr] <= mem_wdata;
        end
        if (k_we == 1'b1) begin
            kram[k_addr] <= k_wdata;
        end
        if (h_we == 1'b1) begin
            hram[idx] <= (m_state == M_KH) ? rd : z_top;
        end
    end

     always_ff @(posedge(clk)) begin
        if (rst == 1'b1) begin
            e_state         <= E_IDLE;
            half            <= 1'b0;
            rnd             <= 4'd1;
            cnt             <= 5'd0;
            e_row_ctr       <= 1'b0;
            e_last_plain    <= 1'b0;
            e_rounds        <= 1'b0;
        end else begin
            unique case (e_state)
                E_IDLE: begin
                    if (aes_go == 1'b1) begin
                        e_row_ctr       <= aes_row_ctr;
                        e_last_plain    <= aes_last_plain;
                        e_rounds        <= aes_rounds;
                        rnd             <= 4'd1;
                        cnt             <= 5'd0;
                        e_state         <= (aes_init == 1'b1) ? E_INIT : E_ROUND;
                    end
                end

                // Load the state: rk0, or rk0 ^ counter block
                E_INIT: begin
                    cnt <= cnt + 5'd1;
                    if (cnt[3:0] == 4'd15) begin
                        cnt     <= 5'd0;
                        e_state <= (e_rounds == 1'b1) ? E_ROUND : E_IDLE;
                    end
                end

                E_ROUND: begin
                    cnt <= cnt + 5'd1;
                    if (cnt == 5'd19) begin
                        cnt     <= 5'd0;
                        half    <= ~half;
                        rnd     <= rnd + 4'd1;
                        if (last_round == 1'b1) begin
                            e_state <= E_IDLE;
                        end
                    end
                end

                default: begin
                    e_state <= E_IDLE;
                end
            endcase
        end
    end

    always_ff @(posedge(clk)) begin
        if (e_state == E_ROUND) begin
            col_a <= {col_a[15:0], sbox_y};
            if (cnt[1:0] == 2'd3) begin
                col_b <= {col_a, sbox_y};
            end
        end
    end

    // GHASH Engine
    function automatic logic [127:0] z_step(input logic [127:0] v,
                                            input logic [127:0] a,
                                            input logic [D-1:0] dig,
                                            input logic [D-1:0] hk,
                                            input logic         mul);
        logic [127:0] r;
        logic         low;
        r = v;
        for (int j = 0; j < D; j++) begin
            low     = r[0];
            r       = {low ^ dig[D - 1 - j], r[127:1]};
            r[6]    = r[6] ^ (low & mul);
            r[1]    = r[1] ^ (low & mul);
            r[0]    = r[0] ^ (low & mul);
            if (hk[D - 1 - j] == 1'b1) begin
                r = r ^ a;
            end
        end
        return r;
    endfunction

    always_comb begin
        for (int b = 0; b < 8; b++) begin
            z_low[7 - b] = z[b];
            z_top[7 - b] = z[120 + b];
        end
        // Hash key digit for this multiplication step, first bit first; data
        // digit for this rotation step. Each is zero outside its own state.
        h_digit = {D{1'b0}};
        d_digit = {D{1'b0}};
        if ((g_state == G_MUL) && (AEAD_EN == 1'b1)) begin
            h_digit = (GS == 1) ? hq[7 -: D]
                                : hq[7 - D * int'(gstep[GS_BITS-1:0]) -: D];
        end
        if (g_state == G_ROT) begin
            d_digit = (GS == 1) ? gbyte[7 -: D]
                                : gbyte[7 - D * int'(gstep[GS_BITS-1:0]) -: D];
        end
    end

    always_ff @(posedge(clk)) begin
        if (rst == 1'b1) begin
            g_state <= G_IDLE;
            gbyte   <= 8'd0;
            gstep   <= 7'd0;
        end else begin
            unique case (g_state)
                G_IDLE: begin
                    gstep <= 7'd0;
                    if (gh_absorb == 1'b1) begin
                        gbyte   <= gh_data;
                        g_state <= G_ROT;
                    end else if ((gh_mult == 1'b1) && (AEAD_EN == 1'b1)) begin
                        g_state <= G_LOAD;
                    end
                end

                G_ROT: begin
                    gstep   <= gstep + 7'd1;
                    if (gstep == 7'(GS - 1)) begin
                        g_state <= G_IDLE;
                    end
                end

                // The operand is what Z holds; the product builds up from zero
                G_LOAD: begin
                    gstep   <= 7'd0;
                    g_state <= G_MUL;
                end

                G_MUL: begin
                    gstep   <= gstep + 7'd1;
                    if (gstep == 7'(MS - 1)) begin
                        g_state <= G_IDLE;
                    end
                end

                default: begin
                    g_state <= G_IDLE;
                end
            endcase
        end
    end

    // Z on its own: a clear and an enable, which are the flip-flops' own
    // reset and clock enable pins, and one function in front of them
    assign z_clr = (rst == 1'b1) | (g_state == G_LOAD)
                 | ((g_state == G_IDLE) & gh_clear);
    assign z_en  = (g_state == G_ROT) | (g_state == G_MUL);

    always_ff @(posedge(clk)) begin
        if (z_clr == 1'b1) begin
            z <= 128'd0;
        end else if (z_en == 1'b1) begin
            z <= z_step(z, a_reg, d_digit, h_digit, (g_state == G_MUL) & AEAD_EN);
        end
    end

    always_ff @(posedge(clk)) begin
        if ((g_state == G_LOAD) && (AEAD_EN == 1'b1)) begin
            a_reg <= z;
        end
    end

    // Sequencer
    assign len_a = {ad_cnt, 3'b000};
    assign len_c = {ct_cnt, 3'b000};

    always_comb begin
        unique case (idx)
            4'd6:    len_byte = {1'b0, len_a[14:8]};
            4'd7:    len_byte = len_a[7:0];
            4'd14:   len_byte = {1'b0, len_c[14:8]};
            4'd15:   len_byte = len_c[7:0];
            default: len_byte = 8'h00;
        endcase

        if (dbl_k2 == 1'b0) begin
            dbl_out = {rd[6:0], dbl_c[1]};
            if ((idx == 4'd15) && (dbl_top[1] == 1'b1)) dbl_out = dbl_out ^ 8'h87;
        end else begin
            dbl_out = {rd[5:0], dbl_c};
            if ((idx == 4'd15) && (dbl_top[1] == 1'b1)) dbl_out = dbl_out ^ 8'h0e;
            if ((idx == 4'd15) && (dbl_top[0] == 1'b1)) dbl_out = dbl_out ^ 8'h87;
            if ((idx == 4'd14) && (dbl_top[1] == 1'b1)) dbl_out = dbl_out ^ 8'h01;
        end
    end

    // Next state assignment
    always_ff @(posedge(clk)) begin
        if (rst == 1'b1) begin
            m_state         <= M_IDLE;
            feed_src        <= F_STATE;
            idx             <= 4'd0;
            ms              <= 3'd0;
            kp              <= 8'd0;
            tmp             <= 8'd0;
            ctr             <= 8'd0;
            ad_cnt          <= 12'd0;
            ct_cnt          <= 12'd0;
            gcnt            <= 4'd0;
            pad_idx         <= 4'd0;
            pad_r           <= 1'b0;
            final_r         <= 1'b0;
            mode_r          <= 1'b0;
            dir_r           <= 1'b0;
            tag_bad         <= 1'b0;
            have_key        <= 1'b0;
            key_run         <= 1'b0;
            dbl_top         <= 2'd0;
            dbl_c           <= 2'd0;
            dbl_k2          <= 1'b0;
            in_pt           <= 1'b0;
            last_r          <= 1'b0;
            blk_pend        <= 1'b0;
            need_j0         <= 1'b0;
            tag_valid_reg   <= 1'b0;
        end else begin
            m_state         <= next_m;
            feed_src        <= next_feed;
            idx             <= next_idx;
            ms              <= next_ms;
            kp              <= next_kp;
            tmp             <= next_tmp;
            ctr             <= next_ctr;
            ad_cnt          <= next_ad_cnt;
            ct_cnt          <= next_ct_cnt;
            gcnt            <= next_gcnt;
            pad_idx         <= next_pad_idx;
            pad_r           <= next_pad;
            final_r         <= next_final;
            mode_r          <= next_mode;
            dir_r           <= next_dir;
            tag_bad         <= next_tag_bad;
            have_key        <= next_have_key;
            key_run         <= next_key_run;
            dbl_top         <= next_dbl_top;
            dbl_c           <= next_dbl_c;
            dbl_k2          <= next_dbl_k2;
            in_pt           <= next_in_pt;
            last_r          <= next_last;
            blk_pend        <= next_blk_pend;
            need_j0         <= next_need_j0;
            tag_valid_reg   <= next_tag_valid;
        end
    end

    // Memory Addressing
    always_comb begin
        mem_raddr   = {half, idx};
        mem_waddr   = {half, idx};
        k_addr      = {4'd0, idx};

        if (e_state == E_INIT) begin
            k_addr      = {(e_row_ctr == 1'b1) ? ROW_CTR : 4'd0, cnt[3:0]};
            mem_waddr   = {half, cnt[3:0]};
        end else if (e_state == E_ROUND) begin
            k_addr      = {rk_row, w_idx};
            mem_raddr   = {half, sr_idx};
            mem_waddr   = {~half, w_idx};
        end else begin
            unique case (m_state)
                // Key expansion: the byte it is derived from, the byte 16
                // back, then the byte itself
                M_KEXP: begin
                    if (ms == 3'd0) begin
                        k_addr = (kp[3:2] == 2'd0)
                               ? {kp[7:4] - 4'd1, 2'b11, kp[1:0] + 2'd1}
                               : {kp[7:4], kp[3:2] - 2'd1, kp[1:0]};
                    end else if (ms == 3'd2) begin
                        k_addr = {kp[7:4] - 4'd1, kp[3:0]};
                    end else begin
                        k_addr = kp;
                    end
                end
                M_KFIX: begin
                    unique case (ms)
                        3'd1:    k_addr = {ROW_RK10, idx};
                        3'd2:    k_addr = {4'd0, idx};
                        3'd3:    k_addr = {ROW_CTR, idx};
                        default: k_addr = {ROW_RK10X, idx};
                    endcase
                end
                M_KDBL: begin
                    k_addr = {ROW_K1 | {3'b000, dbl_k2}, idx};
                    if (ms == 3'd0) begin
                        mem_raddr = {half, 4'd0};
                    end
                end
                M_SUBKEY:   k_addr = {ROW_K1 | {3'b000, pad_r}, idx};
                M_NONCE:    k_addr = {ROW_CTR, idx};
                M_RESTORE:  k_addr = {(ms == 3'd0) ? 4'd0 : ROW_CTR, idx};
                M_GSTREAM:  mem_raddr = {half, gcnt};
                default:    k_addr = {4'd0, idx};
            endcase
        end
    end

    always_comb begin
        automatic logic acc  = 1'b0;    // s_axis byte taken this cycle
        automatic logic kacc = 1'b0;    // key byte taken this cycle

        next_m              = m_state;
        next_feed           = feed_src;
        next_idx            = idx;
        next_ms             = ms;
        next_kp             = kp;
        next_tmp            = tmp;
        next_ctr            = ctr;
        next_ad_cnt         = ad_cnt;
        next_ct_cnt         = ct_cnt;
        next_gcnt           = gcnt;
        next_pad_idx        = pad_idx;
        next_pad            = pad_r;
        next_final          = final_r;
        next_mode           = mode_r;
        next_dir            = dir_r;
        next_tag_bad        = tag_bad;
        next_have_key       = have_key;
        next_key_run        = key_run;
        next_dbl_top        = dbl_top;
        next_dbl_c          = dbl_c;
        next_dbl_k2         = dbl_k2;
        next_in_pt          = in_pt;
        next_last           = last_r;
        next_blk_pend       = blk_pend;
        next_need_j0        = need_j0;
        next_tag_valid      = tag_valid_reg;

        aes_go              = 1'b0;
        aes_init            = 1'b0;
        aes_row_ctr         = 1'b0;
        aes_last_plain      = 1'b0;
        aes_rounds          = 1'b1;

        gh_absorb           = 1'b0;
        gh_mult             = 1'b0;
        gh_clear            = 1'b0;
        g_s                 = 1'b0;
        g_rd                = 1'b0;
        g_k                 = 8'h00;
        h_we                = 1'b0;

        mem_we              = 1'b0;
        w_rnd               = 1'b0;
        w_rd                = 1'b0;
        w_k                 = 1'b0;
        w_s                 = 1'b0;
        w_small             = 8'h00;
        k_we                = 1'b0;
        k_wdata             = kq;

        s_axis_tready_reg   = 1'b0;
        key_tready_reg      = 1'b0;
        m_axis_tvalid_reg   = 1'b0;
        m_axis_tlast_reg    = 1'b0;
        o_s                 = 1'b1;
        o_rd                = 1'b0;
        o_z                 = 1'b0;

        if (e_state == E_INIT) begin
            mem_we      = 1'b1;
            w_k         = 1'b1;
            w_small     = ((e_row_ctr == 1'b1) && (cnt[3:0] == 4'd15)) ? ctr : 8'h00;
        end else if (e_state == E_ROUND) begin
            mem_we      = round_we;
            w_rnd       = 1'b1;
            w_k         = 1'b1;
        end

        if ((need_j0 == 1'b1) && (aes_busy == 1'b0)) begin
            aes_go          = 1'b1;
            aes_init        = 1'b1;
            aes_row_ctr     = 1'b1;
            aes_last_plain  = 1'b1;
            next_need_j0    = 1'b0;
        end

        if (blk_pend == 1'b1) begin
            if (gh_busy == 1'b0) begin
                gh_mult         = 1'b1;
                next_blk_pend   = 1'b0;
            end
        end else begin
            unique case (m_state)
                M_IDLE: begin
                    if (key_tvalid == 1'b1) begin
                        next_tag_valid  = 1'b0;
                        next_have_key   = 1'b0;
                        next_key_run    = 1'b1;
                        next_idx        = 4'd0;
                        next_m          = M_KLOAD;
                    end else if ((s_axis_tvalid == 1'b1) && (have_key == 1'b1)) begin
                        next_mode       = mode & AEAD_EN;
                        next_dir        = dir;
                        next_tag_bad    = 1'b0;
                        next_idx        = 4'd0;
                        next_final      = 1'b0;
                        next_last       = 1'b0;
                        next_in_pt      = 1'b0;
                        next_gcnt       = 4'd0;
                        next_ad_cnt     = 12'd0;
                        next_ct_cnt     = 12'd0;
                        next_tag_valid  = 1'b0;
                        next_m          = ((mode & AEAD_EN) == 1'b1) ? M_NONCE : M_STREAM;
                    end
                end

                M_KLOAD: begin
                    key_tready_reg  = 1'b1;
                    kacc            = key_tvalid;
                    k_wdata         = key_tdata;
                    k_we            = kacc;
                    if (kacc == 1'b1) begin
                        next_idx = idx + 4'd1;
                        if (idx == 4'd15) begin
                            next_kp     = 8'd16;
                            next_ms     = 3'd0;
                            next_m      = M_KEXP;
                        end
                    end
                end

                M_KEXP: begin
                    unique case (ms)
                        3'd0: begin
                            next_tmp    = kq;
                            next_ms     = 3'd1;
                        end
                        3'd1: begin
                            if (kp[3:2] == 2'd0) begin
                                next_tmp = sbox_y ^ ((kp[1:0] == 2'd0) ? rcon : 8'h00);
                            end
                            next_ms     = 3'd2;
                        end
                        3'd2: begin
                            next_tmp    = tmp ^ kq;
                            next_ms     = 3'd3;
                        end
                        default: begin
                            k_wdata     = tmp;
                            k_we        = 1'b1;
                            next_ms     = 3'd0;
                            next_kp     = kp + 8'd1;
                            if (kp == 8'd175) begin
                                next_idx    = 4'd0;
                                next_m      = M_KFIX;
                            end
                        end
                    endcase
                end

                M_KFIX: begin
                    next_ms = ms + 3'd1;
                    unique case (ms)
                        3'd0: begin
                            next_tmp    = kq;
                        end
                        3'd1: begin
                            k_wdata     = tmp;
                            k_we        = 1'b1;
                        end
                        3'd2: begin
                            next_tmp    = kq;
                        end
                        3'd3: begin
                            k_wdata     = tmp;
                            k_we        = 1'b1;
                        end
                        default: begin
                            k_wdata     = kq ^ tmp;
                            k_we        = 1'b1;
                            next_ms     = 3'd0;
                            next_idx    = idx + 4'd1;
                            if (idx == 4'd15) begin
                                // L = E(0): the state RAM is loaded with rk0
                                aes_go          = 1'b1;
                                aes_init        = 1'b1;
                                aes_last_plain  = 1'b1;
                                next_m          = M_KL;
                            end
                        end
                    endcase
                end

                M_KL: begin
                    if (aes_busy == 1'b0) begin
                        next_idx = 4'd0;
                        if (AEAD_EN == 1'b1) begin
                            next_m = M_KH;
                        end else begin
                            next_ms = 3'd0;
                            next_m  = M_KDBL;
                        end
                    end
                end

                M_KH: begin
                    h_we        = 1'b1;
                    next_idx    = idx + 4'd1;
                    if (idx == 4'd15) begin
                        gh_clear    = 1'b1;
                        next_feed   = F_CONST;
                        next_m      = M_FEED;
                    end
                end

                M_KHOUT: begin
                    if (gh_busy == 1'b0) begin
                        if (ms == 3'd0) begin
                            gh_absorb   = 1'b1;
                            next_ms     = 3'd1;
                        end else begin
                            h_we        = 1'b1;
                            next_ms     = 3'd0;
                            next_idx    = idx + 4'd1;
                            if (idx == 4'd15) begin
                                next_m = M_KDBL;
                            end
                        end
                    end
                end

                M_KDBL: begin
                    if (ms == 3'd0) begin
                        next_dbl_top    = rd[7:6];
                        next_dbl_c      = 2'd0;
                        next_idx        = 4'd15;
                        next_ms         = 3'd1;
                    end else begin
                        k_wdata         = dbl_out;
                        k_we            = 1'b1;
                        next_dbl_c      = rd[7:6];
                        next_idx        = idx - 4'd1;
                        if (idx == 4'd0) begin
                            next_dbl_c  = 2'd0;
                            next_dbl_k2 = ~dbl_k2;
                            if (dbl_k2 == 1'b1) begin
                                next_ms = 3'd0;
                                next_m  = M_INIT;
                            end
                        end
                    end
                end

                M_INIT: begin
                    if (aes_busy == 1'b0) begin
                        aes_go      = 1'b1;
                        aes_init    = 1'b1;
                        aes_rounds  = 1'b0;
                        next_m      = M_INITW;
                    end
                end

                M_INITW: begin
                    if (aes_busy == 1'b0) begin
                        if (key_run == 1'b1) begin
                            next_key_run    = 1'b0;
                            next_have_key   = 1'b1;
                            next_m          = M_IDLE;
                        end else begin
                            next_m          = M_RESULT;
                        end
                    end
                end

                M_STREAM: begin
                    s_axis_tready_reg   = m_axis_tready;
                    m_axis_tvalid_reg   = s_axis_tvalid;
                    m_axis_tlast_reg    = dir_r & s_axis_tlast;
                    acc                 = s_axis_tvalid & m_axis_tready;
                    mem_we              = acc;
                    w_rd                = 1'b1;
                    w_s                 = 1'b1;

                    if (acc == 1'b1) begin
                        next_idx = idx + 4'd1;
                        if (s_axis_tlast == 1'b1) begin
                            next_final      = 1'b1;
                            next_pad        = (idx != 4'd15);
                            next_pad_idx    = idx + 4'd1;
                            next_idx        = 4'd0;
                            next_m          = M_SUBKEY;
                        end else if (idx == 4'd15) begin
                            aes_go          = 1'b1;
                            next_m          = M_WAITBLK;
                        end
                    end
                end

                M_WAITBLK: begin
                    if (aes_busy == 1'b0) begin
                        next_idx    = 4'd0;
                        next_m      = M_STREAM;
                    end
                end

                M_SUBKEY: begin
                    mem_we      = 1'b1;
                    w_rd        = 1'b1;
                    w_k         = 1'b1;
                    w_small     = ((pad_r == 1'b1) && (idx == pad_idx)) ? 8'h80 : 8'h00;
                    next_idx    = idx + 4'd1;
                    if (idx == 4'd15) begin
                        aes_go          = 1'b1;
                        aes_last_plain  = 1'b1;
                        next_m          = M_WAITFIN;
                    end
                end

                M_NONCE: begin
                    s_axis_tready_reg   = 1'b1;
                    acc                 = s_axis_tvalid;
                    k_wdata             = kq ^ s_axis_tdata;
                    k_we                = acc;

                    if (acc == 1'b1) begin
                        next_idx = idx + 4'd1;
                        if (idx == 4'd11) begin
                            // Keystream for the first payload block, counter 2
                            next_ctr    = 8'd2;
                            gh_clear    = 1'b1;
                            next_m      = M_GWAIT;
                            next_ms     = 3'd0;
                        end
                    end
                end

                M_GWAIT: begin
                    if (ms == 3'd0) begin
                        aes_go          = 1'b1;
                        aes_init        = 1'b1;
                        aes_row_ctr     = 1'b1;
                        aes_last_plain  = 1'b1;
                        next_m          = M_GSTREAM;
                    end else if ((aes_busy == 1'b0) && (gh_busy == 1'b0)
                                 && (need_j0 == 1'b0)) begin
                        next_feed   = F_STATE;
                        next_idx    = 4'd0;
                        next_m      = M_FEED;
                    end
                end

                M_GSTREAM: begin
                    if (last_r == 1'b1) begin
                        // Zero-fill the last block, then the lengths
                        if (gcnt != 4'd0) begin
                            next_m      = M_GPAD;
                        end else begin
                            next_feed   = F_LEN;
                            next_idx    = 4'd0;
                                next_m      = M_FEED;
                        end
                    end else if (s_axis_tvalid == 1'b1) begin
                        if ((is_payload == 1'b1) && (in_pt == 1'b0)) begin
                            // End of the associated data
                            next_in_pt = 1'b1;
                            if (gcnt != 4'd0) begin
                                next_m = M_GPAD;
                            end
                        end else if (gh_busy == 1'b0) begin
                            if (is_payload == 1'b0) begin
                                s_axis_tready_reg   = m_axis_tready;
                                m_axis_tvalid_reg   = 1'b1;
                                m_axis_tlast_reg    = dir_r & s_axis_tlast;
                                g_s                 = 1'b1;
                            end else if (aes_busy == 1'b0) begin
                                s_axis_tready_reg   = m_axis_tready;
                                m_axis_tvalid_reg   = 1'b1;
                                o_rd                = 1'b1;
                                m_axis_tlast_reg    = dir_r & s_axis_tlast;
                                g_s                 = 1'b1;
                                g_rd                = ~dir_r;
                            end

                            acc = s_axis_tvalid & s_axis_tready_reg;
                            if (acc == 1'b1) begin
                                gh_absorb   = 1'b1;
                                next_gcnt   = gcnt + 4'd1;
                                next_last   = s_axis_tlast;
                                if (gcnt == 4'd15) begin
                                    next_blk_pend = 1'b1;
                                end

                                if (is_payload == 1'b1) begin
                                    next_ct_cnt = ct_cnt + 12'd1;
                                end else begin
                                    next_ad_cnt = ad_cnt + 12'd1;
                                end

                                if (s_axis_tlast == 1'b1) begin
                                    next_ctr        = 8'd1;
                                    next_need_j0    = 1'b1;
                                end else if ((is_payload == 1'b1) && (gcnt == 4'd15)) begin
                                    next_ctr        = ctr + 8'd1;
                                    next_ms         = 3'd0;
                                    next_m          = M_GWAIT;
                                end
                            end
                        end
                    end
                end

                M_GPAD: begin
                    if (gcnt == 4'd0) begin
                        next_m = M_GSTREAM;
                    end else if (gh_busy == 1'b0) begin
                        gh_absorb   = 1'b1;
                        next_gcnt   = gcnt + 4'd1;
                        if (gcnt == 4'd15) begin
                            next_blk_pend = 1'b1;
                        end
                    end
                end

                M_WAITFIN: begin
                    if (aes_busy == 1'b0) begin
                        gh_clear    = 1'b1;
                        next_feed   = F_STATE;
                        next_idx    = 4'd0;
                        next_m      = M_FEED;
                    end
                end

                M_FEED: begin
                    if (gh_busy == 1'b0) begin
                        unique case (feed_src)
                            F_LEN:   g_k  = len_byte;
                            F_CONST: g_k  = ALPHA_254[8*(15 - idx) +: 8];
                            default: g_rd = 1'b1;
                        endcase
                        if ((feed_src == F_STATE) && (dir_r == 1'b1)
                            && ({1'b0, idx} < TAG_BYTES[4:0])) begin
                            s_axis_tready_reg   = 1'b1;
                            gh_absorb           = s_axis_tvalid;
                            if ((s_axis_tvalid == 1'b1)
                                && (s_axis_tdata != (z_low ^ rd))) begin
                                next_tag_bad = 1'b1;
                            end
                        end else if ((feed_src == F_STATE)
                            && ({1'b0, idx} < TAG_BYTES[4:0])) begin
                            m_axis_tvalid_reg   = 1'b1;
                            o_s                 = 1'b0;
                            o_rd                = 1'b1;
                            o_z                 = 1'b1;
                            m_axis_tlast_reg    = ({1'b0, idx} == TAG_BYTES[4:0] - 5'd1);
                            gh_absorb           = m_axis_tready;
                        end else begin
                            gh_absorb           = 1'b1;
                        end

                        if (gh_absorb == 1'b1) begin
                            next_idx    = idx + 4'd1;
                            if (idx == 4'd15) begin
                                next_m = M_FEEDW;
                            end
                        end
                    end
                end

                M_FEEDW: begin
                    if (gh_busy == 1'b0) begin
                        next_idx    = 4'd0;
                        next_ms     = 3'd0;
                        unique case (feed_src)
                            F_CONST: begin
                                gh_mult = 1'b1;
                                next_m  = M_KHOUT;
                            end
                            F_LEN: begin
                                gh_mult = 1'b1;
                                next_ms = 3'd1;
                                next_m  = M_GWAIT;
                            end
                            // Z is the tag
                            default: begin
                                next_m  = (mode_r == 1'b1) ? M_RESTORE : M_INIT;
                            end
                        endcase
                    end
                end

                M_RESTORE: begin
                    if (ms == 3'd0) begin
                        next_tmp    = kq;
                        next_ms     = 3'd1;
                    end else begin
                        k_wdata     = tmp;
                        k_we        = 1'b1;
                        next_ms     = 3'd0;
                        next_idx    = idx + 4'd1;
                        if (idx == 4'd15) begin
                            next_m  = M_INIT;
                        end
                    end
                end

                M_RESULT: begin
                    next_tag_valid  = 1'b1;
                    next_m          = M_IDLE;
                end

                default: begin
                    next_m = M_IDLE;
                end
            endcase
        end
    end

    assign mem_wdata        = ((w_rnd == 1'b1) ? ((last_round == 1'b1) ? b_cur : mc_byte) : 8'h00)
                            ^ ((w_rd == 1'b1) ? rd : 8'h00)
                            ^ ((w_k == 1'b1) ? kq : 8'h00)
                            ^ ((w_s == 1'b1) ? s_axis_tdata : 8'h00)
                            ^ w_small;
    assign gh_data          = ((g_s == 1'b1) ? s_axis_tdata : 8'h00)
                            ^ ((g_rd == 1'b1) ? rd : 8'h00)
                            ^ g_k;
    assign m_axis_tdata_reg = ((o_s == 1'b1) ? s_axis_tdata : 8'h00)
                            ^ ((o_rd == 1'b1) ? rd : 8'h00)
                            ^ ((o_z == 1'b1) ? z_low : 8'h00);

    always_comb begin
        for (int b = 0; b < 128; b++) begin
            tag_full[127 - b] = z[b];
        end
    end
    assign tag_trunc = tag_full[127 -: TAG_BITS];

    assign tag_ok = tag_valid_reg & dir_r & ~tag_bad;

    // Output Assignment
    assign s_axis_tready    = s_axis_tready_reg;
    assign key_tready       = key_tready_reg;
    assign m_axis_tdata     = m_axis_tdata_reg;
    assign m_axis_tvalid    = m_axis_tvalid_reg;
    assign m_axis_tlast     = m_axis_tlast_reg;
    assign tag              = tag_trunc;
    assign tag_valid        = tag_valid_reg;
endmodule
