module ascon_sec_axis
    import ascon_pkg::*;
#(
    parameter int TAG_BYTES = 16,
    parameter bit AEAD_EN = 1'b1 // 0 is MAC-only core
)(
    input wire          clk,
    input wire          rst,

    input wire [7:0]    key_tdata,
    input wire          key_tvalid,
    output wire         key_tready,

    input wire          mode, // 0 is MAC, 1 is AEAD

    input wire          dir, // 0 is transmit, 1 is recieve

    input wire [7:0]    s_axis_tdata,
    input wire [1:0]    s_axis_tuser,
    input wire          s_axis_tvalid,
    output wire         s_axis_tready,
    input wire          s_axis_tlast,

    output wire [7:0]   m_axis_tdata,
    output wire         m_axis_tvalid,
    input wire          m_axis_tready,
    output wire         m_axis_tlast,

    output wire [8*TAG_BYTES-1:0] tag,
    output wire         tag_valid,
    output wire         tag_ok
);
    localparam int W = 8; //bits per word moved per cycle
    localparam int TAG_BITS = 8 * TAG_BYTES;

    localparam logic [4:0] TAG_ROT = (TAG_BYTES > 8) ? 5'd16 : 5'd8;
    localparam int ROT_A [0:4] = '{19, 61, 1, 10, 7};
    localparam int ROT_B [0:4] = '{28, 39, 6, 17, 41};

    localparam logic [1:0] TUSER_PAYLOAD = 2'd2;

    // States
    typedef enum logic [3:0] {
        IDLE,
        KEY,
        LOAD,
        NONCE,
        STREAM,
        PAD,
        PERM_S,
        PERM_L,
        TAG_OUT,
        RESULT
    } state_t;

    // Currently absorbed
    typedef enum logic [1:0] {
        PH_MAC  = 2'd0,
        PH_AD   = 2'd1,
        PH_PT   = 2'd2
    } phase_t;
    
    // Permutation
    typedef enum logic [2:0] {
        PD_STREAM,
        PD_AEAD_INIT,
        PD_AD_DONE,
        PD_MAC_TAG,
        PD_AEAD_TAG
    } pdone_t;

    state_t             current_state, next_state;
    phase_t             phase, next_phase;
    pdone_t             pdone, next_pdone;

    logic [63:0]        r [0:4];
    logic [63:0]        t [0:4];            // S-box output for this round
    logic [63:0]        k [0:1];            // key, circulating
    logic [2:0]         step, next_step;    // rotation phase: byte within the word
    logic [3:0]         round_cnt, next_round;
    logic [1:0]         word, next_word;    // state word being absorbed into
    logic [4:0]         tag_cnt, next_tag_cnt;

    logic               mode_r, next_mode;          // frame is encrypted
    logic               dir_r, next_dir;            // frame is being received
    logic               tag_bad, next_tag_bad;      // a received tag byte differed
    logic               have_key, next_have_key;
    logic               last_r, next_last;          // tlast has been accepted
    logic               padded, next_padded;        // pad byte has gone in
    logic               ad_empty, next_ad_empty;    // no associated data so far
    logic               dsep_pend, next_dsep;       // domain separator still to apply
    logic               perm_first, next_perm_first;
    logic               tag_valid_reg, next_tag_valid;

    logic               word_end, last_round, perm_active;
    logic               key_in, key_out;            // key rides along with this pass
    logic               rot;                        // the selected thing moves this cycle
    logic [4:0]         r_ce;
    logic               k_ce;
    logic               is_payload, phase_differs;
    logic [1:0]         rate_last;

    logic [W-1:0]       col_in  [0:4];      // W bit-columns entering the S-box
    logic [W-1:0]       col_out [0:4];
    logic [W-1:0]       lin_out [0:4];
    logic [W-1:0]       r_ins   [0:4];      // W bits inserted at the top of r
    logic [W-1:0]       t_ins   [0:4];
    logic [W-1:0]       k_head  [0:1];
    logic [W-1:0]       abs_head, iv_slice, abs_in;
    logic [W-1:0]       add_in  [0:4];
    logic               keep, out_head, out_data;
    logic [7:0]         rc;
    logic [W-1:0]       rc_slice, dsep_slice;

    logic [127:0]       tag_bytes;
    logic [TAG_BITS-1:0] tag_trunc;

    logic               s_axis_tready_reg, key_tready_reg;
    logic               m_axis_tvalid_reg, m_axis_tlast_reg;
    logic [7:0]         m_axis_tdata_reg;

    assign word_end     = (step == 3'd7);
    assign last_round   = (round_cnt == 4'd11);
    assign perm_active  = (current_state == PERM_S) | (current_state == PERM_L);

    // s_axis byte belongs to frame is payload, and is part of current absorbed frame
    assign is_payload    = mode_r & (s_axis_tuser == TUSER_PAYLOAD);
    assign phase_differs = mode_r & (s_axis_tuser != phase);

    assign rate_last     = (phase == PH_MAC) ? 2'd3 : 2'd1;

    assign key_in   = (current_state == PERM_S) & perm_first & (pdone == PD_AEAD_TAG);
    assign key_out  = (current_state == PERM_L) & last_round
                    & ((pdone == PD_AEAD_INIT) | (pdone == PD_AEAD_TAG));

    always_comb begin
        unique case (round_cnt)
            4'd0:    rc = 8'hf0;
            4'd1:    rc = 8'he1;
            4'd2:    rc = 8'hd2;
            4'd3:    rc = 8'hc3;
            4'd4:    rc = 8'hb4;
            4'd5:    rc = 8'ha5;
            4'd6:    rc = 8'h96;
            4'd7:    rc = 8'h87;
            4'd8:    rc = 8'h78;
            4'd9:    rc = 8'h69;
            4'd10:   rc = 8'h5a;
            default: rc = 8'h4b;
        endcase
    end

    assign rc_slice     = (step == 3'd0) ? rc : 8'h00;
    assign dsep_slice   = ((dsep_pend & perm_first & word_end) == 1'b1) ? 8'h80 : 8'h00;

    // Subtitution layer, bit-sliced, applied to W columns at a time
    always_comb begin
        automatic logic [W-1:0] x0, x1, x2, x3, x4;
        automatic logic [W-1:0] c0, c4, r2;
        automatic logic [W-1:0] s0, s1, s2, s3, s4;

        for (int i = 0; i < 5; i++) begin
            col_in[i] = r[i][W-1:0];
        end

        x0 = col_in[0];
        x1 = col_in[1];
        x2 = col_in[2] ^ rc_slice ^ ((key_in == 1'b1) ? k_head[0] : 8'h00);
        x3 = col_in[3] ^ ((key_in == 1'b1) ? k_head[1] : 8'h00);
        x4 = col_in[4] ^ dsep_slice;

        c0 = x0 ^ x4;
        c4 = x4 ^ x3;
        r2 = x2 ^ x1;

        s0 = c0 ^ (~x1 & r2);
        s1 = x1 ^ (~r2 & x3);
        s2 = r2 ^ (~x3 & c4);
        s3 = x3 ^ (~c4 & c0);
        s4 = c4 ^ (~c0 & x1);

        col_out[0] = s0 ^ s4;
        col_out[1] = s1 ^ s0;
        col_out[2] = ~s2;
        col_out[3] = s3 ^ s2;
        col_out[4] = s4;
    end

    // Linear diffusion layer
    always_comb begin
        automatic logic [127:0] tt;
        for (int i = 0; i < 5; i++) begin
            tt = {t[i], t[i]};
            lin_out[i] = tt[W-1:0] ^ tt[ROT_A[i] +: W] ^ tt[ROT_B[i] +: W];
        end
    end

    // Slice logic
    always_comb begin
        automatic logic [63:0] iv_word = (mode_r == 1'b1) ? ASCON_AEAD_IV : ASCON_MAC_IV;
        iv_slice    = iv_word[8*int'(step) +: 8];
        k_head[0]   = k[0][W-1:0];
        k_head[1]   = k[1][W-1:0];
        if (current_state == TAG_OUT) begin
            abs_head = (tag_cnt[3] == 1'b1) ? r[1][W-1:0] : r[0][W-1:0];
        end else begin
            abs_head = (word[0] == 1'b1) ? r[1][W-1:0] : r[0][W-1:0];
        end
    end

    // Input Arbitration
    always_comb begin
        if (current_state == PAD) begin
            abs_in = (padded == 1'b1) ? 8'h00 : 8'h01;
        end else begin
            abs_in = s_axis_tdata;
        end

        keep = ~((current_state == LOAD) | (current_state == NONCE)
                 | ((current_state == STREAM) & is_payload & dir_r));

        for (int i = 0; i < 5; i++) begin
            add_in[i] = abs_in;
        end
        if (current_state == LOAD) begin
            add_in[0] = iv_slice;
            add_in[1] = k_head[0];
            add_in[2] = k_head[1];
            add_in[3] = (mode_r == 1'b1) ? s_axis_tdata : 8'h00;
            add_in[4] = 8'h00;
        end
    end

    // Word shift logic
    always_comb begin
        for (int i = 0; i < 5; i++) begin
            automatic logic [W-1:0] head = r[i][W-1:0];

            if (current_state == PERM_L) begin
                r_ins[i] = lin_out[i];
                if (key_out == 1'b1) begin
                    if (pdone == PD_AEAD_INIT) begin
                        if (i == 3) r_ins[i] = lin_out[3] ^ k_head[0];
                        if (i == 4) r_ins[i] = lin_out[4] ^ k_head[1];
                    end else begin
                        if (i == 0) r_ins[i] = lin_out[3] ^ k_head[0];
                        if (i == 1) r_ins[i] = lin_out[4] ^ k_head[1];
                    end
                end
            end else if (current_state == TAG_OUT) begin
                r_ins[i] = head;
            end else begin
                r_ins[i] = ((keep == 1'b1) ? head : 8'h00) ^ add_in[i];
            end

            t_ins[i] = (current_state == PERM_S) ? col_out[i] : t[i][W-1:0];
        end
    end

    // Word rotation
    always_comb begin
        for (int i = 0; i < 5; i++) begin
            unique case (current_state)
                PERM_S, PERM_L: r_ce[i] = 1'b1;
                LOAD:           r_ce[i] = rot;
                NONCE:          r_ce[i] = rot & (i == 4);
                STREAM, PAD:    r_ce[i] = rot & (i < 4) & (word == i[1:0]);
                TAG_OUT:        r_ce[i] = rot & (i < 2) & (tag_cnt[3] == i[0]);
                default:        r_ce[i] = 1'b0;
            endcase
        end
        // The key goes round whenever it is being used
        k_ce = ((current_state == LOAD) & rot) | key_in | key_out;
    end

    // Shift register
    always_ff @(posedge(clk)) begin
        for (int i = 0; i < 5; i++) begin
            if (r_ce[i] == 1'b1) begin
                r[i] <= {r_ins[i], r[i][63:W]};
            end
        end
        if (perm_active == 1'b1) begin
            for (int i = 0; i < 5; i++) begin
                t[i] <= {t_ins[i], t[i][63:W]};
            end
        end
        if (current_state == KEY) begin
            if ((rot == 1'b1) && (word[0] == 1'b0)) k[0] <= {key_tdata, k[0][63:W]};
            if ((rot == 1'b1) && (word[0] == 1'b1)) k[1] <= {key_tdata, k[1][63:W]};
        end else if (k_ce == 1'b1) begin
            k[0] <= {k_head[0], k[0][63:W]};
            k[1] <= {k_head[1], k[1][63:W]};
        end
    end

    // State transition assignment
    always_ff @(posedge(clk)) begin
        if (rst == 1'b1) begin
            current_state   <= IDLE;
            phase           <= PH_MAC;
            pdone           <= PD_STREAM;
            step            <= 3'd0;
            round_cnt       <= 4'd0;
            word            <= 2'd0;
            tag_cnt         <= 5'd0;
            mode_r          <= 1'b0;
            dir_r           <= 1'b0;
            tag_bad         <= 1'b0;
            have_key        <= 1'b0;
            last_r          <= 1'b0;
            padded          <= 1'b0;
            ad_empty        <= 1'b0;
            dsep_pend       <= 1'b0;
            perm_first      <= 1'b0;
            tag_valid_reg   <= 1'b0;
        end else begin
            current_state   <= next_state;
            phase           <= next_phase;
            pdone           <= next_pdone;
            step            <= next_step;
            round_cnt       <= next_round;
            word            <= next_word;
            tag_cnt         <= next_tag_cnt;
            mode_r          <= next_mode;
            dir_r           <= next_dir;
            tag_bad         <= next_tag_bad;
            have_key        <= next_have_key;
            last_r          <= next_last;
            padded          <= next_padded;
            ad_empty        <= next_ad_empty;
            dsep_pend       <= next_dsep;
            perm_first      <= next_perm_first;
            tag_valid_reg   <= next_tag_valid;
        end
    end

    // Combinational State Logic
    always_comb begin
        next_state          = current_state;
        next_phase          = phase;
        next_pdone          = pdone;
        next_step           = step;
        next_round          = round_cnt;
        next_word           = word;
        next_tag_cnt        = tag_cnt;
        next_mode           = mode_r;
        next_dir            = dir_r;
        next_tag_bad        = tag_bad;
        next_have_key       = have_key;
        next_last           = last_r;
        next_padded         = padded;
        next_ad_empty       = ad_empty;
        next_dsep           = dsep_pend;
        next_perm_first     = perm_first;
        next_tag_valid      = tag_valid_reg;

        rot                 = 1'b0;

        s_axis_tready_reg   = 1'b0;
        key_tready_reg      = 1'b0;
        m_axis_tvalid_reg   = 1'b0;
        m_axis_tlast_reg    = 1'b0;

        // m_axis carries state ^ input, with either or both masked during phase
        out_head            = 1'b0;
        out_data            = 1'b1;

        unique case (current_state)

            IDLE: begin
                next_step = 3'd0;
                next_word = 2'd0;
                if (key_tvalid == 1'b1) begin
                    next_have_key   = 1'b0;
                    next_state      = KEY;
                end else if ((s_axis_tvalid == 1'b1) && (have_key == 1'b1)) begin
                    next_mode       = mode & AEAD_EN;
                    next_dir        = dir;
                    next_tag_bad    = 1'b0;
                    next_tag_cnt    = 5'd0;
                    next_last       = 1'b0;
                    next_padded     = 1'b0;
                    next_dsep       = 1'b0;
                    next_tag_valid  = 1'b0;
                    next_state      = LOAD;
                end
            end

            KEY: begin
                key_tready_reg  = 1'b1;
                rot             = key_tvalid;
                if (rot == 1'b1) begin
                    next_step = step + 3'd1;
                    if (word_end == 1'b1) begin
                        next_word = word + 2'd1;
                        if (word[0] == 1'b1) begin
                            next_have_key   = 1'b1;
                            next_state      = IDLE;
                        end
                    end
                end
            end

            LOAD: begin
                s_axis_tready_reg   = mode_r;
                rot                 = (mode_r == 1'b1) ? s_axis_tvalid : 1'b1;
                if (rot == 1'b1) begin
                    next_step = step + 3'd1;
                    if (word_end == 1'b1) begin
                        if (mode_r == 1'b1) begin
                            next_state      = NONCE;
                        end else begin
                            next_phase      = PH_MAC;
                            next_round      = 4'd0;
                            next_perm_first = 1'b1;
                            next_pdone      = PD_STREAM;
                            next_state      = PERM_S;
                        end
                    end
                end
            end

            NONCE: begin
                s_axis_tready_reg   = 1'b1;
                rot                 = s_axis_tvalid;
                if (rot == 1'b1) begin
                    next_step = step + 3'd1;
                    if (word_end == 1'b1) begin
                        next_round      = 4'd0;
                        next_perm_first = 1'b1;
                        next_pdone      = PD_AEAD_INIT;
                        next_state      = PERM_S;
                    end
                end
            end

            STREAM: begin
                if (last_r == 1'b1) begin
                    next_state = PAD;
                end else if (s_axis_tvalid == 1'b1) begin
                    if (phase_differs == 1'b1) begin
                        if ((phase == PH_AD) && (ad_empty == 1'b1)) begin
                            // bypass if no AD 
                            next_phase  = PH_PT;
                            next_dsep   = 1'b1;
                        end else begin
                            next_state  = PAD;
                        end
                    end else begin
                        s_axis_tready_reg   = m_axis_tready;
                        m_axis_tvalid_reg   = 1'b1;
                        out_head            = is_payload;
                        m_axis_tlast_reg    = dir_r & s_axis_tlast;
                        rot                 = m_axis_tready;

                        if (rot == 1'b1) begin
                            next_step       = step + 3'd1;
                            next_last       = s_axis_tlast;
                            next_ad_empty   = 1'b0;
                            if (word_end == 1'b1) begin
                                next_word = word + 2'd1;
                                if (word == rate_last) begin
                                    // Rate block full
                                    next_word       = 2'd0;
                                    next_round      = (phase == PH_MAC) ? 4'd0 : 4'd4;
                                    next_perm_first = 1'b1;
                                    next_pdone      = PD_STREAM;
                                    next_state      = PERM_S;
                                end
                            end
                        end
                    end
                end
            end

            PAD: begin
                rot         = 1'b1;
                next_step   = step + 3'd1;
                next_padded = 1'b1;

                if (word_end == 1'b1) begin
                    next_padded     = 1'b0;
                    next_word       = 2'd0;
                    next_perm_first = 1'b1;
                    next_state      = PERM_S;

                    unique case (phase)
                        PH_AD: begin
                            next_round  = 4'd4;
                            next_pdone  = PD_AD_DONE;
                        end
                        PH_PT: begin
                            next_round  = 4'd0;
                            next_pdone  = PD_AEAD_TAG;
                        end
                        default: begin
                            next_dsep   = 1'b1;
                            next_round  = 4'd0;
                            next_pdone  = PD_MAC_TAG;
                        end
                    endcase
                end
            end

            PERM_S: begin
                next_step = step + 3'd1;
                if (word_end == 1'b1) begin
                    // domain separator went in with this first pass
                    if (perm_first == 1'b1) begin
                        next_dsep = 1'b0;
                    end
                    next_perm_first = 1'b0;
                    next_state      = PERM_L;
                end
            end

            PERM_L: begin
                next_step = step + 3'd1;
                if (word_end == 1'b1) begin
                    if (last_round == 1'b0) begin
                        next_round  = round_cnt + 4'd1;
                        next_state  = PERM_S;
                    end else begin
                        unique case (pdone)
                            PD_AEAD_INIT: begin
                                next_phase      = PH_AD;
                                next_ad_empty   = 1'b1;
                                next_state      = STREAM;
                            end
                            PD_AD_DONE: begin
                                next_phase      = PH_PT;
                                next_dsep       = 1'b1;
                                next_state      = STREAM;
                            end
                            PD_MAC_TAG, PD_AEAD_TAG: begin
                                next_state      = TAG_OUT;
                            end
                            default: begin
                                next_state      = STREAM;
                            end
                        endcase
                    end
                end
            end

            TAG_OUT: begin
                if ((tag_cnt < TAG_BYTES[4:0]) && (dir_r == 1'b1)) begin
                    s_axis_tready_reg   = 1'b1;
                    rot                 = s_axis_tvalid;
                    if ((s_axis_tvalid == 1'b1) && (s_axis_tdata != abs_head)) begin
                        next_tag_bad = 1'b1;
                    end
                end else if (tag_cnt < TAG_BYTES[4:0]) begin
                    m_axis_tvalid_reg   = 1'b1;
                    out_head            = 1'b1;
                    out_data            = 1'b0;
                    m_axis_tlast_reg    = (tag_cnt == TAG_BYTES[4:0] - 5'd1);
                    rot                 = m_axis_tready;
                end else begin
                    rot                 = 1'b1;
                end

                if (rot == 1'b1) begin
                    next_tag_cnt = tag_cnt + 5'd1;
                    if (tag_cnt == TAG_ROT - 5'd1) begin
                        next_state = RESULT;
                    end
                end
            end

            RESULT: begin
                next_tag_valid  = 1'b1;
                next_state      = IDLE;
            end

            default: begin
                next_state = IDLE;
            end
        endcase
    end

    assign m_axis_tdata_reg = ((out_head == 1'b1) ? abs_head : 8'h00)
                            ^ ((out_data == 1'b1) ? s_axis_tdata : 8'h00);

    // Tag byte shifting to conform to interface
    always_comb begin
        for (int i = 0; i < 16; i++) begin
            tag_bytes[127 - 8*i -: 8] = r[i / 8][8*(i % 8) +: 8];
        end
    end
    assign tag_trunc = tag_bytes[127 -: TAG_BITS];

    // Integrity mode tag verified
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
