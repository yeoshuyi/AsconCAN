module ascon_mac #(
    // Secret key to be defined by top level
    parameter logic [127:0] SECRET_KEY = 127'd0,

    // IV based on 128b Key, 256b Rate, 12 Init Rnd, 12 Imm Rnd, 128b Tag
    parameter logic [63:0]  IV = 64'h80008C0000000080
)(
    input wire              clk,
    input wire              rst,
    input wire              sop,
    input wire              eop,

    output wire             tag_valid,
    output wire [127:0]     tag,

    input wire [255:0]      absorb_in,
    input wire              absorb_pulse
);
    // Function used to precompute initial state during compile-time 
    function automatic logic [319:0] ascon_p12(input logic[319:0] state_in);
        logic [63:0] x0, x1, x2, x3, x4;
        logic [63:0] t0, t1, t2, t3, t4;
        logic [7:0]  rc;
        int i;
        x0 = state_in[319:256];
        x1 = state_in[255:192];
        x2 = state_in[191:128];
        x3 = state_in[127:64];
        x4 = state_in[63:0];
        for (i = 0; i < 12; i = i + 1) begin
            case (i)
                0: rc = 8'hf0;  1: rc = 8'he1;  2: rc = 8'hd2;  3: rc = 8'hc3;
                4: rc = 8'hb4;  5: rc = 8'ha5;  6: rc = 8'h96;  7: rc = 8'h87;
                8: rc = 8'h78;  9: rc = 8'h69; 10: rc = 8'h5a; 11: rc = 8'h4b;
                default: rc = 8'h00;
            endcase

            x2 = x2 ^ {56'h0, rc};

            x0 = x0 ^ x4;  x4 = x4 ^ x3;  x2 = x2 ^ x1;
            t0 = ~x0;      t1 = ~x1;      t2 = ~x2;      t3 = ~x3;      t4 = ~x4;
            t0 = t0 & x1;  t1 = t1 & x2;  t2 = t2 & x3;  t3 = t3 & x4;  t4 = t4 & x0;
            x0 = x0 ^ t1;  x1 = x1 ^ t2;  x2 = x2 ^ t3;  x3 = x3 ^ t4;  x4 = x4 ^ t0;
            x1 = x1 ^ x0;  x0 = x0 ^ x4;  x3 = x3 ^ x2;  x2 = ~x2;

            x0 = x0 ^ ((x0 >> 19) | (x0 << 45)) ^ ((x0 >> 28) | (x0 << 36));
            x1 = x1 ^ ((x1 >> 61) | (x1 << 3))  ^ ((x1 >> 39) | (x1 << 25));
            x2 = x2 ^ ((x2 >> 1)  | (x2 << 63)) ^ ((x2 >> 6)  | (x2 << 58));
            x3 = x3 ^ ((x3 >> 10) | (x3 << 54)) ^ ((x3 >> 17) | (x3 << 47));
            x4 = x4 ^ ((x4 >> 7)  | (x4 << 57))  ^ ((x4 >> 41) | (x4 << 23));
        end
        return {x0, x1, x2, x3, x4};
    endfunction 

    // Initial State (Precalculated compile-time)
    localparam logic [319:0] INITIAL_STATE 
        = ascon_p12({IV, SECRET_KEY, 128'b0});

    typedef enum logic [1:0] {
        IDLE,
        ABSORB,
        PRE_SQUEEZE,
        SQUEEZE
    } state_t;

    // Internal Signal Declaration
    state_t current_state, next_state;
    logic [0:4][63:0]   s, next_s, abtr_s;
    logic [255:0]       abs, next_abs;
    logic               tag_valid_reg;
    logic [127:0]       tag_reg;
    logic               abs_en, abs_done;

    // Next Value Assignment
    always_ff @(posedge(clk)) begin
        if (rst == 1'b1) begin
            current_state   <= IDLE;
            s               <= INITIAL_STATE;
            abs             <= absorb_in;
        end else begin
            current_state   <= next_state;
            abs             <= next_abs;
            s <= (abs_done == 1'b1) ? next_s : s;
        end
    end

    // Combinational Control Logic
    always_comb begin
        next_state      = current_state;
        next_abs        = abs;
        abs_en          = 1'b0;
        tag_valid_reg   = 1'b0;
        tag_reg         = 128'd0;

        unique case (current_state)
            IDLE: begin
                next_state      = (sop == 1'b1) ? ABSORB : IDLE;
                if (sop == 1'b1) begin
                    abs_en      = 1'b1;
                    next_state  = ABSORB;
                    next_abs    = absorb_in;
                end
            end
            ABSORB: begin
                abs_en = 1'b1;
                if (eop == 1'b1) begin
                    next_state  = PRE_SQUEEZE;
                end else begin
                    if (absorb_pulse == 1'b1) begin
                        next_abs    = absorb_in;
                    end
                end
            end
            PRE_SQUEEZE: begin
                next_state      = SQUEEZE;
                abs_en          = 1'b0;
            end
            SQUEEZE: begin
                next_state      = IDLE;
                tag_valid_reg   = 1'b1;
                tag_reg         = s[319:192];
            end
            default: begin
                next_state      = IDLE;
            end
        endcase
    end

    // Ascon Permute (12 Rnds) Core
    assign abtr_s = (current_state == SQUEEZE) ? INITIAL_STATE : s;
    ascon_permute ascon_permute_inst (
        .clk(clk),
        .rst(rst),
        .en(abs_en),
        .done(abs_done),
        .state_in(abtr_s),
        .state_out(next_s)
    );

    // Output Assignment
    assign tag_valid    = tag_valid_reg;
    assign tag          = tag_reg;
endmodule
