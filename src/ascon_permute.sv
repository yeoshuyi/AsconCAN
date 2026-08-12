module ascon_permute #(
    parameter ROUNDS = 12
)(
    input wire          clk,
    input wire          rst,
    input wire          en,

    output logic        done,

    input logic [319:0]  state_in,
    output logic [319:0] state_out
);
    localparam logic [7:0] ROUND_CONSTS [0:11] = {
        8'hf0, 8'he1, 8'hd2, 8'hc3,
        8'hb4, 8'ha5, 8'h96, 8'h87, 
        8'h78, 8'h69, 8'h5a, 8'h4b
    };
    localparam int ROUND_CONSTS_START = 12 - ROUNDS;

    typedef enum logic[0:0] {
        IDLE,
        RUN
    } state_t;

    state_t current_state, next_state;
    logic [3:0]  round_cnt, next_cnt;
    logic        load;
    logic [63:0] s [0:4];
    logic [63:0] y [0:4];
    logic [63:0] next_s [0:4];

    ascon_round ascon_round_inst (
        .x0(s[0]), .x1(s[1]), .x2(s[2]), .x3(s[3]), .x4(s[4]),
        .y0(y[0]), .y1(y[1]), .y2(y[2]), .y3(y[3]), .y4(y[4]),
        .round_const(ROUND_CONSTS[ROUND_CONSTS_START + round_count])
    );

    always_ff @(posedge(clk)) begin
        if (rst == 1'b1) begin
            round_cnt               <= 4'd0;
            current_state           <= IDLE;
            done                    <= 1'b0;
        end else begin
            round_cnt               <= next_cnt;
            current_state           <= next_state;
            done <= (current_state == RUN)
              && (round_cnt == ROUNDS[3:0] - 4'd1);
        end

        if (load || current_state == RUN)
            for (int i = 0; i < 5; i++)
                s[i] <= next_s[i];
    end

    always_comb begin
        next_state  = current_state;
        next_cnt    = round_cnt;
        load        = 1'b0;

        unique case(current_state)
            IDLE: begin
                next_cnt = 4'd0;
                if (en == 1'b1) begin
                    load =       1'b1;
                    next_state = RUN;
                end
            end
            RUN: begin
                if (round_cnt >= ROUNDS[3:0] - 4'd1) begin
                    next_cnt    = 4'd0;
                    next_state  = IDLE;
                end else begin
                    next_cnt = round_count + 4'd1;
                end
            end
        endcase
    end

    always_comb begin
        for (int i = 0; i < 5; i++)
            next_s[i] = load ? state_in[64*(4-i) +: 64] : y[i];
    end

    assign state_out = {s[0], s[1], s[2], s[3], s[4]};
endmodule

