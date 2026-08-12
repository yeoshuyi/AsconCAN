// Generic Ascon Round Module Supporting 5x64bit State
module ascon_round (
    // Input State
    input logic [63:0]  x0, x1, x2, x3, x4,
    // Round Constant
    input logic [7:0]   round_const,
    // Output state
    output logic [63:0] y0, y1, y2, y3, y4
    );

    // Intermediate Signal
    logic [63:0] c0, c1, c2, c3, c4;
    logic [63:0] r2, k2;
    logic [63:0] s0, s1, s2, s3, s4;
    logic [63:0] t0, t1, t2, t3, t4;

    always_comb begin
        // Optimized S-Box
        c2 = x2 ^ {56'h0, round_const}; // Constant Addition
        c0 = x0 ^ x4;
        c4 = x4 ^ x3;
        r2 = c2 ^ x1;

        s0 = c0 ^ (~x1 & r2);
        s1 = x1 ^ (~r2 & x3);
        s2 = r2 ^ (~x3 & c4);
        s3 = x3 ^ (~c4 & c0);
        s4 = c4 ^ (~c0 & x1);

        t1 = s1 ^ s0;
        t0 = s0 ^ s4;
        t3 = s3 ^ s2;
        t2 = ~s2;
        t4 = s4;
    end

    // Linear Diffusion
    assign y0 = t0 ^ {t0[18:0], t0[63:19]} ^ {t0[27:0], t0[63:28]};
    assign y1 = t1 ^ {t1[60:0], t1[63:61]} ^ {t1[38:0], t1[63:39]};
    assign y2 = t2 ^ {t2[0:0],  t2[63:1]}  ^ {t2[5:0],  t2[63:6]};
    assign y3 = t3 ^ {t3[9:0],  t3[63:10]} ^ {t3[16:0], t3[63:17]};
    assign y4 = t4 ^ {t4[6:0],  t4[63:7]}  ^ {t4[40:0], t4[63:41]};
endmodule
