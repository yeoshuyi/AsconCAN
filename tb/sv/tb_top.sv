// Top level for TB

module tb_top;
    import sec_tb_pkg::*;

    parameter int ALG = 1; //0 for AES
    parameter bit AEAD_EN = 1'b1;
    parameter int GHASH_D = 4;
    localparam int TAG_BYTES = TB_TAG_BYTES;
    
    logic clk = 1'b0;
    always #5 clk = ~clk;

    tb_ctrl_if tbc(clk);
    axis_if #(.DATA_W(8), .USER_W(2)) s_axis();
    axis_if #(.DATA_W(8), .USER_W(2)) m_axis();
    axis_if #(.DATA_W(8), .USER_W(2)) key_axis();
    sec_ctrl_if #(.TAG_BYTES(16)) ctrl();

    initial begin
        tbc.rst     = 1'b1;
        ctrl.mode   = 1'b0;
        s_axis.tvalid = 1'b0;
        key_axis.tvalid = 1'b0;
        m_axis.tready = 1'b1;
    end

    sec_dut #(
        .ALG (ALG),
        .TAG_BYTES (TAG_BYTES),
        .AEAD_EN (AEAD_EN),
        .GHASH_D (GHASH_D)
    ) dut (
        .clk (clk),
        .rst (tbc.rst),
        .key (key_axis),
        .s_axis (s_axis),
        .m_axis (m_axis),
        .ctrl (ctrl)
    );

    assign tbc.have_key = dut.g_core.u_core.have_key;

    bind sec_dut axis_checker #(.NAME("m_axis")) u_m_axis_chk (
        .clk(clk),
        .rst(rst),
        .tdata(m_tdata),
        .tvalid(m_tvalid),
        .tready(m_axis.tready),
        .tlast(m_tlast)
    );

    bind sec_dut tag_checker #(.TAG_BYTES(TAG_BYTES)) u_tag_chk (
        .clk(clk),
        .rst(rst),
        .tag(tag),
        .tag_valid(tag_valid),
        .tag_ok(tag_ok)
    );

    sec_env env;

    initial begin
        if ((ALG != ALG_AES) && (ALG != ALG_ASCON)) $fatal(1, "Invalid Alg");
        env = new(ALG, AEAD_EN, s_axis, m_axis, key_axis, ctrl, tbc);
        env.run();
        $finish;
    end
endmodule
