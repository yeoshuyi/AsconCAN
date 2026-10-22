// DUT wrapper: one of the two cores behind the shared interfaces
// ALG follows the reference model enums: 0 = AES (GCM / CMAC), 1 = Ascon
module sec_dut #(
    parameter int ALG       = 1,
    parameter int TAG_BYTES = 16,
    parameter bit AEAD_EN   = 1'b1,
    parameter int GHASH_D   = 4
)(
    input logic         clk,
    input logic         rst,

    axis_if.sink        key,
    axis_if.sink        s_axis,
    axis_if.source      m_axis,
    sec_ctrl_if.core    ctrl
);
    // Core outputs as plain nets, so the protocol checker can bind to them
    wire [7:0]              m_tdata;
    wire                    m_tvalid;
    wire                    m_tlast;
    wire                    s_tready;
    wire                    k_tready;
    wire [8*TAG_BYTES-1:0]  tag;
    wire                    tag_valid;
    wire                    tag_ok;

    if (ALG == 0) begin : g_core
        aes_sec_axis #(
            .TAG_BYTES      (TAG_BYTES),
            .AEAD_EN        (AEAD_EN),
            .GHASH_D        (GHASH_D)
        ) u_core (
            .clk            (clk),
            .rst            (rst),
            .key_tdata      (key.tdata),
            .key_tvalid     (key.tvalid),
            .key_tready     (k_tready),
            .mode           (ctrl.mode),
            .dir            (ctrl.dir),
            .s_axis_tdata   (s_axis.tdata),
            .s_axis_tuser   (s_axis.tuser),
            .s_axis_tvalid  (s_axis.tvalid),
            .s_axis_tready  (s_tready),
            .s_axis_tlast   (s_axis.tlast),
            .m_axis_tdata   (m_tdata),
            .m_axis_tvalid  (m_tvalid),
            .m_axis_tready  (m_axis.tready),
            .m_axis_tlast   (m_tlast),
            .tag            (tag),
            .tag_valid      (tag_valid),
            .tag_ok         (tag_ok)
        );
    end else begin : g_core
        ascon_sec_axis #(
            .TAG_BYTES      (TAG_BYTES),
            .AEAD_EN        (AEAD_EN)
        ) u_core (
            .clk            (clk),
            .rst            (rst),
            .key_tdata      (key.tdata),
            .key_tvalid     (key.tvalid),
            .key_tready     (k_tready),
            .mode           (ctrl.mode),
            .dir            (ctrl.dir),
            .s_axis_tdata   (s_axis.tdata),
            .s_axis_tuser   (s_axis.tuser),
            .s_axis_tvalid  (s_axis.tvalid),
            .s_axis_tready  (s_tready),
            .s_axis_tlast   (s_axis.tlast),
            .m_axis_tdata   (m_tdata),
            .m_axis_tvalid  (m_tvalid),
            .m_axis_tready  (m_axis.tready),
            .m_axis_tlast   (m_tlast),
            .tag            (tag),
            .tag_valid      (tag_valid),
            .tag_ok         (tag_ok)
        );
    end

    assign key.tready       = k_tready;
    assign s_axis.tready    = s_tready;
    assign m_axis.tdata     = m_tdata;
    assign m_axis.tvalid    = m_tvalid;
    assign m_axis.tlast     = m_tlast;
    assign m_axis.tuser     = '0;
    assign ctrl.tag         = tag;
    assign ctrl.tag_valid   = tag_valid;
    assign ctrl.tag_ok      = tag_ok;
endmodule
