module axis_checker #(
    parameter string NAME = "m_axis"
)(
    input logic         clk,
    input logic         rst,
    input logic [7:0]   tdata,
    input logic         tvalid,
    input logic         tready,
    input logic         tlast
);
    // A beat offered and not taken must stay offered, unchanged
    property p_hold;
        @(posedge clk) disable iff (rst)
        (tvalid && !tready) |=> (tvalid && $stable(tdata) && $stable(tlast));
    endproperty

    property p_known;
        @(posedge clk) disable iff (rst)
        tvalid |-> !$isunknown({tdata, tlast});
    endproperty

    property p_ctrl_known;
        @(posedge clk) disable iff (rst)
        !$isunknown({tvalid, tready});
    endproperty

    a_hold: assert property (p_hold) else begin
        sec_tb_pkg::g_sva_errors++;
        $error("[SVA] %s: beat changed or dropped before handshake", NAME);
    end

    a_known: assert property (p_known) else begin
        sec_tb_pkg::g_sva_errors++;
        $error("[SVA] %s: X/Z on tdata/tlast while tvalid", NAME);
    end

    a_ctrl_known: assert property (p_ctrl_known) else begin
        sec_tb_pkg::g_sva_errors++;
        $error("[SVA] %s: X/Z on tvalid/tready", NAME);
    end
endmodule

// Tag port sanity: no X on the result flags out of reset, and tag_ok only
// ever reports alongside tag_valid.
module tag_checker #(
    parameter int TAG_BYTES = 16
)(
    input logic                     clk,
    input logic                     rst,
    input logic [8*TAG_BYTES-1:0]   tag,
    input logic                     tag_valid,
    input logic                     tag_ok
);
    a_flags_known: assert property (@(posedge clk) disable iff (rst)
                                    !$isunknown({tag_valid, tag_ok})) else begin
        sec_tb_pkg::g_sva_errors++;
        $error("[SVA] tag: X/Z on tag_valid/tag_ok");
    end

    a_ok_needs_valid: assert property (@(posedge clk) disable iff (rst)
                                       tag_ok |-> tag_valid) else begin
        sec_tb_pkg::g_sva_errors++;
        $error("[SVA] tag: tag_ok high without tag_valid");
    end

    a_tag_known: assert property (@(posedge clk) disable iff (rst)
                                  tag_valid |-> !$isunknown(tag)) else begin
        sec_tb_pkg::g_sva_errors++;
        $error("[SVA] tag: X/Z on tag while tag_valid");
    end
endmodule

