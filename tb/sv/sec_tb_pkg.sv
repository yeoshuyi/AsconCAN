package sec_tb_pkg;
    import ref_mac_pkg::*;

    localparam int TB_TAG_BYTES = 16;

    localparam int ALG_AES      = 0;
    localparam int ALG_ASCON    = 1;

    // s_axis tuser, testbench convention. The cores look only at 2 (payload);
    // Ascon also uses 1 vs 2 to find the end of the associated data.
    localparam logic [1:0] TU_NONCE = 2'd0;
    localparam logic [1:0] TU_AD    = 2'd1;    // AD, or the whole MAC message
    localparam logic [1:0] TU_PT    = 2'd2;    // payload: PT on TX, CT on RX
    localparam logic [1:0] TU_TAG   = 2'd3;    // received tag, RX only

    typedef byte unsigned bq_t[$];

    // Bumped by the bound SVA checkers
    int unsigned g_sva_errors = 0;

    `include "sec_util.svh"
    `include "sec_txn.svh"
    `include "kat_reader.svh"
    `include "sec_evaluator.svh"
    `include "canxl_gen.svh"
    `include "sec_driver.svh"
    `include "sec_monitor.svh"
    `include "sec_scoreboard.svh"
    `include "sec_timer.svh"
    `include "sec_env.svh"
endpackage

