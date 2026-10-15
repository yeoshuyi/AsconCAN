interface sec_ctrl_if #(
    parameter int TAG_BYTES = 16
);
    logic                   mode;       // 0 = integrity only, 1 = authenticated encryption
    logic                   dir;        // 0 = transmit, 1 = receive

    logic [8*TAG_BYTES-1:0] tag;
    logic                   tag_valid;
    logic                   tag_ok;     // receive: the tag that followed the frame matched

    modport core (
        input  mode, dir,
        output tag, tag_valid, tag_ok
    );

    modport host (
        output mode, dir,
        input  tag, tag_valid, tag_ok
    );

    modport monitor (
        input  mode, dir, tag, tag_valid, tag_ok
    );
endinterface

