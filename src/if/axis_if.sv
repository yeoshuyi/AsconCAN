interface axis_if #(
    parameter int DATA_W = 8,
    parameter int USER_W = 2
);
    logic [DATA_W-1:0]  tdata;
    logic [USER_W-1:0]  tuser;
    logic               tvalid;
    logic               tready;
    logic               tlast;

    modport source (
        output tdata, tuser, tvalid, tlast,
        input  tready
    );

    modport sink (
        input  tdata, tuser, tvalid, tlast,
        output tready
    );

    modport monitor (
        input  tdata, tuser, tvalid, tready, tlast
    );
endinterface

