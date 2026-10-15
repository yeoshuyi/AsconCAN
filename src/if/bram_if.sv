interface bram_if #(
    parameter int ADDR_W = 32,
    parameter int DATA_W = 32
);
    logic [ADDR_W-1:0]      addr;
    logic [DATA_W-1:0]      din;        // write data, into the RAM
    logic [DATA_W-1:0]      dout;       // read data, out of the RAM
    logic                   en;
    logic [DATA_W/8-1:0]    we;

    modport master (
        output addr, din, en, we,
        input  dout
    );

    modport slave (
        input  addr, din, en, we,
        output dout
    );
endinterface

