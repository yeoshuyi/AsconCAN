// Ascon Keys
// Based on Ascon v1.3 for MAC, NIST SP 800-232 for AEAD

package ascon_pkg;
    
    // MAC: Variant 5, 12/12 Rounds, 128b Tag, 256b In / 128b Out Rate
    localparam logic [63:0] ASCON_MAC_IV    = 64'h0010200080CC0005;

    // AEAD: Variant 1, 12/8 rounds, 128b Tag, 128b Rate
    localparam logic [63:0] ASCON_AEAD_IV   = 64'h00001000808C0001;

endpackage
