#logs the security core's switching for power analysis

set core ""
foreach s [get_scopes -r *] {
    if {[regexp {u_core\s*$} $s]} { set core $s; break }
}
if {$core eq ""} {
    puts "ERROR: SAIF: core scope u_core not found"
    quit
}

current_scope $core
open_saif core.saif
log_saif [get_objects -r *]
run -all
close_saif

# Vivado's SAIF reader rejects the escaped names, so rename the hierarchy to
# plain tb_top/dut/u_core (what fpga/util.tcl strips).
set fh [open core.saif r]; set txt [read $fh]; close $fh
regsub {\(INSTANCE\s+tb_top\\\(ALG\\=\d\\\)} $txt {(INSTANCE tb_top} txt
regsub {\(INSTANCE\s+g_core\\\.u_core} $txt {(INSTANCE u_core} txt
set fh [open core.saif w]; puts -nonewline $fh $txt; close $fh
quit
