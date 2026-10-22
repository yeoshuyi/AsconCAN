# Out-of-context area, timing, Fmax and power for one security core.
#
#   vivado -mode batch -nojournal -nolog -source fpga/util.tcl -tclargs <ascon|aes> [options]
#
# Options (any order):
#   impl              place and route as well (real area, timing at PERIOD)
#   power             report_power after route (implies impl)
#   fmax              sweep the clock period after route to find Fmax (implies impl)
#   period=<ns>       clock period for synthesis and impl (default 10.0 = 100 MHz)
#   saif=<path>       switching activity for power, from `make -C tb sim SAIF=1`
#                     (implies power)
#   generic=<K>=<V>   core parameter, e.g. generic=AEAD_EN=0 generic=GHASH_D=8


set alg      [lindex $argv 0]
set impl     0
set do_power 0
set do_fmax  0
set period   10.0
set saif     ""
set generics {}

if {$alg ni {ascon aes}} {
    puts "usage: -tclargs <ascon|aes> \[impl\] \[power\] \[fmax\] \[period=<ns>\] \[saif=<path>\] \[generic=K=V ...\]"
    exit 1
}
foreach a [lrange $argv 1 end] {
    switch -glob -- $a {
        impl        { set impl 1 }
        power       { set do_power 1 }
        fmax        { set do_fmax 1 }
        period=*    { set period [string range $a 7 end] }
        saif=*      { set saif [file normalize [string range $a 5 end]] }
        generic=*   { lappend generics -generic [string range $a 8 end] }
        default     { puts "unknown option: $a"; exit 1 }
    }
}
if {$saif ne ""} { set do_power 1 }
if {$do_power || $do_fmax} { set impl 1 }

set part xc7s25csga324-1                
set root [file normalize [file join [file dirname [info script]] ..]]
set out  $root/fpga/reports/$alg
file mkdir $out
cd $out                                 
set summary {}

proc wns {} {
    set p [get_timing_paths -delay_type max -max_paths 1]
    if {$p eq ""} { return 0.0 }
    return [get_property SLACK $p]
}

proc grab {text pattern} {
    if {[regexp $pattern $text -> v]} { return [string trim $v] }
    return "?"
}

proc area_lines {} {
    set u [report_utilization -return_string]
    set l {}
    lappend l "  LUTs        [grab $u {\|\s*Slice LUTs\*?\s*\|\s*([0-9.]+)}]"
    lappend l "  LUT as mem  [grab $u {\|\s*LUT as Memory\s*\|\s*([0-9.]+)}]"
    lappend l "  FFs         [grab $u {\|\s*Slice Registers\s*\|\s*([0-9.]+)}]"
    lappend l "  BRAM tiles  [grab $u {\|\s*Block RAM Tile\s*\|\s*([0-9.]+)}]"
    lappend l "  DSPs        [grab $u {\|\s*DSPs\s*\|\s*([0-9.]+)}]"
    return $l
}

#synth
read_verilog -sv [list $root/src/$alg/${alg}_pkg.sv $root/src/$alg/${alg}_sec_axis.sv]

set fh [open $out/clk.xdc w]
puts $fh "create_clock -name clk -period $period \[get_ports clk\]"
close $fh
read_xdc -mode out_of_context $out/clk.xdc

synth_design -top ${alg}_sec_axis -part $part -mode out_of_context {*}$generics
write_checkpoint -force $out/synth.dcp
report_utilization               -file $out/util_synth.rpt
report_utilization -hierarchical -file $out/util_synth_hier.rpt
report_timing_summary            -file $out/timing_synth.rpt

lappend summary "core      ${alg}_sec_axis  [join $generics { }]"
lappend summary "part      $part"
lappend summary ""
lappend summary "Area, post-synthesis (estimate)"
lappend summary {*}[area_lines]

#impl
if {$impl} {
    opt_design
    place_design
    route_design
    write_checkpoint -force $out/route.dcp
    report_utilization    -file $out/util_impl.rpt
    report_timing_summary -file $out/timing_impl.rpt

    set w [wns]
    lappend summary ""
    lappend summary "Area, post-route"
    lappend summary {*}[area_lines]
    lappend summary ""
    lappend summary [format "Timing at %.3f ns (%.1f MHz): WNS %.3f ns, %s" \
        $period [expr {1000.0 / $period}] $w [expr {$w >= 0 ? "met" : "FAILED"}]]
    lappend summary [format "  slack estimate of Fmax: %.1f MHz" [expr {1000.0 / ($period - $w)}]]

    #power report
    if {$do_power} {
        if {$saif ne ""} {
            # tb/sv/saif.tcl writes the core under tb_top/dut/u_core
            read_saif -strip_path tb_top/dut/u_core $saif
        }
        report_power -file $out/power.rpt
        set pw [report_power -return_string]
        lappend summary ""
        lappend summary [format "Power at %.1f MHz (%s)" [expr {1000.0 / $period}] \
            [expr {$saif ne "" ? "SAIF: [file tail $saif]" : "vectorless"}]]
        lappend summary "  total       [grab $pw {Total On-Chip Power \(W\)\s*\|\s*([0-9.]+)}] W"
        lappend summary "  dynamic     [grab $pw {Dynamic \(W\)\s*\|\s*([0-9.]+)}] W   <- compare cores on this"
        lappend summary "  static      [grab $pw {Device Static \(W\)\s*\|\s*([0-9.]+)}] W"
        lappend summary "  confidence  [grab $pw {Confidence Level\s*\|\s*([A-Za-z]+)}]"
        if {$saif ne ""} {
            lappend summary "  nets matched [grab $pw {Design Nets Matched\s*\|\s*([^|]+)\|}]"
        }
    }

    #fmax sweep
    if {$do_fmax} {
        set hi ""; set lo ""
        set hi_w 0.0; set lo_w 0.0
        if {$w >= 0} { set hi $period; set hi_w $w } else { set lo $period; set lo_w $w }
        set sweep [list [format "  %7.3f ns  WNS %7.3f  %s" $period $w [expr {$w >= 0 ? "met" : "fail"}]]]

        for {set i 0} {$i < 8} {incr i} {
            if {$hi ne "" && $lo ne ""} {
                if {$hi - $lo < 0.1} break
                set p [expr {($hi + $lo) / 2.0}]
            } elseif {$hi ne ""} {
                set p [expr {max(1.0, $hi - $hi_w - 0.1)}]
            } else {
                set p [expr {$lo - $lo_w + 0.1}]
            }
            set p [expr {round($p * 1000) / 1000.0}]

            close_design
            open_checkpoint $out/synth.dcp
            create_clock -name clk -period $p [get_ports clk]
            opt_design
            place_design
            route_design
            set pw_ [wns]
            lappend sweep [format "  %7.3f ns  WNS %7.3f  %s" $p $pw_ [expr {$pw_ >= 0 ? "met" : "fail"}]]
            if {$pw_ >= 0} {
                set hi $p; set hi_w $pw_
                report_timing_summary -file $out/timing_fmax.rpt
            } else {
                set lo $p; set lo_w $pw_
            }
        }

        lappend summary ""
        lappend summary "Fmax sweep (post-route)"
        lappend summary {*}$sweep
        if {$hi ne ""} {
            lappend summary [format "  Fmax: %.1f MHz (period %.3f ns met)" [expr {1000.0 / $hi}] $hi]
        } else {
            lappend summary "  Fmax: no passing period found"
        }
    }
}

set fh [open $out/summary.txt w]
puts $fh [join $summary "\n"]
close $fh
puts ""
puts [join $summary "\n"]
puts "\nReports in $out"
