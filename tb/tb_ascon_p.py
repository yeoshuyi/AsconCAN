
import cocotb
import os
import random

from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, Timer

from ascon_ref import RC, M64, ascon_round, ascon_permute, pack, unpack

CLK_NS = 10
SEED = int(os.environ.get("ASCON_SEED", "1234"))

def hexs(v) :
    return " ".join("%016x" % w for w in unpack(v))

def check(dut, got, exp, ctx):
    if got != exp:
        g, e  = unpack(got), unpack(exp)

        raise AssertionError()

async def apply_round(dut, state, rc):
    dut.r_state_in.value = pack(state)
    dut.r_round_const.value = rc
    await Timer(1, unit="ns")
    return int(dut.r_state_out.value)

@cocotb.test()
async def test_round_directed(dut):
    
