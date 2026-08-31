#!/usr/bin/env python3
"""clean lc TB: 加 lc_sync 同步等待"""
P = "/workspace/pickerfuzz/perip/lc-clean/rtl_wrapper/lc_fsm_tb.sv"
s = open(P).read()

old = """    rma_token = 128'h11111111_22222222_33333333_DEADBEEF;
    rma_token_valid = On;
    hashed_token = 128'h99999999_88888888_77777777_DEADBEEF;
    trans_target = '{default: DecLcStRma};
    repeat (2) @(posedge clk);"""

new = """    rma_token = 128'h11111111_22222222_33333333_DEADBEEF;
    rma_token_valid = On;
    hashed_token = 128'h99999999_88888888_77777777_DEADBEEF;
    trans_target = '{default: DecLcStRma};
    repeat (20) @(posedge clk);  // 等 lc_sync 同步"""

if old in s:
    s = s.replace(old, new)
    open(P, "w").write(s)
    print("sync wait added")
else:
    print("pattern not found")
