#!/usr/bin/env python3
"""完成 Bug#32 harness 修改: sp_data_out_we 绑定 + we==3 判断"""
P = "/workspace/pickerfuzz/perip/aes-ctf/harness/pf_aes_harness.cpp"
s = open(P).read()

# 1. 绑定到 sp_data_out_we
old = 'g_sigs[i].ptr = &SIGF(data_out_we);'
new = 'g_sigs[i].ptr = &SIGD(u_aes_control__DOT__sp_data_out_we);'
if old in s:
    s = s.replace(old, new)
    print("bind -> sp_data_out_we")

# 2. we==3 判断（SP2V_HIGH=3'b011）
old2 = """        uint32_t we = pf_sig_read(we_sig, 0);
        if (we) {"""
new2 = """        uint32_t we = pf_sig_read(we_sig, 0);
        if (we == 3) {  // SP2V_HIGH = 3'b011"""
if old2 in s:
    s = s.replace(old2, new2)
    print("we==3 check added")

open(P, "w").write(s)
print("done")
