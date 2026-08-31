#!/usr/bin/env python3
"""修 data_out_we 白盒路径"""
P = "/workspace/pickerfuzz/perip/aes-ctf/harness/pf_aes_harness.cpp"
s = open(P).read()

old = "#define SIGF(n) rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_control__DOT__gen_fsm__BRA__0__KET____DOT__gen_fsm_p__DOT__u_aes_control_fsm_i__DOT__u_aes_control_fsm__DOT__##n"
new = "#define SIGF(n) rootp->aes_perip_tb__DOT__u_dut__DOT__u_aes_core__DOT__u_aes_control__DOT__gen_fsm__BRA__0__KET____DOT__gen_fsm_p__DOT__u_aes_control_fsm_i__DOT__##n"
if old in s:
    s = s.replace(old, new)
    print("SIGF fixed")

old2 = 'g_sigs[i].ptr = &SIGD(data_out_we);'
new2 = 'g_sigs[i].ptr = &SIGF(data_out_we);'
if old2 in s:
    s = s.replace(old2, new2)
    print("bind fixed")

open(P, "w").write(s)
print("done")
