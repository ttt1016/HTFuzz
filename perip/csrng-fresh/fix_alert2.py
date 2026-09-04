#!/usr/bin/env python3
"""修 csrng TB: alert_rx 字段名（老版无 alert_ 前缀）"""
P = "/workspace/pickerfuzz/perip/csrng-ctf/rtl_wrapper/csrng_perip_tb.sv"
s = open(P).read()

old = """    alert_rx = '{default: '{alert_ping_p: 1'b0, alert_ping_n: 1'b1, alert_ack_p: 1'b0, alert_ack_n: 1'b1}};"""
new = """    alert_rx = '{default: '{ping_p: 1'b0, ping_n: 1'b1, ack_p: 1'b0, ack_n: 1'b1}};"""

if old in s:
    s = s.replace(old, new)
    open(P, "w").write(s)
    print("alert_rx fields fixed")
else:
    print("pattern not found")
