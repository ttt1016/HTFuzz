#!/usr/bin/env python3
"""修 csrng TB: alert_rx 赋值（用 default）"""
P = "/workspace/pickerfuzz/perip/csrng-ctf/rtl_wrapper/csrng_perip_tb.sv"
s = open(P).read()

old = """    alert_rx = '{default: '{alert_ping_p: 1'b0, alert_ping_n: 1'b1, alert_ack_p: 1'b0, alert_ack_n: 1'b1, alert_crashdump_p: 1'b0, alert_crashdump_n: 1'b1}};"""
new = """    alert_rx = '{default: '{alert_ping_p: 1'b0, alert_ping_n: 1'b1, alert_ack_p: 1'b0, alert_ack_n: 1'b1}};"""

if old in s:
    s = s.replace(old, new)
    open(P, "w").write(s)
    print("alert_rx fixed")
else:
    # 直接用 default '0
    import re
    s2 = re.sub(r"alert_rx = '\{default:.*?\};", "alert_rx = '{default: '0};", s)
    if s2 != s:
        open(P, "w").write(s2)
        print("alert_rx -> default 0")
    else:
        print("pattern not found")
