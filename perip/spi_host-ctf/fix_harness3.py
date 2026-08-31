#!/usr/bin/env python3
"""修 spi_host harness: 删旧 dbg/err 绑定，加 regwe 计数绑定"""
import re
p = "/workspace/pickerfuzz/perip/spi_host-ctf/harness/pf_spi_host_harness.cpp"
s = open(p).read()
# 删 dbg/err 旧绑定
for pre in ["dbg", "err"]:
    for nm in ["addr_q", "wdata_q", "we_q", "valid_q", "cmdbusy_q", "overflow_q",
               "underflow_q", "accessinval_q", "csidinval_q", "cmdinval_q"]:
        s = s.replace('    {"%s.%s", nullptr, 1, false},\n' % (pre, nm), "")
        s = re.sub(r'[ \t]*else if \(strcmp\(n, "%s\.%s"\) == 0\) p = &rootp->[^;]+;\n' % (pre, nm), "", s)
# 加 regwe 计数绑定
if "dbg.regwe_cnt" not in s:
    s = s.replace(
        '    {"tb.en", nullptr, 1, false},\n};',
        '    {"tb.en", nullptr, 1, false},\n'
        '    {"dbg.regwe_cnt", nullptr, 1, false},\n'
        '    {"dbg.regre_cnt", nullptr, 1, false},\n};')
    s = s.replace(
        '        else if (strcmp(n, "tb.en") == 0) p = &rootp->spi_host_perip_tb__DOT__u_dut__DOT__en;',
        '        else if (strcmp(n, "tb.en") == 0) p = &rootp->spi_host_perip_tb__DOT__u_dut__DOT__en;\n'
        '        else if (strcmp(n, "dbg.regwe_cnt") == 0) p = &rootp->spi_host_perip_tb__DOT__dbg_regwe_cnt;\n'
        '        else if (strcmp(n, "dbg.regre_cnt") == 0) p = &rootp->spi_host_perip_tb__DOT__dbg_regre_cnt;')
open(p, "w").write(s)
print("harness 更新完成")
