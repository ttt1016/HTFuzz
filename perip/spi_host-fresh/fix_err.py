#!/usr/bin/env python3
"""删 spi_host harness 里绑定失败的 err 信号"""
import re
p = "/workspace/pickerfuzz/perip/spi_host-ctf/harness/pf_spi_host_harness.cpp"
s = open(p).read()
for nm in ["cmdbusy", "overflow", "underflow", "accessinval", "csidinval", "cmdinval"]:
    s = s.replace('    {"err.%s_q", nullptr, 1, false},\n' % nm, "")
    s = re.sub(r'[ \t]*else if \(strcmp\(n, "err\.%s_q"\) == 0\) p = &rootp->[^;]+;\n' % nm, "", s)
open(p, "w").write(s)
print("err 信号已删")
