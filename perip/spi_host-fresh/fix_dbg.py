#!/usr/bin/env python3
"""删 spi_host harness 里 dbg 绑定"""
import re
p = "/workspace/pickerfuzz/perip/spi_host-ctf/harness/pf_spi_host_harness.cpp"
s = open(p).read()
for nm in ["addr_q", "wdata_q", "we_q", "valid_q"]:
    s = s.replace('    {"dbg.%s", nullptr, 1, false},\n' % nm, "")
    s = re.sub(r'[ \t]*else if \(strcmp\(n, "dbg\.%s"\) == 0\) p = &rootp->[^;]+;\n' % nm, "", s)
open(p, "w").write(s)
print("dbg 绑定已删")
