#!/usr/bin/env python3
"""修 ibex wrapper 数组端口连接"""
p = "/workspace/pickerfuzz/perip/ibex-ctf/rtl_wrapper/ibex_mini_tb.sv"
s = open(p).read()
s = s.replace("""    .ic_tag_rdata_i    ('0),""", """    .ic_tag_rdata_i    (ic_tag_rdata),""")
s = s.replace("""    .ic_data_rdata_i   ('0),""", """    .ic_data_rdata_i   (ic_data_rdata),""")
s = s.replace("""  // CPU 实例（匹配 ibex_core 真实端口）""",
"""  logic [ibex_pkg::TagSizeECC-1:0] ic_tag_rdata [ibex_pkg::IC_NUM_WAYS];
  logic [ibex_pkg::LineSizeECC-1:0] ic_data_rdata [ibex_pkg::IC_NUM_WAYS];

  // CPU 实例（匹配 ibex_core 真实端口）""")
open(p, "w").write(s)
print("数组端口修复完成")
