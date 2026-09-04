#!/usr/bin/env python3
"""spi_host harness: __PVT__ 路径更新 + new_command/stall 观测"""
p = "/workspace/pickerfuzz/perip/spi_host-ctf/harness/pf_spi_host_harness.cpp"
s = open(p).read()
# 所有子模块信号加 __PVT__ 前缀
s = s.replace(
    "rootp->spi_host_perip_tb__DOT__u_dut__DOT__u_spi_core__DOT__u_fsm__DOT__",
    "rootp->spi_host_perip_tb__DOT____PVT__u_dut__DOT__u_spi_core__DOT__u_fsm__DOT__")
s = s.replace(
    "rootp->spi_host_perip_tb__DOT__u_dut__DOT__u_cmd_queue__DOT__",
    "rootp->spi_host_perip_tb__DOT____PVT__u_dut__DOT__u_cmd_queue__DOT__")
s = s.replace(
    "rootp->spi_host_perip_tb__DOT__u_dut__DOT__u_data_fifos__DOT__",
    "rootp->spi_host_perip_tb__DOT____PVT__u_dut__DOT__u_data_fifos__DOT__")
s = s.replace(
    "rootp->spi_host_perip_tb__DOT__u_dut__DOT__u_reg__DOT__",
    "rootp->spi_host_perip_tb__DOT____PVT__u_dut__DOT__u_reg__DOT__")
# 加 new_command/stall 观测
if "fsm.new_command" not in s:
    s = s.replace(
        '    {"dbg.regre_cnt", nullptr, 1, false},\n};',
        '    {"dbg.regre_cnt", nullptr, 1, false},\n'
        '    {"fsm.new_command", nullptr, 1, false},\n'
        '    {"fsm.stall", nullptr, 1, false},\n};')
    s = s.replace(
        '        else if (strcmp(n, "dbg.regre_cnt") == 0) p = &rootp->spi_host_perip_tb__DOT__dbg_regre_cnt;',
        '        else if (strcmp(n, "dbg.regre_cnt") == 0) p = &rootp->spi_host_perip_tb__DOT__dbg_regre_cnt;\n'
        '        else if (strcmp(n, "fsm.new_command") == 0) p = &rootp->spi_host_perip_tb__DOT____PVT__u_dut__DOT__u_spi_core__DOT__u_fsm__DOT__new_command;\n'
        '        else if (strcmp(n, "fsm.stall") == 0) p = &rootp->spi_host_perip_tb__DOT____PVT__u_dut__DOT__u_spi_core__DOT__u_fsm__DOT__stall;')
# include 子模块头文件
if "Vspi_host_perip_tb_spi_host_perip_tb.h" not in s:
    s = s.replace(
        '#include "Vspi_host_perip_tb___024root.h"',
        '#include "Vspi_host_perip_tb___024root.h"\n#include "Vspi_host_perip_tb_spi_host_perip_tb.h"')
open(p, "w").write(s)
print("harness __PVT__ 路径更新完成")
