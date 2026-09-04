#!/usr/bin/env python3
"""spi_host harness: 顶层 u_dut 信号也走子模块指针"""
p = "/workspace/pickerfuzz/perip/spi_host-ctf/harness/pf_spi_host_harness.cpp"
s = open(p).read()
s = s.replace(
    "rootp->spi_host_perip_tb__DOT__u_dut__DOT__core_command_valid;",
    "rootp->spi_host_perip_tb->__PVT__u_dut__DOT__core_command_valid;")
s = s.replace(
    "rootp->spi_host_perip_tb__DOT__u_dut__DOT__error_cmd_inval;",
    "rootp->spi_host_perip_tb->__PVT__u_dut__DOT__error_cmd_inval;")
s = s.replace(
    "rootp->spi_host_perip_tb__DOT__u_dut__DOT__error_csid_inval;",
    "rootp->spi_host_perip_tb->__PVT__u_dut__DOT__error_csid_inval;")
s = s.replace(
    "rootp->spi_host_perip_tb__DOT__u_dut__DOT__en;",
    "rootp->spi_host_perip_tb->__PVT__u_dut__DOT__en;")
s = s.replace(
    "rootp->spi_host_perip_tb__DOT__u_dut__DOT__command_busy;",
    "rootp->spi_host_perip_tb->__PVT__u_dut__DOT__command_busy;")
open(p, "w").write(s)
print("顶层信号路径更新完成")
