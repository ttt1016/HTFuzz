#!/usr/bin/env python3
"""适配干净版 wrapper 的 kmac app_rsp_t 字段名"""
P = "/workspace/pickerfuzz/perip/keymgr-clean/rtl_wrapper/keymgr_perip_tb.sv"
s = open(P).read()

old = """  kmac_pkg::app_req_t kmac_req;
  kmac_pkg::app_rsp_t kmac_rsp;
  assign kmac_rsp.ready = 1'b1;
  assign kmac_rsp.done = 1'b1;
  assign kmac_rsp.digest_share0 = {kmac_pkg::AppDigestW{1'b0}};
  assign kmac_rsp.digest_share1 = {kmac_pkg::AppDigestW{1'b0}};
  assign kmac_rsp.error = 1'b0;"""
new = """  kmac_pkg::app_req_t kmac_req;
  kmac_pkg::app_rsp_t kmac_rsp;
  assign kmac_rsp.req_ready = 1'b1;
  assign kmac_rsp.rsp_valid = 1'b1;
  assign kmac_rsp.rsp_finish = 1'b1;
  assign kmac_rsp.digest_s0 = {kmac_pkg::AppDigestW{1'b0}};
  assign kmac_rsp.digest_s1 = {kmac_pkg::AppDigestW{1'b0}};
  assign kmac_rsp.error = 1'b0;"""
assert old in s, "anchor not found"
s = s.replace(old, new)
open(P, "w").write(s)
print("clean wrapper adapted")
