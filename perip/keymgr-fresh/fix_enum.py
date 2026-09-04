#!/usr/bin/env python3
"""修复 wrapper 里的枚举引用（改数值比较）"""
P = "/workspace/pickerfuzz/perip/keymgr-ctf/rtl_wrapper/keymgr_perip_tb.sv"
s = open(P).read()

old_func = """  function automatic string state_str(logic [9:0] v);
    case (v)
      StCtrlReset: return "StCtrlReset";
      StCtrlEntropyReseed: return "StCtrlEntropyReseed";
      StCtrlRandom: return "StCtrlRandom";
      StCtrlRootKey: return "StCtrlRootKey";
      StCtrlInit: return "StCtrlInit";
      StCtrlCreatorRootKey: return "StCtrlCreatorRootKey";
      StCtrlOwnerIntKey: return "StCtrlOwnerIntKey";
      StCtrlOwnerKey: return "StCtrlOwnerKey";
      StCtrlDisabled: return "StCtrlDisabled";
      StCtrlWipe: return "StCtrlWipe";
      StCtrlInvalid: return "StCtrlInvalid";
      default: return $sformatf("Unknown(0x%x)", v);
    endcase
  endfunction"""

new_func = """  localparam logic [9:0] ST_INVALID = 10'b1011000111;

  function automatic string state_str(logic [9:0] v);
    case (v)
      10'b1101100001: return "StCtrlReset";
      10'b1110010010: return "StCtrlEntropyReseed";
      10'b0011110100: return "StCtrlRandom";
      10'b0110101111: return "StCtrlRootKey";
      10'b0100000100: return "StCtrlInit";
      10'b1000011101: return "StCtrlCreatorRootKey";
      10'b0001001010: return "StCtrlOwnerIntKey";
      10'b1101111110: return "StCtrlOwnerKey";
      10'b1010101000: return "StCtrlDisabled";
      10'b0000110011: return "StCtrlWipe";
      10'b1011000111: return "StCtrlInvalid";
      default: return $sformatf("Unknown(0x%x)", v);
    endcase
  endfunction"""

if old_func in s:
    s = s.replace(old_func, new_func)
    print("state_str fixed")
elif "ST_INVALID" in s:
    print("already fixed")

s = s.replace("if (st == StCtrlInvalid) begin", "if (st == ST_INVALID) begin")
open(P, "w").write(s)
print("done")
