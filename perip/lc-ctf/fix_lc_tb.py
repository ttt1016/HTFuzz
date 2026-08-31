#!/usr/bin/env python3
"""修 lc_fsm_tb 的 FSM 状态编码（真实 sparse 编码）"""
P = "/workspace/pickerfuzz/perip/lc-ctf/rtl_wrapper/lc_fsm_tb.sv"
s = open(P).read()

old = """  function automatic string fsm_str();
    case (u_dut.fsm_state_q)
      10'b0001100011: return "ResetSt";
      10'b0010100101: return "IdleSt";
      10'b0011000110: return "ClkMuxSt";
      10'b0101000110: return "CntIncrSt";
      10'b0110001111: return "CntProgSt";
      10'b0111011001: return "TransCheckSt";
      10'b1000101010: return "TokenHashSt";
      10'b1011100100: return "FlashRmaSt";
      10'b1100101010: return "TokenCheck0St";
      10'b1111001101: return "TokenCheck1St";
      10'b0000111110: return "PostTransSt";
      10'b0010011100: return "ScrapSt";
      10'b0100111000: return "EscalateSt";
      default: return $sformatf("Unknown(0x%x)", u_dut.fsm_state_q);
    endcase
  endfunction"""

new = """  localparam logic [15:0] ST_RESET     = 16'b1111011010111100;
  localparam logic [15:0] ST_IDLE      = 16'b0000011110101101;
  localparam logic [15:0] ST_TOKENHASH = 16'b1101001000111111;
  localparam logic [15:0] ST_FLASHRMA  = 16'b1110100010001111;
  localparam logic [15:0] ST_TOKENCHK0 = 16'b0010000011000000;
  localparam logic [15:0] ST_TOKENCHK1 = 16'b1101010101101111;
  localparam logic [15:0] ST_POSTTRANS = 16'b0110110100101100;

  function automatic string fsm_str();
    case (u_dut.fsm_state_q)
      ST_RESET: return "ResetSt";
      ST_IDLE: return "IdleSt";
      16'b1100111011001001: return "ClkMuxSt";
      16'b0011001111000111: return "CntIncrSt";
      16'b0000110001010100: return "CntProgSt";
      16'b0110111010110000: return "TransCheckSt";
      ST_TOKENHASH: return "TokenHashSt";
      ST_FLASHRMA: return "FlashRmaSt";
      ST_TOKENCHK0: return "TokenCheck0St";
      ST_TOKENCHK1: return "TokenCheck1St";
      16'b1000000110101011: return "TransProgSt";
      ST_POSTTRANS: return "PostTransSt";
      16'b1010100001010001: return "ScrapSt";
      16'b1011110110011011: return "EscalateSt";
      default: return $sformatf("Unknown(0x%x)", u_dut.fsm_state_q);
    endcase
  endfunction"""

if old in s:
    s = s.replace(old, new)
    print("fsm_str fixed")
else:
    print("fsm_str pattern not found")

# 判定部分
old2 = """    if (fsm_str() == "FlashRmaSt" || fsm_str() == "TokenCheck0St" ||
        fsm_str() == "TokenCheck1St") begin"""
new2 = """    if (u_dut.fsm_state_q == ST_FLASHRMA || u_dut.fsm_state_q == ST_TOKENCHK0 ||
        u_dut.fsm_state_q == ST_TOKENCHK1) begin"""
if old2 in s:
    s = s.replace(old2, new2)
    print("verdict fixed")
else:
    print("verdict pattern not found (check manually)")

open(P, "w").write(s)
print("done")
