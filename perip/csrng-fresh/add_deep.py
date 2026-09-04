#!/usr/bin/env python3
"""csrng TB 加深度盲测任务"""
P = "/workspace/pickerfuzz/perip/csrng-ctf/rtl_wrapper/csrng_perip_tb.sv"
s = open(P).read()

old = "  initial run_detection();"

new = """  // ---- 深度盲测: O-A/B/C ----
  task automatic run_deep_fuzz;
    logic [31:0] rdata;
    logic [31:0] g0, g1, g2, g3;
    logic [31:0] h0, h1, h2, h3;
    begin
      $display("\\n======================================================================");
      $display("Deep fuzz: O-A/B/C on csrng");
      $display("======================================================================");

      // O-B: 两次独立 instantiate+gen，genbits 应不同（entropy LFSR 在变）
      rst_n = 0; repeat (3) @(posedge clk); rst_n = 1; repeat (10) @(posedge clk);
      tl_write(32'h14, 32'h6666); tl_write(32'h14, 32'h6666);
      csrng_cmd(32'h00000001);  // INS
      csrng_cmd(32'h00000003);  // GEN
      read_genbits(g0, g1, g2, g3);

      rst_n = 0; repeat (3) @(posedge clk); rst_n = 1; repeat (10) @(posedge clk);
      tl_write(32'h14, 32'h6666); tl_write(32'h14, 32'h6666);
      csrng_cmd(32'h00000001);  // INS
      csrng_cmd(32'h00000003);  // GEN
      read_genbits(h0, h1, h2, h3);

      $display("[O-B] run1 GEN: %08x %08x", g0, g1);
      $display("[O-B] run2 GEN: %08x %08x", h0, h1);
      if ({g0, g1} == {h0, h1}) begin
        $display("[O-B] VIOLATION: 两次独立 instantiate+gen 输出相同 → 熵注入无效");
      end else begin
        $display("[O-B] PASS: 输出不同（熵正常注入）");
      end

      // O-A: INS 后读内部状态（V 寄存器残留检查）
      rst_n = 0; repeat (3) @(posedge clk); rst_n = 1; repeat (10) @(posedge clk);
      tl_write(32'h14, 32'h6666); tl_write(32'h14, 32'h6666);
      csrng_cmd(32'h00000001);  // INS
      tl_write(32'h38, 32'h6666); tl_write(32'h38, 32'h6666);
      tl_write(32'h40, 32'h0);
      $display("[O-A] INS 后内部状态:");
      for (int i = 0; i < 4; i++) begin
        tl_read(32'h44, rdata);
        $display("  V[%0d] = %08x", i, rdata);
      end

      $finish;
    end
  endtask

  initial run_detection();
  initial begin
    #200000;
    run_deep_fuzz();
  end"""

if old in s:
    s = s.replace(old, new)
    open(P, "w").write(s)
    print("deep fuzz added")
else:
    print("pattern not found")
