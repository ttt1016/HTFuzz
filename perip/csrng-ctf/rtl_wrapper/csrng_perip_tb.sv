// PickerFuzz csrng per-IP testbench (self-contained SV detection)
module csrng_perip_tb;
  import tlul_pkg::*;
  import csrng_pkg::*;
  import csrng_reg_pkg::*;
  import entropy_src_pkg::*;
  import prim_mubi_pkg::*;

  localparam int NHwApps = 2;  // csrng_pkg::NHwApps
  localparam int NumAlerts = 2;
  logic clk = 0, rst_n = 0;
  always #5 clk = ~clk;

  tl_h2d_t tl_h2d;
  tl_d2h_t tl_d2h;

  // OTP / LC inputs
  prim_mubi_pkg::mubi8_t otp_en_csrng_sw_app_read;
  lc_ctrl_pkg::lc_tx_t lc_hw_debug_en;

  // entropy_src hw interface (stub: always ready with fips entropy)
  entropy_src_hw_if_req_t entropy_src_hw_if;
  entropy_src_hw_if_rsp_t entropy_src_hw_if_i;
  logic [63:0] esrng_lfsr_q;
  // 注意: LFSR 不随 DUT reset 重置（模拟真实 entropy_src 的连续运行）
  initial esrng_lfsr_q = 64'hDEADBEEFCAFEBABE;
  always_ff @(posedge clk) begin
    esrng_lfsr_q <= {esrng_lfsr_q[62:0], esrng_lfsr_q[63]^esrng_lfsr_q[61]^esrng_lfsr_q[40]^esrng_lfsr_q[0]};
  end
  assign entropy_src_hw_if_i = '{es_ack: 1'b1, es_bits: esrng_lfsr_q, es_fips: 4'hF};

  // aes halt handshake (stub: never halt)
  cs_aes_halt_req_t cs_aes_halt_i;
  cs_aes_halt_rsp_t cs_aes_halt_o;
  assign cs_aes_halt_i.cs_aes_halt_req = 1'b0;

  // HW app interface (NHwApps stubs: all idle)
  csrng_req_t [NHwApps-1:0] csrng_cmd_i;
  csrng_rsp_t [NHwApps-1:0] csrng_cmd_o;

  logic [NumAlerts-1:0] alert_rx_int;
  prim_alert_pkg::alert_rx_t [NumAlerts-1:0] alert_rx;
  prim_alert_pkg::alert_tx_t [NumAlerts-1:0] alert_tx;

  logic intr_cs_cmd_req_done, intr_cs_entropy_req, intr_cs_hw_inst_exc, intr_cs_fatal_err;

  csrng u_dut (
    .clk_i(clk), .rst_ni(rst_n),
    .tl_i(tl_h2d), .tl_o(tl_d2h),
    .otp_en_csrng_sw_app_read_i(otp_en_csrng_sw_app_read),
    .lc_hw_debug_en_i(lc_hw_debug_en),
    .entropy_src_hw_if_o(entropy_src_hw_if),
    .entropy_src_hw_if_i(entropy_src_hw_if_i),
    .cs_aes_halt_i(cs_aes_halt_i),
    .cs_aes_halt_o(cs_aes_halt_o),
    .csrng_cmd_i(csrng_cmd_i),
    .csrng_cmd_o(csrng_cmd_o),
    .alert_rx_i(alert_rx),
    .alert_tx_o(alert_tx),
    .intr_cs_cmd_req_done_o(intr_cs_cmd_req_done),
    .intr_cs_entropy_req_o(intr_cs_entropy_req),
    .intr_cs_hw_inst_exc_o(intr_cs_hw_inst_exc),
    .intr_cs_fatal_err_o(intr_cs_fatal_err)
  );

  initial begin
    tl_h2d = 0;
    otp_en_csrng_sw_app_read = prim_mubi_pkg::MuBi8True;
    lc_hw_debug_en = lc_ctrl_pkg::Off;
    csrng_cmd_i = '{default: '{csrng_req_valid: 1'b0, csrng_req_bus: '0, genbits_ready: 1'b0}};
    alert_rx_int = '0;
    alert_rx = '{default: '{ping_p: 1'b0, ping_n: 1'b1, ack_p: 1'b0, ack_n: 1'b1}};
  end

  // ---- TLUL host tasks ----
  task automatic tl_write(input logic [31:0] addr, input logic [31:0] data);
    begin
      @(posedge clk);
      tl_h2d.a_valid = 1'b1;
      tl_h2d.a_opcode = PutFullData;
      tl_h2d.a_param = 3'h0;
      tl_h2d.a_size = 2'h2;
      tl_h2d.a_source = 3'h0;
      tl_h2d.a_address = addr;
      tl_h2d.a_mask = 4'b1111;
      tl_h2d.a_data = data;
      tl_h2d.a_user.instr_type = prim_mubi_pkg::MuBi4False;
      tl_h2d.a_user.rsvd = 0;
      tl_h2d.a_user.cmd_intg = tlul_pkg::get_cmd_intg(tl_h2d);
      tl_h2d.a_user.data_intg = tlul_pkg::get_data_intg(data);
      tl_h2d.d_ready = 1'b1;
      while (!tl_d2h.a_ready) @(posedge clk);
      @(posedge clk);
      tl_h2d.a_valid = 1'b0;
      while (!tl_d2h.d_valid) @(posedge clk);
      @(posedge clk);
      tl_h2d.d_ready = 1'b0;
    end
  endtask

  task automatic tl_read(input logic [31:0] addr, output logic [31:0] data);
    begin
      @(posedge clk);
      tl_h2d.a_valid = 1'b1;
      tl_h2d.a_opcode = Get;
      tl_h2d.a_param = 3'h0;
      tl_h2d.a_size = 2'h2;
      tl_h2d.a_source = 3'h0;
      tl_h2d.a_address = addr;
      tl_h2d.a_mask = 4'b1111;
      tl_h2d.a_data = 0;
      tl_h2d.a_user.instr_type = prim_mubi_pkg::MuBi4False;
      tl_h2d.a_user.rsvd = 0;
      tl_h2d.a_user.cmd_intg = tlul_pkg::get_cmd_intg(tl_h2d);
      tl_h2d.a_user.data_intg = tlul_pkg::get_data_intg(0);
      tl_h2d.d_ready = 1'b1;
      while (!tl_d2h.a_ready) @(posedge clk);
      @(posedge clk);
      tl_h2d.a_valid = 1'b0;
      while (!tl_d2h.d_valid) @(posedge clk);
      data = tl_d2h.d_data;
      @(posedge clk);
      tl_h2d.d_ready = 1'b0;
    end
  endtask

  // ---- 检测: instantiate → gen → 输出确定性 + zeroize 残留 ----
  // 寄存器偏移（csrng_reg_pkg）:
  //   CTRL=0x14, CMD_REQ=0x18, GENBITS_VLD=0x30, GENBITS=0x34,
  //   INT_STATE_READ_ENABLE=0x38, INT_STATE_NUM=0x40, INT_STATE_VAL=0x44
  task automatic csrng_cmd(input logic [31:0] cmd);
    logic [31:0] st;
    begin
      tl_write(32'h18, cmd);  // CMD_REQ
      // 等 cmd_req_done 中断
      for (int i = 0; i < 2000; i++) begin
        @(posedge clk);
        if (intr_cs_cmd_req_done) begin
          tl_write(32'h0, 32'h1);  // 清中断（rw1c）
          $display("  [cmd %08x] done @%0d", cmd, i);
          break;
        end
        if (i % 500 == 499) begin
          tl_read(32'h18, st);
          $display("  [cmd %08x] timeout, CMD_REQ=%08x es_req=%b es_ack=%b es_bits=%h",
                   cmd, st, entropy_src_hw_if.es_req, entropy_src_hw_if_i.es_ack, entropy_src_hw_if_i.es_bits);
        end
      end
    end
  endtask

  task automatic read_genbits(output logic [31:0] g0, output logic [31:0] g1,
                              output logic [31:0] g2, output logic [31:0] g3);
    logic [31:0] vld;
    begin
      // 等 genbits_vld
      for (int i = 0; i < 2000; i++) begin
        tl_read(32'h30, vld);
        if (vld[0]) break;
        @(posedge clk);
      end
      tl_read(32'h34, g0);
      tl_read(32'h34, g1);
      tl_read(32'h34, g2);
      tl_read(32'h34, g3);
    end
  endtask

  task automatic run_detection;
    logic [31:0] rdata;
    logic [31:0] g0, g1, g2, g3;
    logic [31:0] h0, h1, h2, h3;
    begin
      $display("======================================================================");
      $display("csrng Bug discovery: DRBG output determinism + zeroize residual");
      $display("======================================================================");

      // reset
      rst_n = 0;
      repeat (5) @(posedge clk);
      rst_n = 1;
      repeat (10) @(posedge clk);

      // CTRL: 全部 mubi4 True=0x6（ENABLE/SW_APP_ENABLE/READ_INT_STATE/AES_KEY_SEL）
      // shadow 两阶段写
      tl_write(32'h14, 32'h6666);
      tl_write(32'h14, 32'h6666);
      tl_read(32'h14, rdata);
      $display("[T0] CTRL readback = %08x (期望 6666)", rdata);

      // instantiate (INS=1): flag0=0, cmd=INS, clen=0
      // acmd 格式: [3:0]=cmd, [11:8]=clen, [31:12]=flag
      csrng_cmd(32'h0000_0001);  // INS

      // gen (GEN=3)
      csrng_cmd(32'h0000_0003);  // GEN
      read_genbits(g0, g1, g2, g3);
      $display("[T1] 第一次 GEN 输出: %08x %08x %08x %08x", g0, g1, g2, g3);

      // 再 GEN 一次（V 应递增 → 输出应不同）
      csrng_cmd(32'h0000_0003);  // GEN
      read_genbits(h0, h1, h2, h3);
      $display("[T2] 第二次 GEN 输出: %08x %08x %08x %08x", h0, h1, h2, h3);

      // 判定 1: 两次 GEN 输出应不同（CTR_DRBG V 递增）
      $display("\n======================================================================");
      $display("VERDICT");
      $display("======================================================================");
      if ({g0, g1} == {h0, h1} && {g2, g3} == {h2, h3}) begin
        $display("VIOLATION: 两次 GEN 输出完全相同 → DRBG 状态未更新（PRNG 停转）");
        $display("  → 随机数生成器失效，输出可预测");
      end else begin
        $display("PASS: 两次 GEN 输出不同（DRBG 正常递增）");
      end

      // 读内部状态（INT_STATE_VAL）
      tl_write(32'h38, 32'h1);  // INT_STATE_READ_ENABLE
      tl_write(32'h40, 32'h0);  // INT_STATE_NUM = 0
      $display("\n内部状态（INT_STATE_VAL 读取）:");
      for (int i = 0; i < 12; i++) begin
        tl_read(32'h44, rdata);
        $display("  state[%0d] = %08x", i, rdata);
      end

      // (continue to deep fuzz)
    end
  endtask

  // ---- 深度盲测: O-A/B/C ----
  task automatic run_deep_fuzz;
    logic [31:0] rdata;
    logic [31:0] g0, g1, g2, g3;
    logic [31:0] h0, h1, h2, h3;
    begin
      $display("\n======================================================================");
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
  end
endmodule
