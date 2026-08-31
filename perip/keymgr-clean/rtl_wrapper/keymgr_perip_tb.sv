// PickerFuzz keymgr per-IP testbench (self-contained SV detection)
module keymgr_perip_tb;
  import tlul_pkg::*;
  import keymgr_pkg::*;
  import keymgr_reg_pkg::*;

  logic clk = 0, rst_n = 0, rst_shadowed_n = 0, clk_edn = 0, rst_edn_n = 0;
  always #5 clk = ~clk;
  always #3.5 clk_edn = ~clk_edn;

  tl_h2d_t tl_h2d;
  tl_d2h_t tl_d2h;

  kmac_pkg::app_req_t kmac_req;
  kmac_pkg::app_rsp_t kmac_rsp;
  assign kmac_rsp.req_ready = 1'b1;
  assign kmac_rsp.rsp_valid = 1'b1;
  assign kmac_rsp.rsp_finish = 1'b1;
  assign kmac_rsp.digest_s0 = {kmac_pkg::AppDigestW{1'b0}};
  assign kmac_rsp.digest_s1 = {kmac_pkg::AppDigestW{1'b0}};
  assign kmac_rsp.error = 1'b0;

  edn_pkg::edn_req_t edn_req;
  edn_pkg::edn_rsp_t edn_rsp;
  assign edn_rsp.edn_ack = 1'b1;
  assign edn_rsp.edn_fips = 1'b1;
  assign edn_rsp.edn_bus = 32'hA5A5A5A5;

  lc_ctrl_pkg::lc_tx_t lc_keymgr_en;
  lc_ctrl_pkg::lc_keymgr_div_t lc_keymgr_div;
  otp_ctrl_pkg::otp_keymgr_key_t otp_key;
  otp_ctrl_pkg::otp_device_id_t otp_device_id;
  flash_ctrl_pkg::keymgr_flash_t flash;
  rom_ctrl_pkg::keymgr_data_t rom_digest;

  hw_key_req_t aes_key_o, kmac_key_o;
  otbn_key_req_t otbn_key_o;
  logic intr_op_done;
  prim_alert_pkg::alert_rx_t [keymgr_reg_pkg::NumAlerts-1:0] alert_rx;
  prim_alert_pkg::alert_tx_t [keymgr_reg_pkg::NumAlerts-1:0] alert_tx;

  keymgr u_dut (
    .clk_i(clk), .rst_ni(rst_n), .rst_shadowed_ni(rst_shadowed_n),
    .clk_edn_i(clk_edn), .rst_edn_ni(rst_edn_n),
    .tl_i(tl_h2d), .tl_o(tl_d2h),
    .aes_key_o(aes_key_o), .kmac_key_o(kmac_key_o), .otbn_key_o(otbn_key_o),
    .kmac_data_o(kmac_req), .kmac_data_i(kmac_rsp),
    .kmac_en_masking_i(1'b1),
    .lc_keymgr_en_i(lc_keymgr_en),
    .lc_keymgr_div_i(lc_keymgr_div),
    .otp_key_i(otp_key), .otp_device_id_i(otp_device_id),
    .flash_i(flash), .edn_o(edn_req), .edn_i(edn_rsp),
    .rom_digest_i(rom_digest),
    .intr_op_done_o(intr_op_done),
    .alert_rx_i(alert_rx), .alert_tx_o(alert_tx)
  );

  initial begin
    tl_h2d = 0;
    lc_keymgr_en = lc_ctrl_pkg::On;
    lc_keymgr_div = 64'hDEADBEEFCAFEBABE;
    otp_key = 0;
    otp_device_id = 0;
    flash = 0;
    rom_digest = 0;
    alert_rx = 0;
  end

  localparam logic [9:0] ST_INVALID = 10'b1011000111;

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
  endfunction

  // ---- Bug#21/64 检测（全 SV）----
  task automatic run_detection;
    logic [9:0] st;
    int ks[2][2][8];
    int samples[5][2][8];
    bit share0_eq_ks, share1_eq_ks, changing;
    begin
      $display("======================================================================");
      $display("keymgr Bug#21/64: StCtrlInvalid key exposure detection");
      $display("======================================================================");

      // reset
      rst_n = 0; rst_shadowed_n = 0; rst_edn_n = 0;
      repeat (5) @(posedge clk);
      rst_n = 1; rst_shadowed_n = 1; rst_edn_n = 1;
      repeat (20) @(posedge clk);

      st = u_dut.u_ctrl.state_q;
      $display("\nstate = %s (0x%x)", state_str(st), st);
      $display("invalid_stage_sel = %0d  stage_sel = %0d",
               u_dut.u_ctrl.invalid_stage_sel_o, u_dut.u_ctrl.stage_sel_o);

      // key_state_q
      $display("\nkey_state_q (internal key state):");
      for (int cdi = 0; cdi < 2; cdi++)
        for (int share = 0; share < 2; share++) begin
          $write("  [cdi=%0d][share=%0d] =", cdi, share);
          for (int w = 0; w < 8; w++) begin
            ks[cdi][share][w] = u_dut.u_ctrl.key_state_q[cdi][share][w];
            $write(" %08x", ks[cdi][share][w]);
          end
          $write("\n");
        end

      // u_ctrl.key_o 采样
      $display("\nu_ctrl.key_o sampling (every 50 cycles):");
      for (int i = 0; i < 5; i++) begin
        repeat (50) @(posedge clk);
        for (int share = 0; share < 2; share++)
          for (int w = 0; w < 8; w++)
            samples[i][share][w] = u_dut.u_ctrl.key_o.key[share][w];
        $write("  sample %0d share0 =", i);
        for (int w = 0; w < 8; w++) $write(" %08x", samples[i][0][w]);
        $write("\n           share1 =");
        for (int w = 0; w < 8; w++) $write(" %08x", samples[i][1][w]);
        $write("\n  lfsr = %08x\n", u_dut.lfsr[63:32]);
      end

      // 判定
      st = u_dut.u_ctrl.state_q;
      $display("\n======================================================================");
      $display("VERDICT");
      $display("======================================================================");
      if (st == ST_INVALID) begin
        $display("State: StCtrlInvalid (invalid_stage_sel=%0d)",
                 u_dut.u_ctrl.invalid_stage_sel_o);
        share0_eq_ks = 1; share1_eq_ks = 1; changing = 0;
        for (int i = 0; i < 5; i++)
          for (int w = 0; w < 8; w++) begin
            if (samples[i][0][w] !== ks[0][0][w]) share0_eq_ks = 0;
            if (samples[i][1][w] !== ks[0][1][w]) share1_eq_ks = 0;
          end
        for (int i = 1; i < 5 && !changing; i++)
          for (int share = 0; share < 2 && !changing; share++)
            for (int w = 0; w < 8 && !changing; w++)
              if (samples[i][share][w] !== samples[0][share][w]) changing = 1;
        if (share0_eq_ks && share1_eq_ks) begin
          $display("VIOLATION: key_o.key == key_state_q in StCtrlInvalid state");
          $display("  -> Bug#21/64 CONFIRMED: unmasked key material exposed");
          $display("  Injected code skips entropy XOR:");
          $display("     if (invalid_stage_sel_o && state_q == StCtrlInvalid)");
          $display("       key_o.key[i] = key_state_q[cdi_sel_o][i];");
          $display("  Clean: key_o.key = {EntropyRounds{entropy_i[i]}} (LFSR mask)");
        end else if (changing) begin
          $display("SAFE: key_o.key follows LFSR entropy mask (changes over time)");
        end else begin
          $display("INCONCLUSIVE: constant, share0==ks: %0d, share1==ks: %0d",
                   share0_eq_ks, share1_eq_ks);
        end
      end else begin
        $display("State: %s (not StCtrlInvalid)", state_str(st));
      end
      $finish;
    end
  endtask

  initial run_detection();
endmodule
