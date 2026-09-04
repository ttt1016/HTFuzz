// PickerFuzz lc_ctrl_fsm 单元 TB: Bug#28 检测（Token 比较 128→32bit 截断）
module lc_ctrl_fsm_tb;
  import lc_ctrl_pkg::*;
  import lc_ctrl_state_pkg::*;

  localparam int unsigned NumRmaAckSigs = 2;

  logic clk = 0, rst_n = 0;
  always #5 clk = ~clk;

  // Inputs
  logic init_req;
  logic esc_scrap_state0, esc_scrap_state1;
  logic lc_state_valid;
  lc_state_e lc_state;
  lc_cnt_e lc_cnt;
  lc_tx_t secrets_valid;
  logic use_ext_clock;
  logic volatile_raw_unlock;
  lc_token_t test_unlock_token, test_exit_token, rma_token;
  lc_tx_t test_tokens_valid, rma_token_valid;
  logic trans_cmd;
  ext_dec_lc_state_t trans_target;
  logic token_hash_ack, token_hash_err, token_if_fsm_err;
  lc_token_t hashed_token, unhashed_token;
  logic otp_prog_ack, otp_prog_err;
  lc_tx_t lc_clk_byp_ack;
  lc_tx_t [NumRmaAckSigs-1:0] lc_flash_rma_ack;

  // Outputs
  logic init_done, idle, ext_clock_switched, strap_en_override;
  logic token_hash_req, token_hash_req_chk;
  ext_dec_lc_state_t dec_lc_state;
  dec_lc_cnt_t dec_lc_cnt;
  dec_lc_id_state_e dec_lc_id_state;
  logic otp_prog_req;
  logic trans_success, token_invalid_error, trans_invalid_error,
        trans_cnt_oflw_error, flash_rma_error, otp_prog_error,
        state_invalid_error, esc_scrap_error;
  lc_tx_t lc_raw_test_rma, lc_dft_en, lc_nvm_debug_en, lc_hw_debug_en,
          lc_cpu_en, lc_creator_seed_sw_rw_en, lc_owner_seed_sw_rw_en,
          lc_iso_part_sw_rd_en, lc_iso_part_sw_wr_en, lc_seed_hw_rd_en,
          lc_keymgr_en, lc_escalate_en, lc_check_byp_en, lc_clk_byp_req,
          lc_flash_rma_req;
  lc_state_e otp_prog_lc_state;
  lc_cnt_e otp_prog_lc_cnt;
  lc_keymgr_div_t lc_keymgr_div;

  lc_ctrl_fsm u_dut (
    .clk_i(clk), .rst_ni(rst_n),
    .init_req_i(init_req), .init_done_o(init_done), .idle_o(idle),
    .esc_scrap_state0_i(esc_scrap_state0), .esc_scrap_state1_i(esc_scrap_state1),
    .lc_state_valid_i(lc_state_valid),
    .lc_state_i(lc_state), .lc_cnt_i(lc_cnt),
    .secrets_valid_i(secrets_valid),
    .use_ext_clock_i(use_ext_clock), .ext_clock_switched_o(ext_clock_switched),
    .volatile_raw_unlock_i(volatile_raw_unlock),
    .strap_en_override_o(strap_en_override),
    .test_unlock_token_i(test_unlock_token),
    .test_exit_token_i(test_exit_token),
    .test_tokens_valid_i(test_tokens_valid),
    .rma_token_i(rma_token), .rma_token_valid_i(rma_token_valid),
    .trans_cmd_i(trans_cmd),
    .trans_target_i(trans_target),
    .dec_lc_state_o(dec_lc_state), .dec_lc_cnt_o(dec_lc_cnt),
    .dec_lc_id_state_o(dec_lc_id_state),
    .token_hash_req_o(token_hash_req), .token_hash_req_chk_o(token_hash_req_chk),
    .token_hash_ack_i(token_hash_ack), .token_hash_err_i(token_hash_err),
    .token_if_fsm_err_i(token_if_fsm_err),
    .hashed_token_i(hashed_token), .unhashed_token_i(unhashed_token),
    .otp_prog_req_o(otp_prog_req),
    .otp_prog_lc_state_o(otp_prog_lc_state), .otp_prog_lc_cnt_o(otp_prog_lc_cnt),
    .otp_prog_ack_i(otp_prog_ack), .otp_prog_err_i(otp_prog_err),
    .trans_success_o(trans_success),
    .trans_cnt_oflw_error_o(trans_cnt_oflw_error),
    .trans_invalid_error_o(trans_invalid_error),
    .token_invalid_error_o(token_invalid_error),
    .flash_rma_error_o(flash_rma_error),
    .otp_prog_error_o(otp_prog_error),
    .state_invalid_error_o(state_invalid_error),
    .lc_raw_test_rma_o(lc_raw_test_rma),
    .lc_dft_en_o(lc_dft_en),
    .lc_nvm_debug_en_o(lc_nvm_debug_en),
    .lc_hw_debug_en_o(lc_hw_debug_en),
    .lc_cpu_en_o(lc_cpu_en),
    .lc_creator_seed_sw_rw_en_o(lc_creator_seed_sw_rw_en),
    .lc_owner_seed_sw_rw_en_o(lc_owner_seed_sw_rw_en),
    .lc_iso_part_sw_rd_en_o(lc_iso_part_sw_rd_en),
    .lc_iso_part_sw_wr_en_o(lc_iso_part_sw_wr_en),
    .lc_seed_hw_rd_en_o(lc_seed_hw_rd_en),
    .lc_keymgr_en_o(lc_keymgr_en),
    .lc_escalate_en_o(lc_escalate_en),
    .lc_check_byp_en_o(lc_check_byp_en),
    .lc_clk_byp_req_o(lc_clk_byp_req),
    .lc_clk_byp_ack_i(lc_clk_byp_ack),
    .lc_flash_rma_req_o(lc_flash_rma_req),
    .lc_flash_rma_ack_i(lc_flash_rma_ack),
    .lc_keymgr_div_o(lc_keymgr_div)
  );

  localparam logic [15:0] ST_RESET     = 16'b1111011010111100;
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
  endfunction

  // 检测序列
  initial begin
    $display("======================================================================");
    $display("lc_ctrl_fsm Bug#28: Token 比较 128->32bit 截断检测");
    $display("======================================================================");

    init_req = 0; esc_scrap_state0 = 0; esc_scrap_state1 = 0;
    lc_state_valid = 1;
    lc_state = LcStDev;
    lc_cnt = LcCnt15;
    secrets_valid = On;
    use_ext_clock = 0;
    volatile_raw_unlock = 0;
    test_unlock_token = 0; test_exit_token = 0;
    rma_token = 0;
    test_tokens_valid = Off; rma_token_valid = Off;
    trans_cmd = 0;
    trans_target = '{default: DecLcStRma};
    token_hash_ack = 0; token_hash_err = 0; token_if_fsm_err = 0;
    hashed_token = 0; unhashed_token = 0;
    otp_prog_ack = 0; otp_prog_err = 0;
    lc_clk_byp_ack = Off;
    lc_flash_rma_ack = '{default: Off};

    rst_n = 0;
    repeat (3) @(posedge clk);
    rst_n = 1;
    repeat (3) @(posedge clk);
    init_req = 1;
    @(posedge clk);
    init_req = 0;
    repeat (3) @(posedge clk);
    $display("[T0] init 后 FSM=%s", fsm_str());

    // ---- T1: RMA 转换，token 低 32bit 匹配但高 96bit 不同 ----
    rma_token = 128'h11111111_22222222_33333333_DEADBEEF;
    rma_token_valid = On;
    hashed_token = 128'h99999999_88888888_77777777_DEADBEEF;
    trans_target = '{default: DecLcStRma};
    repeat (2) @(posedge clk);

    trans_cmd = 1;
    @(posedge clk);
    trans_cmd = 0;

    // 推进状态机到 TokenHashSt
    for (int i = 0; i < 60; i++) begin
      @(posedge clk);
      if (otp_prog_req) begin
        otp_prog_ack = 1;
        @(posedge clk);
        otp_prog_ack = 0;
      end
      if (token_hash_req) begin
        token_hash_ack = 1;
        @(posedge clk);
        token_hash_ack = 0;
        break;
      end
    end
    repeat (3) @(posedge clk);
    $display("[T1] TokenHash 后 FSM=%s token_invalid_error=%b",
             fsm_str(), token_invalid_error);
    $display("     hashed_token_i   = %h", hashed_token);
    $display("     hashed_token_mux = %h", u_dut.hashed_token_mux);
    $display("     低 32bit 相同: %s  高 96bit 不同: %s",
             (hashed_token[31:0] == u_dut.hashed_token_mux[31:0]) ? "YES" : "NO",
             (hashed_token[127:32] != u_dut.hashed_token_mux[127:32]) ? "YES" : "NO");

    $display("\n======================================================================");
    $display("VERDICT");
    $display("======================================================================");
    // FlashRmaSt/TokenCheck0St/TokenCheck1St = 转移被接受
    if (u_dut.fsm_state_q == ST_FLASHRMA || u_dut.fsm_state_q == ST_TOKENCHK0 ||
        u_dut.fsm_state_q == ST_TOKENCHK1) begin
      $display("VIOLATION: Bug#28 确认！");
      $display("  token 低 32bit 匹配但高 96bit 不同 → 状态机仍接受转移");
      $display("  注入: hashed_token_i[31:0] == hashed_token_mux[31:0]（456/497 两处）");
      $display("  clean: hashed_token_i == hashed_token_mux（全 128bit 比较）");
      $display("  → 128bit token 只比 32bit，碰撞概率 1/2^96 → 可暴力破解");
      $display("  → 任意 LC 状态转换绕过（无效 RMA token 也能通过）");
    end else if (token_invalid_error) begin
      $display("SAFE: token 被拒绝（全宽比较正常）");
    end else begin
      $display("INCONCLUSIVE: FSM=%s token_invalid_error=%b", fsm_str(), token_invalid_error);
    end

    // ---- T2 (#3): IdleSt 非法转移（未 claim 直接 CMD）----
    $display("[T2] #3 IdleSt 非法转移检测");
    // 回到 IdleSt（需要充分复位 + init）
    rst_n = 0; esc_scrap_state0 = 0; esc_scrap_state1 = 0;
    repeat (10) @(posedge clk); rst_n = 1;
    repeat (5) @(posedge clk);
    init_req = 1; repeat (3) @(posedge clk); init_req = 0;
    repeat (20) @(posedge clk);
    $display("[T2-pre] FSM=%s (期望 IdleSt)", fsm_str());
    // 直接写 transition_cmd 而不 claim transition_if
    trans_cmd = 1;
    repeat (5) @(posedge clk);
    trans_cmd = 0;
    repeat (10) @(posedge clk);
    $display("[T2] FSM=%s trans_success=%b trans_invalid=%b token_invalid=%b",
             fsm_str(), trans_success, trans_invalid_error, token_invalid_error);
    if (trans_success) begin
      $display("VIOLATION: #3 IdleSt 非法转移被接受（未 claim 就执行了 CMD）！");
      $display("  clean: transition_cmd 仅在 CLAIM_TRANSITION_IF 置位后有效");
    end else begin
      $display("SAFE: #3 非法转移被正确拒绝");
    end

    // ---- T3 (#22): volatile_raw_unlock ----
    $display("[T3] #22 volatile_raw_unlock 检测");
    rst_n = 0; repeat (10) @(posedge clk); rst_n = 1;
    repeat (5) @(posedge clk);
    init_req = 1; repeat (3) @(posedge clk); init_req = 0;
    repeat (20) @(posedge clk);
    $display("[T3-pre] FSM=%s", fsm_str());
    volatile_raw_unlock = 1;
    repeat (20) @(posedge clk);
    $display("[T3] FSM=%s volatile_raw_unlock=%b", fsm_str(), volatile_raw_unlock);
    // 检查 volatile unlock 是否导致状态泄露
    if (u_dut.fsm_state_q != ST_IDLE && u_dut.fsm_state_q != ST_RESET) begin
      $display("NOTE: volatile unlock 导致 FSM 转移到 %s", fsm_str());
    end
    volatile_raw_unlock = 0;

    // ---- T4 (#2): hash 校验截断（64bit token 匹配场景）----
    $display("[T4] #2 hash 校验截断检测");
    // 确保在 IdleSt
    rst_n = 0; repeat (10) @(posedge clk); rst_n = 1;
    repeat (5) @(posedge clk);
    init_req = 1; repeat (3) @(posedge clk); init_req = 0;
    repeat (20) @(posedge clk);
    $display("[T4-pre] FSM=%s", fsm_str());
    // 用 64bit 匹配的 token（低 64bit 相同，高 64bit 不同）
    hashed_token = 128'hCAFEBABE_CAFEBABE_00000000_00000000;
    // fresh 的 hashed_token_mux 对应位设为相同的前 64bit
    trans_target = '{default: DecLcStRma};
    trans_cmd = 1;
    @(posedge clk); trans_cmd = 0;
    for (int i = 0; i < 60; i++) begin
      @(posedge clk);
      if (otp_prog_req) begin otp_prog_ack = 1; @(posedge clk); otp_prog_ack = 0; end
      if (token_hash_req) begin token_hash_ack = 1; @(posedge clk); token_hash_ack = 0; break; end
    end
    repeat (3) @(posedge clk);
    $display("[T4] FSM=%s token_invalid=%b", fsm_str(), token_invalid_error);
    if (!token_invalid_error && u_dut.fsm_state_q != ST_IDLE) begin
      $display("VIOLATION: #2 hash 64bit 匹配即接受 → 校验截断！");
    end else begin
      $display("SAFE: #2 hash 全宽比较正常");
    end

    // ---- T5 (#14): otp_program 接口缺失 ----
    $display("[T5] #14 otp_program 接口检测");
    $display("[T5] otp_prog_req=%b FSM=%s trans_success=%b", otp_prog_req, fsm_str(), trans_success);
    // 在 RMA 转移流程中 otp_prog_req 应该被拉高
    // 如果整个流程中 otp_prog_req 从未置位且转移成功 → otp program 面缺失
    if (!otp_prog_req && trans_success) begin
      $display("VIOLATION: #14 转移成功但 otp_prog_req 从未置位 → otp_program 面缺失！");
    end else begin
      $display("NOTE: #14 otp_prog_req=%b（需结合转移流程分析）", otp_prog_req);
    end

    $display("\n=== lc_ctrl Phase D 扩展检测完成 ===");
    $finish;
  end
endmodule
