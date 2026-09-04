// prim_subreg_shadow 单元 TB: Bug#7 检测（error_s 悬空 → shadow 错误检测失效）
module shadow_tb;
  localparam int DW = 8;
  localparam int AW = 1;

  logic clk = 0, rst_n = 0;
  always #5 clk = ~clk;

  logic [DW-1:0] wd, d, q, qs;
  logic we, de, qe, qre;
  logic err_update, err_storage;
  logic phase;
  logic re = 0;
  logic [DW-1:0] ds;

  prim_subreg_shadow #(
    .DW       ( DW ),
    .SwAccess ( prim_subreg_pkg::SwAccessRW ),
    .RESVAL   ( 8'hA5 )
  ) u_shadow (
    .clk_i     (clk),
    .rst_ni    (rst_n),
    .rst_shadowed_ni (rst_n),
    .re,
    .we, .wd,
    .de, .d,
    .qe, .q, .ds, .qs,
    .phase,
    .err_update, .err_storage
  );

  // 检测序列
  initial begin
    $display("======================================================================");
    $display("prim_subreg_shadow Bug#7: error_s 悬空 → shadow 错误检测失效");
    $display("======================================================================");
    // 复位
    rst_n = 0; we = 0; wd = 0; de = 0; d = 0;
    repeat (3) @(posedge clk);
    rst_n = 1;
    repeat (2) @(posedge clk);

    // 正常两阶段写（相同值）→ 无错误
    we = 1; wd = 8'h12; @(posedge clk); we = 0;
    @(posedge clk);
    we = 1; wd = 8'h12; @(posedge clk); we = 0;
    @(posedge clk);
    $display("[T1] 正常两阶段写 0x12: q=%02x err_update=%b err_storage=%b (期望 q=12, err=0)",
             q, err_update, err_storage);

    // 两阶段写不同值 → 应报 err_update（clean 行为）
    we = 1; wd = 8'h34; @(posedge clk); we = 0;
    @(posedge clk);
    we = 1; wd = 8'h56; @(posedge clk); we = 0;
    @(posedge clk);
    $display("[T2] 两阶段写不同值 0x34/0x56: err_update=%b (期望 1，fork 因 error_s 悬空恒 0)",
             err_update);

    // storage 错误注入: 直接翻转 shadow 内部（通过 wr_data_err 路径不可行，用 X 注入）
    // 简化: 检查 err_storage 在正常操作下恒 0 即可（fork 无检测能力）
    $display("[T3] err_storage=%b（fork: error_s 悬空 → 恒 0，storage 错误无法检测）",
             err_storage);

    $display("\n======================================================================");
    $display("VERDICT");
    $display("======================================================================");
    if (!err_update_after_write) begin
      $display("VIOLATION: 两阶段写不同值未触发 err_update");
      $display("  注入: error_s 声明但从未赋值（悬空）→ err_update/err_storage 恒 0");
      $display("  clean: err_update = (~shadow_q != wr_data) ? phase_q & wr_en : 0");
      $display("  → SEC_CM CONFIG.SHADOW 双写一致性检测完全失效");
    end else begin
      $display("SAFE: err_update 正常触发");
    end
    $finish;
  end

  // err_update 采样（T2 写后一拍）
  logic err_update_after_write;
  always_ff @(posedge clk) begin
    if (we) err_update_after_write <= err_update;
  end
endmodule
