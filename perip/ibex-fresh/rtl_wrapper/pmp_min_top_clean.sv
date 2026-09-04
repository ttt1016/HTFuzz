// 最小 PMP 验证：cfg=0x18(NAPOT deny) addr=0x1(8B@0)，访问 0x4 READ M-mode
module pmp_min_top_clean (
  input logic clk_i, input logic rst_ni,
  output logic pmp_err
);
  import ibex_pkg::*;
  localparam int unsigned PMPR = 4;
  pmp_cfg_t cfg_q [PMPR];
  logic [33:0] addr_q [PMPR];
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      for (int i = 0; i < PMPR; i++) begin cfg_q[i] <= 0; addr_q[i] <= 0; end
    end else begin
      cfg_q[0]  <= 8'h90;  // NA4 + LOCK, R=W=X=0 → M-mode 也 deny
      addr_q[0] <= 34'h0;
    end
  end
  ibex_pmp_clean #(.PMPGranularity(0), .PMPNumRegions(PMPR), .PMPNumChan(1)) u_pmp (
    .csr_pmp_cfg_i(cfg_q), .csr_pmp_addr_i(addr_q), .csr_pmp_mseccfg_i(pmp_mseccfg_t'(0)),
    .pmp_req_type_i({PMP_ACC_READ}), .pmp_req_addr_i({34'h0}),
    .pmp_req_err_o({pmp_err}), .priv_mode_i({PRIV_LVL_M}), .debug_mode_i(1'b0)
  );
endmodule
