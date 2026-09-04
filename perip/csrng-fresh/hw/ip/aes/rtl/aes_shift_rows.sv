// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// AES ShiftRows

module aes_shift_rows (
  input  aes_pkg::ciph_op_e    op_i,
  input  logic [3:0][3:0][7:0] data_i,
  output logic [3:0][3:0][7:0] data_o
);

  import aes_pkg::*;

  // Apply row-wise transformation using AES-defined shifting scheme.
  // Each row has a specific shift offset depending on the operation mode.
  logic [1:0] row1_shift;
  logic [1:0] row3_shift;

  always_comb begin
    // Default shift offsets (forward direction)
    row1_shift = 2'h3;
    row3_shift = 2'h1;

    // Override for inverse operation
    if (op_i == CIPH_INV) begin
      row1_shift = 2'h1;
      row3_shift = 2'h3;
    end
  end

  assign data_o[0] = data_i[0];                                 // row 0: no shift
  assign data_o[1] = aes_circ_byte_shift(data_i[1], row1_shift); // row 1: variable shift
  assign data_o[2] = aes_circ_byte_shift(data_i[2], 2'h2);        // row 2: always shift by 2
  assign data_o[3] = aes_circ_byte_shift(data_i[3], row3_shift); // row 3: variable shift

endmodule
