// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//

package prim_pkg;
  // The name of the technology implementation.
  parameter PrimTechName = "Generic";

  // Prim implementation enum (primgen 生成)
  typedef enum int unsigned {
    ImplGeneric = 0
  } prim_impl_e;

endpackage // prim_pkg
