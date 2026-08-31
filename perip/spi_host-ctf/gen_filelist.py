#!/usr/bin/env python3
"""生成 spi_host filelist（pkg 优先 + wrapper 最后）"""
import os
base = "/workspace/pickerfuzz/perip/spi_host-ctf"
os.chdir(base)

pkgs = [
    "hw/ip/prim/rtl/prim_assert.sv",
    "hw/ip/prim/rtl/prim_flop_macros.sv",
    "hw/ip/prim/rtl/prim_mubi_pkg.sv",
    "hw/ip/prim_generic/rtl/prim_pkg.sv",
    "hw/ip/prim/rtl/prim_secded_pkg.sv",
    "hw/ip/prim/rtl/prim_cipher_pkg.sv",
    "hw/ip/prim/rtl/prim_count_pkg.sv",
    "hw/ip/prim/rtl/prim_util_pkg.sv",
    "hw/ip/prim/rtl/prim_alert_pkg.sv",
    "hw/ip/tlul/rtl/tlul_pkg.sv",
    "hw/top_earlgrey/rtl/top_pkg.sv",
    "hw/top_earlgrey/rtl/top_racl_pkg.sv",
    "hw/ip/spi_device/rtl/spi_device_pkg.sv",
    "hw/ip/spi_host/rtl/spi_host_cmd_pkg.sv",
    "hw/ip/spi_host/rtl/spi_host_reg_pkg.sv",
]
all_files = []
for root, dirs, files in os.walk("hw"):
    for fn in sorted(files):
        if fn.endswith(".sv"):
            all_files.append(os.path.join(root, fn))
# pkg 优先，其余按路径排序
ordered = [f for f in pkgs if f in all_files]
rest = sorted(f for f in all_files if f not in ordered)
files = ordered + rest + ["rtl_wrapper/spi_host_perip_tb.sv"]
with open("filelist.f", "w") as f:
    f.write("\n".join(files) + "\n")
print("filelist.f:", len(files), "files")
