#!/usr/bin/env python3
"""
HTFuzz 通用配置层 —— 解耦芯片特定信息

设计原则:
  核心引擎（oracle/变异/分诊）不包含任何芯片特定信息。
  芯片相关的所有内容（路径/地址/信号模式/安全标注格式）都在 profile 文件里。

Profile 格式（JSON）:
{
  "name": "opentitan-earlgrey",
  "rtl_path": "/workspace/opentitan",
  "perip_base": 0x40000000,
  "module_base": {
    "uart": 0x40000000, "aes": 0x41100000, ...
  },
  "signal_patterns": {
    "sensitive": ["key", "secret", "seed", ...],
    "control": ["state_q", "_q", "fsm", ...]
  },
  "security_annotations": {
    "format": "SEC_CM",           // 或 "SEC_MEAS" / 自定义
    "pattern": "SEC_CM:\\s*([A-Z_.0-9]+)",
    "strategy_map": {             // 标注关键字 → oracle 策略
      "SEC_WIPE": "O-A-residual",
      "MASKING": "O-B-determinism",
      ...
    }
  },
  "regmap_dir": "/workspace/pickerfuzz/traces",
  "bus": "tlul"                   // 或 "apb"/"axi" — 影响 intg 计算方式
}

用法:
  discover_engine.py --profile profiles/opentitan.json <dut_dir> <module>
  # 或环境变量
  PF_PROFILE=profiles/opentitan.json discover_engine.py ...
"""
import json, os

DEFAULT_PROFILE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "profiles")

def load_profile(path=None):
    """加载芯片 profile；无 profile 时返回通用默认值"""
    if path is None:
        # 查找顺序: 环境变量 > 默认目录 > 内置 opentitan
        path = os.environ.get("PF_PROFILE")
        if not path:
            for cand in ["opentitan.json", "default.json"]:
                p = os.path.join(DEFAULT_PROFILE_DIR, cand)
                if os.path.exists(p):
                    path = p
                    break
    if path and os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    # 通用默认（无芯片特定信息，oracle 仍可工作但靶点生成降级）
    return {
        "name": "generic",
        "rtl_path": os.environ.get("PF_TARGET_RTL", "."),
        "perip_base": 0x40000000,
        "module_base": {},
        "signal_patterns": {
            "sensitive": ["key", "secret", "seed", "digest", "hash", "mask",
                          "entropy", "priv", "credential", "token", "nonce",
                          "rand", "cipher", "plain"],
            "control": ["state_q", "_q", "fsm", "ctrl", "cfg", "en", "status"]
        },
        "security_annotations": {
            "format": "none",  # 无标注格式 → 靶点生成降级为纯盲测
            "pattern": None,
            "strategy_map": {}
        },
        "regmap_dir": ".",
        "bus": "generic"
    }

def save_profile(profile, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(profile, f, indent=1)
    print(f"profile saved: {path}")
