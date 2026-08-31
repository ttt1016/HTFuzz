# HTFuzz 芯片 Profile

## 用法
```bash
PF_PROFILE=profiles/opentitan.json python3 scripts/target_gen.py
PF_PROFILE=profiles/opentitan.json python3 scripts/discover_engine.py perip/hmac-ctf hmac
```

## 字段说明
| 字段 | 必填 | 说明 |
|------|------|------|
| rtl_path | ✅ | 比赛/目标 RTL 根目录 |
| perip_base | ❌ | 外设基地址（默认 0x40000000）|
| module_base | ❌ | 模块名→地址映射（discover_fuzz 用）|
| signal_patterns.sensitive | ❌ | 敏感信号名模式（默认通用列表）|
| signal_patterns.control | � | 控制信号名模式 |
| security_annotations.format | ❌ | SEC_CM / none（none=纯盲测模式）|
| security_annotations.pattern | ❌ | 标注提取正则 |
| security_annotations.strategy_map | ❌ | 标注→oracle 策略映射 |
| regmap_dir | ❌ | 寄存器映射目录 |
| bus | ❌ | tlul / apb / axi / generic |

## 新环境接入步骤
1. `cp profiles/template.json profiles/mychip.json`
2. 填 `rtl_path`（唯一必填项）
3. 若 RTL 有安全标注（如 SEC_CM），填 `security_annotations.pattern`
4. 若已知模块地址，填 `module_base`（否则 discover_fuzz 需手动指定）
5. 运行 `target_gen.py` → `discover_engine.py` → `triage_nofresh.py`
