#!/usr/bin/env python3
"""
HTFuzz 发现引擎 v2 —— 不依赖漏洞表的通用漏洞发现管线

核心思想: 对任意 per-IP DUT，自动执行 3 类通用 oracle，任何 VIOLATION 都是
"新发现"（不参考任何已知漏洞信息）:

  O-A 残留oracle: 敏感数据写入后，任意操作序列后扫描白盒敏感信号是否残留
      （覆盖: wipe 失效/擦除变注入/密钥恢复类）
  O-B 确定性oracle: 相同输入序列两次执行，比较所有白盒信号轨迹
      （覆盖: 掩码静态/PRNG 不动/熵缺失类 —— 掩码信号两次相同即可疑）
  O-C 等价类oracle: 语义等价的操作序列产生不同结果
      （覆盖: 配置位错误解码/极性反转/条件删除类）

用法: discover_engine.py <dut_dir> <module_name>
输出: findings JSON（每条含 oracle 类型/触发序列/证据信号）
"""
import ctypes, os, sys, json, random, itertools, re

# ---------- DUT 加载 ----------
class DUT:
    def __init__(self, dut_dir, name):
        os.environ["LD_LIBRARY_PATH"] = os.path.join(dut_dir, "obj_so")
        os.chdir(dut_dir)
        # 加载 DUT lib + API lib
        objdir = os.path.abspath("obj_so")
        libs = sorted(f for f in os.listdir(objdir) if f.endswith(".so"))
        # 加载顺序: 先 DUT lib（liblibpf*），后 API lib（依赖 DUT 符号）
        # 用绝对路径 + RTLD_GLOBAL，API lib 的 DT_NEEDED 仍可能失败 →
        # 失败时用绝对路径重试
        dut_libs = [f for f in libs if f.startswith("liblibpf")]
        api_libs = [f for f in libs if not f.startswith("liblibpf")]
        loaded = []
        for f in dut_libs + api_libs:
            path = os.path.join(objdir, f)
            try:
                loaded.append(ctypes.CDLL(path, mode=ctypes.RTLD_GLOBAL))
            except OSError:
                # 预加载 DUT lib 后重试
                try:
                    for df in dut_libs:
                        ctypes.CDLL(os.path.join(objdir, df), mode=ctypes.RTLD_GLOBAL)
                    loaded.append(ctypes.CDLL(path, mode=ctypes.RTLD_GLOBAL))
                except OSError as e:
                    print(f"  [warn] {f}: {e}")
        # API 句柄: 优先 API lib，否则 DUT lib
        if api_libs:
            self.api = ctypes.CDLL(os.path.join(objdir, api_libs[0]), mode=ctypes.RTLD_GLOBAL)
        elif loaded:
            self.api = loaded[0]
        else:
            raise RuntimeError("no .so loaded")
        # 标准 API 签名
        a = self.api
        a.pf_init.argtypes = [ctypes.c_uint]
        a.pf_init.restype = ctypes.c_int
        a.pf_write.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
        a.pf_write.restype = ctypes.c_int
        a.pf_read.restype = ctypes.c_uint32
        a.pf_read.argtypes = [ctypes.c_uint32]
        a.pf_step.argtypes = [ctypes.c_int]
        a.pf_step.restype = None
        self.has_reset = True
        try:
            a.pf_reset.restype = None
        except AttributeError:
            self.has_reset = False
        a.pf_sig_count.restype = ctypes.c_int
        a.pf_sig_name.restype = ctypes.c_char_p
        a.pf_sig_name.argtypes = [ctypes.c_int]
        a.pf_sig_words.restype = ctypes.c_int
        a.pf_sig_words.argtypes = [ctypes.c_int]
        self.has_sig_read = True
        try:
            a.pf_sig_read.restype = ctypes.c_uint32
            a.pf_sig_read.argtypes = [ctypes.c_char_p, ctypes.c_int]
        except AttributeError:
            self.has_sig_read = False
        # pf_sig_value 备用
        try:
            a.pf_sig_value.restype = ctypes.c_uint32
            a.pf_sig_value.argtypes = [ctypes.c_int, ctypes.c_int]
        except AttributeError:
            pass
        self.name = name
        # 必须先 pf_init（创建 DUT 实例），否则 pf_reset 解引用空指针
        try:
            self.api.pf_init(0)
        except Exception as e:
            print(f"  [warn] pf_init: {e}")
        # 枚举白盒信号
        self.sigs = {}
        try:
            n = int(a.pf_sig_count())
            self._sig_idx = {}
            for i in range(n):
                raw = a.pf_sig_name(i)
                nm = raw.decode() if raw else ""
                if nm:
                    self.sigs[nm] = int(a.pf_sig_words(i))
                    self._sig_idx[nm] = i
        except Exception as e:
            print(f"  [warn] 信号枚举失败: {e}")

    def reset(self):
        if self.has_reset:
            self.api.pf_reset()
        else:
            # 无 pf_reset 的 DUT: 用 pf_init 重建（等效复位）
            self.api.pf_init(0)

    def step(self, n=1):
        self.api.pf_step(n)

    def write(self, addr, data, mask=0xF):
        return self.api.pf_write(addr, data, mask)

    def read(self, addr):
        return self.api.pf_read(addr)

    def sig(self, name, w=0):
        if self.has_sig_read:
            return self.api.pf_sig_read(name.encode(), w)
        # 降级: 名字→索引→value
        idx = self._sig_idx.get(name)
        if idx is None:
            return 0
        return self.api.pf_sig_value(idx, w)

    def sig_all(self, name):
        return [self.sig(name, w) for w in range(self.sigs.get(name, 0))]

    def snapshot(self, names=None):
        """抓取全部（或指定）白盒信号"""
        out = {}
        for nm in (names or self.sigs):
            out[nm] = self.sig_all(nm)
        return out

# ---------- 敏感信号自动分类 ----------
# 信号分类模式（从 profile 加载，有默认值）
SENSITIVE_PATTERNS = [
    "key", "secret", "seed", "digest", "hash", "mask", "entropy",
    "priv", "credential", "otp", "token",
]
CONTROL_PATTERNS = [
    "state_q", "_q", "fsm", "ctrl", "cfg", "state", "sm_",
]

# 排除模式：wrapper 辅助信号 / 自由运行计数器（非 DUT 语义状态，必然周期性回绕，
# 会造成 O-F 倒退误报和 O-D 漂移误报）
EXCLUDE_PATTERNS = [
    "tb.div_cnt", "tb.drv_q", "tb.req_", "tb.tl_",   # wrapper 驱动/分频
    "count_cdc", "count_dst", "count_src",            # CDC 自由计数器
    "handshake", "fsm_cs",                            # CDC 协议握手 FSM（瞬态采样噪声，非安全状态机）
]

# alert/error 类信号（O-J 错误传播 oracle 的观察目标；
# 不并入 CONTROL_PATTERNS，避免污染 O-C/O-D 的控制信号集）
ALERT_PATTERNS = ["alert", "err", "fault", "intg", "escalate"]


def alert_sigs(sigs):
    """提取 alert/err 类信号（排除时钟/复位/驱动辅助与 comb next-state）"""
    out = []
    for nm in sigs:
        low = nm.lower()
        if any(p in low for p in EXCLUDE_PATTERNS):
            continue
        if any(p in low for p in ALERT_PATTERNS):
            if low.endswith("_d") or "intr_enable" in low or "err_d" in low:
                continue
            out.append(nm)
    return out


def load_signal_patterns(profile=None):
    global SENSITIVE_PATTERNS, CONTROL_PATTERNS, EXCLUDE_PATTERNS
    if profile and "signal_patterns" in profile:
        SENSITIVE_PATTERNS = profile["signal_patterns"].get("sensitive", SENSITIVE_PATTERNS)
        CONTROL_PATTERNS = profile["signal_patterns"].get("control", CONTROL_PATTERNS)
        EXCLUDE_PATTERNS = profile["signal_patterns"].get("exclude", EXCLUDE_PATTERNS)

def classify(sigs):
    """把白盒信号分为敏感/控制/其他（先过排除表）"""
    sens, ctrl, other = [], [], []
    for nm in sigs:
        low = nm.lower()
        if any(p in low for p in EXCLUDE_PATTERNS):
            other.append(nm)  # 排除信号不参与 oracle，仅保留可见性
        elif any(p in low for p in SENSITIVE_PATTERNS):
            sens.append(nm)
        elif any(p in low for p in CONTROL_PATTERNS):
            ctrl.append(nm)
        else:
            other.append(nm)
    return sens, ctrl, other

# ---------- O-A: 残留 oracle ----------
def oracle_residual(dut, regmap, findings, cfg):
    """敏感数据写入 → 多种清除/操作序列 → 扫描残留"""
    sens, ctrl, other = classify(dut.sigs)
    if not sens:
        return
    rnd = random.Random(cfg.get("seed", 0xC0FFEE))
    # 找寄存器写目标（regmap: name -> offset）
    wr_targets = [(nm, off) for nm, off in regmap.items()
                  if any(k in nm.lower() for k in ["key", "wdata", "wr_data", "data_in", "secret", "msg", "entropy_data"])]
    clear_targets = [(nm, off) for nm, off in regmap.items()
                     if any(k in nm.lower() for k in ["clear", "wipe", "flush", "trigger", "cmd", "sha3_start", "control"])]
    if not wr_targets or not clear_targets:
        return
    # 前置使能: 写所有 enable/conf 类寄存器为 mubi True（通用激活）
    en_regs = [(nm, off) for nm, off in regmap.items()
               if any(k in nm.lower() for k in ["enable", "conf", "control", "ctrl"])
               and "regwen" not in nm.lower() and "threshold" not in nm.lower()
               and "intr_enable" not in nm.lower() and "alert_test" not in nm.lower()]
    def do_enable(dut):
        # 顺序: CONF(全字段 mubi True) → REGWEN → 其余 enable/control
        # （entropy_src 实测: CONF 先写 0x66666666，REGWEN/FW_OV_CTRL 写 0x66）
        for nm, off in en_regs[:6]:
            # module_enable 触发 main_sm 转移清 FW_OV；entropy_control 改路由
            if "module_enable" in nm.lower() or "entropy_control" in nm.lower():
                continue
            if "conf" in nm.lower():
                dut.write(off, 0x66666666)
            elif "ctrl" in nm.lower() and "control" not in nm.lower():
                dut.write(off, 0x1)  # ctrl.enable 位（timer/pwrmgr 类）
            else:
                dut.write(off, 0x66)
            dut.step(2)
        for nm, off in regmap.items():
            if "regwen" in nm.lower():
                dut.write(off, 0x66)
                dut.step(2)
    for trial in range(cfg.get("trials", 8)):
        dut.reset()
        dut.step(5)
        do_enable(dut)
        dut.step(10)
        # 写敏感数据（特征值便于识别）
        marker = 0xDEAD0000 | (trial << 8) | 0xBE
        written = []
        for nm, off in wr_targets[:4]:
            for w in range(min(4, 8)):
                dut.write(off + 4 * w, marker + w)
                written.append((nm, off + 4 * w, marker + w))
        dut.step(10)
        # 随机操作序列（含清除）
        for _ in range(cfg.get("ops", 6)):
            nm, off = rnd.choice(clear_targets)
            dut.write(off, rnd.choice([0x1, 0x2, 0x4, 0x8, 0xF, marker]))
            dut.step(rnd.randint(5, 50))
        # 扫描残留
        dut.step(20)
        for snm in sens:
            words = dut.sig_all(snm)
            for w, v in enumerate(words):
                # 宽信号(>8bit)用高16位匹配；窄信号(<=8bit)用低8位匹配
                if v != 0 and any(
                    ((v & 0xFFFF0000) == (m & 0xFFFF0000)) or
                    ((v <= 0xFF) and ((v & 0xFF) == (m & 0xFF)))
                    for _, _, m in written):
                    findings.append({
                        "oracle": "O-A-residual",
                        "signal": snm, "word": w, "value": hex(v),
                        "marker": hex(marker), "trial": trial,
                        "desc": f"敏感信号 {snm}[{w}] 在清除/操作序列后残留写入标记值",
                    })
                    break

# ---------- O-B: 确定性 oracle（掩码/熵静态性）----------
def oracle_determinism(dut, regmap, findings, cfg):
    """相同输入两次执行 → 掩码/熵类信号若逐位相同则可疑"""
    sens, ctrl, other = classify(dut.sigs)
    # 掩码/熵类信号: 两次执行应该不同（随机性），相同即可疑
    mask_sigs = [nm for nm in dut.sigs
                 if any(k in nm.lower() for k in ["mask", "entropy", "rnd", "lfsr", "prng", "rand"])]
    if not mask_sigs:
        return
    # 找操作序列寄存器: CFG/CFG_SHADOWED（使能）→ MSG/WDATA（数据）→ CMD（启动）
    cfg_regs = [(nm, off) for nm, off in regmap.items()
                if any(k in nm.upper() for k in ["CFG", "CTRL"]) and "REGWEN" not in nm.upper()]
    msg_regs = [(nm, off) for nm, off in regmap.items()
                if any(k in nm.upper() for k in ["MSG", "WDATA", "WR_DATA", "DATA_IN"])]
    cmd_regs = [(nm, off) for nm, off in regmap.items()
                if "CMD" in nm.upper() or "SHA3_START" in nm.upper()]
    # CFG 候选值: 覆盖常见使能位组合（bit0/1/3/20/24 等高位使能）
    cfg_vals = [0x1, 0x3, 0x9, 0x1100002, 0x0110000A, 0x01000002]
    def do_ops(dut, cv):
        # 使能配置（含 shadow 两阶段）
        for nm, off in cfg_regs[:2]:
            dut.write(off, cv)
            dut.step(3)
            dut.write(off, cv)
            dut.step(3)
        # 写消息
        for nm, off in msg_regs[:4]:
            for w in range(2):
                dut.write(off + 4 * w, 0xA5A5A5A5 + w)
                dut.step(2)
        # 启动
        for nm, off in cmd_regs[:1]:
            dut.write(off, 0x1)
        dut.step(200)
    for trial, cv in enumerate(cfg_vals):
        runs = []
        for run in range(2):
            dut.reset()
            dut.step(5)
            do_ops(dut, cv)
            runs.append({nm: dut.sig_all(nm) for nm in mask_sigs})
        # 比较
        for nm in mask_sigs:
            r0, r1 = runs[0][nm], runs[1][nm]
            if r0 and r0 == r1 and any(v != 0 for v in r0):
                # 排除常量信号（两次都全 F 或全 0 已排除）
                findings.append({
                    "oracle": "O-B-determinism",
                    "signal": nm,
                    "value": " ".join(hex(v) for v in r0[:4]),
                    "trial": trial,
                    "desc": f"掩码/熵信号 {nm} 两次独立执行逐位相同 → 无随机性（静态掩码/PRNG 不动）",
                })

# ---------- O-C: 等价类 oracle ----------
def oracle_equivclass(dut, regmap, findings, cfg):
    """语义等价操作序列 → 结果应一致；不一致即可疑"""
    # 等价对: (序列A, 序列B) —— 例如 shadow 寄存器两阶段写顺序交换、
    # 中断先使能后触发 vs 触发后使能（对 W1C 寄存器）
    # 通用构造: 对每个 RW 寄存器，写 v 再写 v（两阶段）vs 写 v 写 v 中间插读
    rnd = random.Random(cfg.get("seed", 0xBEEF) + 1)
    rw_regs = [(nm, off) for nm, off in regmap.items()
               if any(k in nm.lower() for k in ["cfg", "ctrl", "cmd"])]
    if len(rw_regs) < 1:
        return
    for nm, off in rw_regs[:6]:
        results = []
        for variant in range(2):
            dut.reset()
            dut.step(5)
            if variant == 0:
                dut.write(off, 0x5); dut.step(5); dut.write(off, 0x5); dut.step(20)
            else:
                dut.write(off, 0x5); dut.step(5)
                _ = dut.read(off)  # 中间插读
                dut.write(off, 0x5); dut.step(20)
            results.append(dut.snapshot())
        # 比较控制信号终态
        _, ctrl, _ = classify(dut.sigs)
        for cnm in ctrl[:6]:
            if results[0][cnm] != results[1][cnm]:
                findings.append({
                    "oracle": "O-C-equivclass",
                    "signal": cnm,
                    "detail": f"寄存器 {nm} 两阶段写 vs 中间插读，控制信号 {cnm} 终态不同",
                    "seq0": [hex(v) for v in results[0][cnm][:3]],
                    "seq1": [hex(v) for v in results[1][cnm][:3]],
                    "desc": f"语义等价序列产生不同控制状态 → 可能存在中间读副作用/相位错误",
                })

# ---------- O-D: FSM 探索 oracle ----------
def oracle_fsm(dut, regmap, findings, cfg):
    """非法/边界输入驱动 FSM → 检测卡死或非法状态
    覆盖: FSM 状态机注入（非法转移/卡死/状态丢失）
    方法: 对每个控制寄存器写边界值/非法组合，观察控制信号终态:
      - 卡死: FSM 停在非 IDLE 状态且不再响应（多拍后仍不变）
      - 非法状态: onehot/编码状态出现未定义编码
    """
    _, ctrl, _ = classify(dut.sigs)
    if not ctrl:
        return
    # FSM 类信号: 名字含 state/fsm/st_q
    fsm_sigs = [nm for nm in ctrl if any(k in nm.lower() for k in
                ["state", "fsm", "st_q", "ctrl_state", "main_sm", "ack_sm"])
                and not nm.lower().endswith("_en") and not nm.lower().endswith("enable")]
    if not fsm_sigs:
        return
    # 控制寄存器（可写的）
    ctrl_regs = [(nm, off) for nm, off in regmap.items()
                 if any(k in nm.upper() for k in ["CMD", "CTRL", "CONTROL", "CFG", "TRIGGER", "ENABLE"])
                 and "REGWEN" not in nm.upper() and "STATUS" not in nm.upper()
                 and "THRESHOLD" not in nm.upper() and "WATERMARK" not in nm.upper()]
    if not ctrl_regs:
        # 无寄存器总线的 DUT（如 CPU 核）: pf_write 退化为推进时钟，
        # 仍可观测 FSM 在随机时序下的行为
        ctrl_regs = [("virtual_step", 0)]
    rnd = random.Random(cfg.get("seed", 0xC0FFEE) + 7)
    # 边界/非法值池: 全0 全1 单bit 交替位 mubi非法值
    edge_vals = [0x0, 0xFFFFFFFF, 0x1, 0x2, 0x4, 0x8, 0xAAAAAAAA, 0x55555555,
                 0x3, 0x7, 0xF, 0x10, 0x80000000]
    # ---- 基线: 正常操作下的 FSM 稳态集合（合法 busy 状态不算卡死）----
    # 方法: 复位后只写合法值（0x1/0x2 等常见使能），记录 FSM 稳态
    baseline_states = {nm: set() for nm in fsm_sigs}
    for bt in range(3):
        dut.reset()
        dut.step(5)
        for nm, off in ctrl_regs[:3]:
            if off is not None:
                dut.write(off, 0x1 if bt == 0 else (0x2 if bt == 1 else 0x0))
                dut.step(5)
        dut.step(200)  # 等正常操作完成/回到 idle
        for nm in fsm_sigs:
            baseline_states[nm].add(tuple(dut.sig_all(nm)))
        dut.step(100)
        for nm in fsm_sigs:
            baseline_states[nm].add(tuple(dut.sig_all(nm)))

    for trial in range(cfg.get("fsm_trials", 6)):
        dut.reset()
        dut.step(5)
        # 随机写 2-4 个控制寄存器的边界值（制造非法组合）
        ops = rnd.sample(ctrl_regs, min(len(ctrl_regs), rnd.randint(2, 4)))
        for nm, off in ops:
            dut.write(off, rnd.choice(edge_vals))
            dut.step(rnd.randint(2, 10))
        # 观察窗口: FSM 是否卡死（连续两次采样间隔 100 拍，状态不变且非 0）
        dut.step(50)
        snap1 = {nm: dut.sig_all(nm) for nm in fsm_sigs}
        dut.step(100)
        snap2 = {nm: dut.sig_all(nm) for nm in fsm_sigs}
        for nm in fsm_sigs:
            s1, s2 = snap1[nm], snap2[nm]
            if s1 and s1 == s2 and any(v != 0 for v in s1):
                # 关键过滤: 与基线稳态相同 → 合法 busy/idle，不算卡死
                if tuple(s1) in baseline_states[nm]:
                    continue
                # 状态非 0、100 拍不变、且不在基线稳态集合 → 真卡死候选
                findings.append({
                    "oracle": "O-D-fsm",
                    "signal": nm,
                    "value": " ".join(hex(v) for v in s1[:3]),
                    "trial": trial,
                    "confidence": "MEDIUM",
                    "desc": f"FSM 信号 {nm} 在边界输入后 100 拍保持 {s1[0]:#x} 不变，且该稳态在正常操作中未出现 → 疑似卡死/无超时恢复",
                })
            elif s1 and s1 != s2 and any(v not in (0, 0xFFFFFFFF) for v in s2):
                # 状态漂移到非常规值（不判违规，仅记录低置信度）
                if tuple(s2) in baseline_states[nm]:
                    continue
                findings.append({
                    "oracle": "O-D-fsm",
                    "signal": nm,
                    "value": " ".join(hex(v) for v in s2[:3]),
                    "trial": trial,
                    "confidence": "LOW",
                    "desc": f"FSM 信号 {nm} 在边界输入后漂移到非常规终态（低置信度）",
                })

# ---------- O-E: FIFO 压力 oracle ----------
def oracle_fifo(dut, regmap, findings, cfg):
    """FIFO 压力测试: 溢出写/空读/边界深度 → 检测数据破坏或状态错乱
    覆盖: FIFO 溢出/下溢类注入（深度篡改/指针错误）
    方法: 1) 连续写远超 FIFO 深度的数据 2) 读空 FIFO
      3) 压力后做正常操作，检查输出一致性（同输入两次结果应相同）
    """
    # FIFO 类寄存器: WDATA/MSG/DATA_IN（写口）+ STATUS（full/empty 位）
    wr_regs = [(nm, off) for nm, off in regmap.items()
               if any(k in nm.upper() for k in ["WDATA", "WR_DATA", "MSG", "DATA_IN", "FIFO"])]
    st_regs = [(nm, off) for nm, off in regmap.items() if "STATUS" in nm.upper()]
    if not wr_regs:
        return
    # 敏感/数据信号用于一致性检查
    sens, ctrl, other = classify(dut.sigs)
    check_sigs = [nm for nm in (sens + ctrl)][:8]
    depth = cfg.get("fifo_depth", 64)  # 远超典型 FIFO 深度（4-32）
    for trial in range(cfg.get("fifo_trials", 3)):
        # --- 阶段1: 溢出写 ---
        dut.reset()
        dut.step(5)
        marker = 0xF00D0000 | (trial << 8)
        for i in range(depth):
            nm, off = wr_regs[i % len(wr_regs)]
            dut.write(off, marker + i)
            if i % 8 == 0:
                dut.step(2)
        dut.step(50)
        # 溢出后状态快照
        ovf_snap = {nm: dut.sig_all(nm) for nm in check_sigs}
        # --- 阶段2: 空读（读所有可读寄存器）---
        for nm, off in list(regmap.items())[:12]:
            _ = dut.read(off)
        dut.step(20)
        # --- 阶段3: 压力后一致性: 同配置跑两次正常操作，结果应相同 ---
        results = []
        for run in range(2):
            dut.reset()
            dut.step(5)
            # 最小正常操作: 写数据 + 启动
            for nm, off in wr_regs[:2]:
                for w in range(2):
                    dut.write(off + 4 * w, 0x12345678 + w)
                    dut.step(2)
            cmd_regs = [(nm, off) for nm, off in regmap.items() if "CMD" in nm.upper()]
            for nm, off in cmd_regs[:1]:
                dut.write(off, 0x1)
            dut.step(150)
            results.append({nm: dut.sig_all(nm) for nm in check_sigs})
        # 压力历史不应影响后续正常操作（两次结果应一致）
        for nm in check_sigs:
            r0, r1 = results[0][nm], results[1][nm]
            if r0 != r1 and any(v != 0 for v in r0) :
                findings.append({
                    "oracle": "O-E-fifo",
                    "signal": nm,
                    "value": " ".join(hex(v) for v in r0[:3]) + " vs " + " ".join(hex(v) for v in r1[:3]),
                    "trial": trial,
                    "desc": f"FIFO 压力后正常操作结果不一致: {nm} → 疑似溢出破坏内部状态",
                })
                break

# ---------- O-F: 流式数据 oracle ----------
def oracle_stream(dut, regmap, findings, cfg):
    """流式数据通路活性/单调性检查（entropy_src 等流式模块）
    覆盖: 数据流卡死/计数器冻结/健康检查失效类注入
    方法: 使能数据流后，间隔采样计数器类信号:
      - 冻结: 计数器在数据持续供给时多拍不变（应递增）
      - 倒退: 计数器无清除指令时值变小（指针/计数错误）
    """
    _, ctrl, _ = classify(dut.sigs)
    # 计数器类信号: cnt/counter/event_cntr/window（排除 wrapper/自由计数器）
    # mtime/time_count 类计时器也算流式计数器
    cnt_sigs = [nm for nm in dut.sigs
                if any(k in nm.lower() for k in ["cnt", "counter", "event_cntr", "window_cntr", "depth", "mtime", "time_count"])
                and not any(p in nm.lower() for p in EXCLUDE_PATTERNS)]
    if not cnt_sigs:
        return
    # 使能类寄存器（激活数据流）
    # 顺序敏感: conf/fw_ov 先写，module_enable 最后（过早写会清流式状态）
    en_regs = [(nm, off) for nm, off in regmap.items()
               if any(k in nm.lower() for k in ["enable", "conf", "control", "ctrl"])
               and "regwen" not in nm.lower() and "threshold" not in nm.lower()
               and "entropy_control" not in nm.lower()
               and "intr_enable" not in nm.lower() and "alert_test" not in nm.lower()]
    en_regs.sort(key=lambda x: 0 if "module_enable" in x[0].lower() else 1)
    for trial in range(cfg.get("stream_trials", 3)):
        dut.reset()
        dut.step(5)
        # 激活: CONF 全字段 + REGWEN 解锁 + module_enable 最后
        for nm, off in en_regs[:6]:
            # conf=mubi 类写 0x66666666；cfg=数值类（prescale/step 等）写小值
            # 避免把 prescale 写成 0x666 导致计数器 300 拍内不 tick 的假冻结
            if "conf" in nm.lower():
                v = 0x66666666
            elif "cfg" in nm.lower():
                v = 0x00010003
            elif "ctrl" in nm.lower():
                v = 0x1  # ctrl.enable 位（timer/pwrmgr 类）
            else:
                v = 0x66
            dut.write(off, v)
            dut.step(2)
        for nm, off in regmap.items():
            if "regwen" in nm.lower():
                dut.write(off, 0x66)
                dut.step(2)
        dut.step(50)
        # 间隔采样 3 次，检查计数器活性
        samples = []
        for k in range(3):
            dut.step(150)
            samples.append({nm: dut.sig_all(nm) for nm in cnt_sigs})
        for nm in cnt_sigs:
            v0, v1, v2 = samples[0][nm], samples[1][nm], samples[2][nm]
            if not v0:
                continue
            # 冻结: 三次采样完全相同且非零（计数器应随数据流变化）
            if v0 == v1 == v2 and any(x != 0 for x in v0):
                # 排除: 该信号在复位后就是恒值（无数据流依赖）
                findings.append({
                    "oracle": "O-F-stream",
                    "signal": nm,
                    "value": " ".join(hex(x) for x in v0[:3]),
                    "trial": trial,
                    "confidence": "MEDIUM",
                    "desc": f"计数器 {nm} 在数据流使能后 300 拍三次采样完全不变（值 {v0[0]:#x}）→ 疑似计数器冻结/数据流卡死",
                })
            # 倒退: 无清除时值变小
            elif v1 != v0 and any(b < a for a, b in zip(v0, v1)) and all(x != 0 for x in v1):
                findings.append({
                    "oracle": "O-F-stream",
                    "signal": nm,
                    "value": " ".join(hex(x) for x in v1[:3]),
                    "trial": trial,
                    "confidence": "LOW",
                    "desc": f"计数器 {nm} 无清除指令时值倒退（{v0[0]:#x} → {v1[0]:#x}）→ 疑似指针/计数错误",
                })

# ---------- O-G: 脉冲宽度 oracle ----------
def oracle_pulse(dut, regmap, findings, cfg):
    """握手信号脉冲宽度检测（rom_ctrl Bug#2 类: 脉冲电平化）
    覆盖: 响应信号脉冲变电平/多拍保持（TL-UL 协议违例）
    方法: 对可读寄存器发起读事务，采样 done 后关键信号的残留拍数:
      - 正常: 握手脉冲 1 拍即消
      - 异常: done 后信号仍保持多拍（电平化）→ 同一响应被重复采样
    依赖: harness 提供 pf_rvalid_cycles()/pf_done_residual()（可选）
    """
    # 检查 harness 是否支持脉冲采样
    if not hasattr(dut.api, "pf_rvalid_cycles"):
        try:
            dut.api.pf_rvalid_cycles.restype = ctypes.c_int
        except AttributeError:
            return
    # 读目标: 所有可读寄存器（采样分布）
    rd_targets = [(nm, off) for nm, off in list(regmap.items())[:8]]
    if not rd_targets:
        return
    from collections import Counter
    width_dist = Counter()
    residual_dist = Counter()
    for nm, off in rd_targets:
        for trial in range(3):
            dut.reset()
            dut.step(20)
            v = dut.read(off)
            try:
                rc = dut.api.pf_rvalid_cycles()
                width_dist[rc] += 1
            except Exception:
                pass
            try:
                dr = dut.api.pf_done_residual()
                residual_dist[dr] += 1
            except Exception:
                pass
    # 判定: 正常脉冲宽度应为单一值（通常 1）；出现多分布或 0 = 异常
    if width_dist:
        modes = [w for w, c in width_dist.items() if c == max(width_dist.values())]
        normal_w = min(w for w in width_dist if w > 0) if any(w > 0 for w in width_dist) else 1
        for w, c in sorted(width_dist.items()):
            if w == 0 or (w != normal_w and c < max(width_dist.values())):
                findings.append({
                    "oracle": "O-G-pulse",
                    "signal": "rvalid_pulse",
                    "value": "width=%d count=%d" % (w, c),
                    "confidence": "MEDIUM",
                    "desc": f"读响应脉冲宽度异常: 宽度 {w} 出现 {c} 次（正常 {normal_w}）→ 疑似脉冲电平化/时序违例",
                })
    # 残留检测: done 后 rvalid 仍高 = 电平化
    if residual_dist:
        for dr, c in sorted(residual_dist.items()):
            if dr > 0:
                findings.append({
                    "oracle": "O-G-pulse",
                    "signal": "rvalid_residual",
                    "value": "residual=%d count=%d" % (dr, c),
                    "confidence": "HIGH",
                    "desc": f"事务完成后响应信号残留 {dr} 拍（出现 {c} 次）→ 脉冲电平化，同一响应可能被重复采样",
                })

# ---------- O-J: 错误传播 oracle ----------
def oracle_errprop(dut, regmap, findings, cfg):
    """错误传播检查: 制造错误/非法操作 → alert/err 类信号必须置位
    覆盖: alert 抑制 / 错误吞没 / escalation 无 fanout 类注入
    四类触发: T1 非法配置 / T2 越界访问 / T3 锁后写入 / T4 shadow 两阶段写冲突
    """
    alerts = alert_sigs(dut.sigs)
    if not alerts:
        return
    en_regs = [(nm, off) for nm, off in regmap.items()
               if any(k in nm.lower() for k in ("enable", "conf", "ctrl"))
               and "regwen" not in nm.lower() and "intr_enable" not in nm.lower()
               and "alert_test" not in nm.lower()]
    ctrl_regs = [(nm, off) for nm, off in regmap.items()
                 if any(k in nm.lower() for k in ("ctrl", "cfg", "cmd", "control"))]
    sens_regs = [(nm, off) for nm, off in regmap.items()
                 if any(k in nm.lower() for k in ("key", "secret", "wdata", "data_in", "msg"))]
    max_off = max([off for off in regmap.values()] or [0x100])

    def baseline():
        return {nm: dut.sig_all(nm) for nm in alerts}

    def raised(before):
        """40 拍内逐拍采样，任何 alert 信号变化/置位即传播成功，返回信号名"""
        for _ in range(20):
            dut.step(2)
            for nm in alerts:
                cur = dut.sig_all(nm)
                if cur != before[nm] and (any(v != 0 for v in cur)
                                          or any(v != 0 for v in before[nm])):
                    return nm
        return None

    res = {}

    # T1 非法配置
    if ctrl_regs:
        dut.reset(); dut.step(5)
        for nm, off in en_regs[:4]:
            dut.write(off, 0x66666666 if "conf" in nm.lower() else 0x1)
            dut.step(2)
        b = baseline()
        for nm, off in ctrl_regs[:4]:
            dut.write(off, 0xFFFFFFFF)
            dut.step(3)
        res["T1-invalid-cfg"] = raised(b)

    # T2 越界访问
    dut.reset(); dut.step(5)
    b = baseline()
    dut.write(max_off + 0x100, 0xDEADBEEF)
    dut.step(2)
    _ = dut.read(max_off + 0x104)
    dut.step(2)
    dut.write(max_off + 0x1F8, 0x12345678)
    res["T2-oob-access"] = raised(b)

    # T3 锁后写入
    if sens_regs:
        dut.reset(); dut.step(5)
        b = baseline()
        wen = [(nm, off) for nm, off in regmap.items() if "regwen" in nm.lower()]
        for nm, off in wen[:2]:
            dut.write(off, 0)
            dut.step(2)
        for nm, off in sens_regs[:4]:
            dut.write(off, 0xFEEDFACE)
            dut.step(2)
        res["T3-locked-write"] = raised(b)

    # T4 shadow 两阶段写冲突
    if ctrl_regs:
        dut.reset(); dut.step(5)
        b = baseline()
        for nm, off in ctrl_regs[:2]:
            dut.write(off, 0x5)
            dut.step(3)
            dut.write(off, 0xA)
            dut.step(3)
        res["T4-shadow-conflict"] = raised(b)

    silent = [t for t, r in res.items() if r is None]
    fired = {t: r for t, r in res.items() if r}
    if silent and len(silent) == len(res):
        findings.append({
            "oracle": "O-J-errprop",
            "signal": ",".join(alerts[:3]),
            "value": f"tried={len(res)}",
            "confidence": "HIGH",
            "desc": f"全部 {len(res)} 类错误触发均未引起任何 alert/err 信号置位 → 错误传播链断裂",
        })
    elif silent:
        findings.append({
            "oracle": "O-J-errprop",
            "signal": ",".join(alerts[:3]),
            "value": f"fired={len(fired)} silent={len(silent)}",
            "confidence": "MEDIUM",
            "desc": f"错误传播不完整: 静默触发 {silent}（{len(fired)} 类已传播）→ 疑似部分错误路径被吞没",
        })


# ---------- O-N: 多轨一致性 oracle ----------
def oracle_multirail(dut, regmap, findings, cfg):
    """冗余一致性 (SEC_CM: CTRL.REDUN / CTR.REDUN / FSM.REDUN，目标 RTL 50+ 处)
    多轨副本（如 aes gen_fsm 0/1/2 的 state_raw 三轨）运行中必须一致；
    不一致后 alert/err 必须置位 —— 不置位 = 冗余比较器失效注入。
    """
    # 自动发现多轨信号组: 按"去掉最后一段后的前缀 + 尾名"分组，组内 ≥2 且组名互不相同
    groups = {}
    for nm in dut.sigs:
        parts = nm.split(".")
        if len(parts) < 2:
            continue
        tail = parts[-1]
        prefix = ".".join(parts[:-1])
        # 轨标识: 前缀里最后一个 gen_fsm__BRA__N / gen_..._N 段归一化
        norm = re.sub(r"BRA__\d__KET__", "BRA__N__KET__", prefix)
        key = (norm, tail)
        groups.setdefault(key, []).append(nm)
    rails = {k: v for k, v in groups.items() if len(v) >= 2}
    if not rails:
        return
    alerts = alert_sigs(dut.sigs)
    en_regs = [(nm, off) for nm, off in regmap.items()
               if any(k in nm.lower() for k in ("enable", "conf", "ctrl"))
               and "regwen" not in nm.lower() and "intr_enable" not in nm.lower()
               and "alert_test" not in nm.lower()]
    ctrl_regs = [(nm, off) for nm, off in regmap.items()
                 if any(k in nm.lower() for k in ("ctrl", "cfg", "cmd", "trigger"))]
    diff_seen, alert_on_diff = False, False
    for trial in range(cfg.get("rail_trials", 3)):
        dut.reset(); dut.step(10)
        for nm, off in en_regs[:4]:
            dut.write(off, 0x66666666 if "conf" in nm.lower() else 0x1)
            dut.step(2)
        # 激活 + 压力: 写 ctrl 边界值迫使 FSM 转移
        for nm, off in ctrl_regs[:3]:
            dut.write(off, rnd_seed(cfg, trial) & 0xFFFFFFF)
            dut.step(5)
        for tick in range(30):
            dut.step(5)
            for key, names in rails.items():
                vals = [tuple(dut.sig_all(n)) for n in names]
                if any(v != vals[0] for v in vals[1:]):
                    diff_seen = True
                    # 轨间差异必须触发 alert/err（逐拍观察）
                    for _ in range(10):
                        dut.step(2)
                        for a in alerts:
                            cur = dut.sig_all(a)
                            if any(v != 0 for v in cur):
                                alert_on_diff = True
                                break
                        if alert_on_diff:
                            break
                    if alert_on_diff:
                        break
            if alert_on_diff:
                break
        if diff_seen and alert_on_diff:
            break
    if diff_seen and not alert_on_diff:
        grp_desc = "; ".join(f"{names[0].split('.')[-1]}×{len(names)}" for names in
                             list(rails.values())[:2])
        findings.append({
            "oracle": "O-N-multirail",
            "signal": grp_desc,
            "value": f"rails={len(rails)}",
            "confidence": "HIGH",
            "desc": f"多轨副本出现不一致但 alert/err 未置位（{len(rails)} 组轨）→ 冗余比较器失效",
        })
    elif not diff_seen:
        pass  # 无差异发生（激励未迫使分叉），不报


def rnd_seed(cfg, trial):
    return (cfg.get("seed", 0xC0FFEE) + trial * 7919) | 0x5A5A0000


# ---------- O-M: MUBI 编码合法性 oracle ----------
def oracle_mubi(dut, regmap, findings, cfg):
    """MUBI 多位编码 (SEC_CM: INTERSIG.MUBI/CONFIG.MUBI/LC_CTRL.INTERSIG.MUBI，31+ 处)
    名字含 mubi 的信号，值必须属于合法编码集 {True, False}；非法编码必须被检测/纠正。
    """
    mubi_sigs = [nm for nm in dut.sigs if "mubi" in nm.lower()]
    if not mubi_sigs:
        return
    VALID = {1: {0x1, 0x0}, 4: {0x6, 0x9}, 8: {0x66, 0x99}, 12: {0x666, 0x999},
             16: {0x6666, 0x9999}}
    bad = []
    en_regs = [(nm, off) for nm, off in regmap.items()
               if any(k in nm.lower() for k in ("enable", "conf"))
               and "regwen" not in nm.lower()]
    for trial in range(cfg.get("mubi_trials", 2)):
        dut.reset(); dut.step(10)
        for nm, off in en_regs[:4]:
            dut.write(off, 0x66666666 if "conf" in nm.lower() else 0x1)
            dut.step(2)
        dut.step(30)
        for nm in mubi_sigs:
            for v in dut.sig_all(nm):
                width = 1 if v <= 0xF else (8 if v <= 0xFF else (12 if v <= 0xFFF else 16))
                if width in VALID and v not in VALID[width] and v != 0:
                    bad.append((nm, hex(v)))
    if bad:
        sigs = sorted({b[0] for b in bad})[:3]
        findings.append({
            "oracle": "O-M-mubi",
            "signal": ",".join(sigs),
            "value": "; ".join(f"{n}={v}" for n, v in bad[:3]),
            "confidence": "MEDIUM",
            "desc": f"MUBI 信号出现非法编码 {bad[0][1]}（合法集 {{True,False}}）→ 编码完整性失效",
        })


# ---------- O-L: 密码符合性（KAT）oracle ----------
def _hmac_run(dut, regmap, cfg_val, key_words, msg_words, max_iter=120):
    """驱动 hmac 完成 one-block 运算，返回 (done, digest_words, err_code)"""
    d = dut
    regmap = {k.lower(): v for k, v in regmap.items()}
    d.reset(); d.step(10)
    if key_words:
        for i, w in enumerate(key_words):
            d.write(regmap["key"] + 4 * i, w)
            d.step(2)
    d.write(regmap["cfg"], cfg_val)
    d.step(5)
    d.write(regmap["cmd"], 0x1)      # start
    d.step(5)
    fifo = regmap.get("msg_fifo", 0x1000)
    for w in msg_words:
        d.write(fifo, w)
        d.step(2)
    d.write(regmap["msg_length_lower"], len(msg_words) * 32)
    d.write(regmap["msg_length_upper"], 0)
    d.write(regmap["cmd"], 0x2)      # process
    def _rd(addr):
        v = d.read(addr)
        return v.get("value") if isinstance(v, dict) else v

    done = False
    intr = 0
    for _ in range(max_iter):
        d.step(50)
        intr = _rd(0)
        if intr & 0x1:
            done = True
            break
    d.write(0, 0x1)                  # clear intr
    d.step(10)
    digest = [_rd(regmap["digest"] + 4 * i) for i in range(16)]
    err = _rd(regmap["err_code"]) if "err_code" in regmap else 0
    return done, digest, err, intr


def oracle_kat(dut, regmap, findings, cfg):
    """密码符合性: 标准向量喂入 → 结果必须与规范一致且无虚假错误。
    覆盖: 密码实现算错（P2 #43 hmac_core SHA-512）、错误中断无成因（#42）。
    """
    module = cfg.get("module", "")
    if module == "hmac":
        key = [0xDEADBEEF] * 8
        msg = [0xA5A5A5A5] * 8
        # (名称, CFG, key, 期望摘要前 4 字（大端字序）)
        exp = {
            "SHA-256":  (0x422, [0xFC8B6400, 0x1C5FDD0F, 0x2F40FB67, 0xDAE4A865]),
            "HMAC-SHA-256": (0x423, [0xC5CEBD02, 0x246EE426, 0x0A559B72, 0x715F97D7]),
            "SHA-512":  (0x502, [0x774B67B3, 0xA64977E9, 0xA42E4621, 0x7F17A6E8]),
        }
        for name, (cfg_val, expect) in exp.items():
            kw = key if "HMAC" in name else None
            done, digest, err, intr = _hmac_run(dut, regmap, cfg_val, kw, msg)
            got = digest[:len(expect)]
            if not done:
                findings.append({
                    "oracle": "O-L-kat",
                    "signal": f"hmac.{name}",
                    "value": f"err_intr={bool(intr & 0x4)} err_code={hex(err)}",
                    "confidence": "HIGH",
                    "desc": f"{name} 标准向量运算未完成"
                            + ("，且 hmac_err 置位但 ERR_CODE=0（错误无成因）"
                               if (intr & 0x4) and err == 0 else ""),
                })
            elif got != expect:
                findings.append({
                    "oracle": "O-L-kat",
                    "signal": f"hmac.{name}",
                    "value": "got=" + " ".join(hex(w) for w in got[:2]),
                    "confidence": "HIGH",
                    "desc": f"{name} 标准向量摘要不匹配（期望 {hex(expect[0])}...，密码实现算错）",
                })
    # 其他模块（aes/ascon/kmac）的 KAT 向量随 DUT 扩充逐步添加
    return


# ---------- 主流程 ----------
def main():
    if len(sys.argv) < 3:
        print("用法: discover_engine.py <dut_dir> <module_name> [regmap_json]")
        sys.exit(1)
    dut_dir, module = sys.argv[1], sys.argv[2]
    regmap_path = sys.argv[3] if len(sys.argv) > 3 else None
    regmap = {}
    # 注意: DUT.__init__ 会 chdir，所以这里必须先读 regmap（绝对路径）
    cands = []
    if regmap_path:
        cands.append(regmap_path)
    cands += [f"/workspace/HTFuzz/traces/{module}_regmap.json",
              f"/workspace/HTFuzz/traces/regmap_{module}.json"]
    for cand in cands:
        if cand and os.path.exists(cand):
            regmap = json.load(open(cand))
            print(f"regmap: {cand}")
            break
    # regmap 格式: list of {name, offset} 或 dict
    norm = {}
    if isinstance(regmap, list):
        for e in regmap:
            if not isinstance(e, dict):
                continue
            nm = e.get("name")
            off = e.get("offset", e.get("addr"))
            if nm is None or off is None:
                continue
            try:
                norm[nm] = int(off, 0) if isinstance(off, str) else off
            except Exception:
                pass
    elif isinstance(regmap, dict):
        for k, v in regmap.items():
            off = v.get("offset", v.get("addr")) if isinstance(v, dict) else v
            if off is not None:
                try:
                    norm[k] = int(off, 0) if isinstance(off, str) else off
                except Exception:
                    pass
    cfg = {"seed": 0xC0FFEE, "trials": 6, "ops": 6}
    # profile 加载（信号模式/FSM/FIFO 参数）
    try:
        from pf_profile import load_profile
        prof = load_profile()
        load_signal_patterns(prof)
        if isinstance(prof.get("signal_patterns"), dict):
            cfg["fsm_trials"] = prof["signal_patterns"].get("fsm_trials", 6)
            cfg["fifo_trials"] = prof["signal_patterns"].get("fifo_trials", 3)
    except Exception as e:
        print(f"  [warn] profile 加载失败（用默认模式）: {e}")
    dut = DUT(dut_dir, module)
    print(f"=== 发现引擎: {module} ===")
    print(f"白盒信号 {len(dut.sigs)} 个, 寄存器 {len(norm)} 个")
    sens, ctrl, other = classify(dut.sigs)
    print(f"敏感: {len(sens)}  控制: {len(ctrl)}  其他: {len(other)}")
    findings = []
    print("\n[O-A] 残留 oracle...")
    oracle_residual(dut, norm, findings, cfg)
    print("  → %d 条" % sum(1 for f in findings if f["oracle"]=="O-A-residual"))
    print("[O-B] 确定性 oracle...")
    oracle_determinism(dut, norm, findings, cfg)
    print("  → %d 条" % sum(1 for f in findings if f["oracle"]=="O-B-determinism"))
    print("[O-C] 等价类 oracle...")
    oracle_equivclass(dut, norm, findings, cfg)
    print("  → %d 条" % sum(1 for f in findings if f["oracle"]=="O-C-equivclass"))
    print("[O-D] FSM 探索 oracle...")
    oracle_fsm(dut, norm, findings, cfg)
    print("  → %d 条" % sum(1 for f in findings if f["oracle"]=="O-D-fsm"))
    print("[O-E] FIFO 压力 oracle...")
    oracle_fifo(dut, norm, findings, cfg)
    print("  → %d 条" % sum(1 for f in findings if f["oracle"]=="O-E-fifo"))
    print("[O-F] 流式数据 oracle...")
    oracle_stream(dut, norm, findings, cfg)
    print("  → %d 条" % sum(1 for f in findings if f["oracle"]=="O-F-stream"))
    print("[O-G] 脉冲宽度 oracle...")
    oracle_pulse(dut, norm, findings, cfg)
    print("  → %d 条" % sum(1 for f in findings if f["oracle"]=="O-G-pulse"))
    print("[O-J] 错误传播 oracle...")
    try:
        oracle_errprop(dut, norm, findings, cfg)
        print("  → %d 条" % sum(1 for f in findings if f["oracle"]=="O-J-errprop"))
    except Exception as e:
        print(f"  [warn] O-J 执行异常: {e}")
    print("[O-N] 多轨一致性 oracle...")
    try:
        oracle_multirail(dut, norm, findings, cfg)
        print("  → %d 条" % sum(1 for f in findings if f["oracle"]=="O-N-multirail"))
    except Exception as e:
        print(f"  [warn] O-N 执行异常: {e}")
    cfg["module"] = module
    print("[O-L] 密码符合性 KAT oracle...")
    try:
        oracle_kat(dut, norm, findings, cfg)
        print("  → %d 条" % sum(1 for f in findings if f["oracle"]=="O-L-kat"))
    except Exception as e:
        print(f"  [warn] O-L 执行异常: {e}")
    print("[O-M] MUBI 合法性 oracle...")
    try:
        oracle_mubi(dut, norm, findings, cfg)
        print("  → %d 条" % sum(1 for f in findings if f["oracle"]=="O-M-mubi"))
    except Exception as e:
        print(f"  [warn] O-M 执行异常: {e}")
    out = f"/workspace/HTFuzz/fuzz/discover_{module}.json"
    json.dump({"module": module, "findings": findings}, open(out, "w"), indent=1, ensure_ascii=False)
    # 覆盖率插桩模型：结束时写 coverage.dat（普通模型无此 API，静默跳过）
    try:
        dut.api.pf_final()
    except Exception:
        pass
    print(f"\n=== 结果: {len(findings)} 条候选 → {out} ===")
    for f in findings[:10]:
        sig = f.get("signal", "")
        desc = f.get("desc", "")[:70]
        print("  [%s] %s %s" % (f["oracle"], sig, desc))

if __name__ == "__main__":
    main()
