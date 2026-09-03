#!/usr/bin/env python3
"""
操作序列变异器 —— 把 fuzz_engine 的 7 算子移植到 per-IP TL-UL 事务级

序列元素: (op, addr, data, mask, wait)
  op: "W"=写, "R"=读, "S"=step(n拍), "W1"=写后读
变异算子（作用于序列）:
  1. bitflip      数据位翻转
  2. boundary     数据替换为边界值（0/全F/0x80000000...）
  3. illegal_dir  对 RO/只写寄存器反向操作
  4. reorder      事务重排（打乱写顺序）
  5. window_oob   地址越界窗口
  6. fsm_violation 插入状态机违例序列（start 后再 start / 中途 clear）
  7. dup_splice   序列复制拼接
"""
import random

BOUNDARY = [0x0, 0xFFFFFFFF, 0x80000000, 0x7FFFFFFF, 0xAAAAAAAA, 0x55555555, 0x1, 0xF]

class OpSeqFuzzer:
    def __init__(self, regmap, base, seed=0):
        self.rnd = random.Random(seed)
        self.base = base
        self.regs = regmap  # {name: offset}
        self.w_regs = [(n, o) for n, o in regmap.items()]
        self.rnd.shuffle(self.w_regs)

    def gen_base_seq(self, n=10):
        """基础序列: 保证覆盖敏感写目标（KEY/WDATA/DATA_IN/MSG 类）+ 随机填充"""
        seq = []
        # 1. 敏感写目标必写（特征标记值，便于残留匹配）
        sens_keys = ["KEY", "WDATA", "DATA_IN", "MSG", "SECRET", "SEED", "IV"]
        sens_regs = [(n, o) for n, o in self.w_regs
                     if any(k in n.upper() for k in sens_keys)]
        marker = 0xDEADBEEF
        for i, (nm, off) in enumerate(sens_regs[:6]):
            seq.append(("W", off, marker + i, 0xF, 2))
        # 2. 配置/命令寄存器（触发操作）
        # CFG 值池: 覆盖常见使能组合 + 高位使能（entropy_ready=bit24 类）
        cfg_vals = [0x1, 0x3, 0x9, 0x1100002, 0x0110000A, 0x01000002, 0x1100006]
        cfg_regs = [(n, o) for n, o in self.w_regs
                    if any(k in n.upper() for k in ["CFG", "CTRL", "CMD", "TRIGGER"])
                    and "REGWEN" not in n.upper()]
        cv = self.rnd.choice(cfg_vals)
        for nm, off in cfg_regs[:2]:
            seq.append(("W", off, cv, 0xF, 3))
            seq.append(("W", off, cv, 0xF, 3))  # shadow 两阶段
        # 3. 随机填充
        for _ in range(n):
            nm, off = self.rnd.choice(self.w_regs)
            r = self.rnd.random()
            if r < 0.5:
                seq.append(("W", off, self.rnd.choice(BOUNDARY), 0xF, self.rnd.randint(0, 5)))
            elif r < 0.8:
                seq.append(("R", off, 0, 0xF, self.rnd.randint(0, 3)))
            else:
                seq.append(("S", 0, 0, 0, self.rnd.randint(10, 100)))
        return seq

    # ---- 7 算子 ----
    def mut_bitflip(self, seq):
        s = [list(x) for x in seq]
        for e in s:
            if e[0] == "W":
                for _ in range(self.rnd.randint(1, 8)):
                    e[2] ^= 1 << self.rnd.randint(0, 31)
        return [tuple(x) for x in s]

    def mut_boundary(self, seq):
        s = [list(x) for x in seq]
        for e in s:
            if e[0] == "W" and self.rnd.random() < 0.7:
                e[2] = self.rnd.choice(BOUNDARY)
        return [tuple(x) for x in s]

    def mut_illegal_dir(self, seq):
        # 对随机寄存器做"读后立即写"或"写后立即读"（违反访问时序）
        s = list(seq)
        nm, off = self.rnd.choice(self.w_regs)
        pos = self.rnd.randint(0, len(s))
        s.insert(pos, ("R", off, 0, 0xF, 0))
        s.insert(pos + 1, ("W", off, self.rnd.choice(BOUNDARY), 0xF, 0))
        return s

    def mut_reorder(self, seq):
        s = list(seq)
        if len(s) > 3:
            i, j = self.rnd.sample(range(len(s)), 2)
            s[i], s[j] = s[j], s[i]
        return s

    def mut_window_oob(self, seq):
        s = [list(x) for x in seq]
        for e in s:
            if e[0] == "W" and self.rnd.random() < 0.3:
                e[1] = (e[1] + self.rnd.choice([-0x100, 0x100, 0x1000, 4])) & 0xFFFFF
        return [tuple(x) for x in s]

    def mut_fsm_violation(self, seq):
        # 插入状态机违例: 连续两次 start / 操作中途 clear
        s = list(seq)
        nm, off = self.rnd.choice(self.w_regs)
        if any(k in nm.upper() for k in ["CMD", "TRIGGER", "CTRL", "START"]):
            pos = self.rnd.randint(0, len(s))
            s.insert(pos, ("W", off, 0x1, 0xF, 1))
            s.insert(pos + 1, ("W", off, 0x1, 0xF, 0))  # 双 start
        return s

    def mut_dup_splice(self, seq):
        # 复制前半段拼接到尾部（重复操作）
        half = seq[:max(1, len(seq) // 2)]
        return list(seq) + half

    OPS = [mut_bitflip, mut_boundary, mut_illegal_dir, mut_reorder,
           mut_window_oob, mut_fsm_violation, mut_dup_splice]

    def fuzz(self, n_seqs=20, base_len=10):
        """产出 n_seqs 个变异序列"""
        out = []
        base = self.gen_base_seq(base_len)
        out.append(("base", base))
        for i in range(n_seqs - 1):
            op = self.rnd.choice(self.OPS)
            parent = self.rnd.choice(out)[1] if out and self.rnd.random() < 0.5 else base
            try:
                mutated = op(self, parent)
                out.append((op.__name__, mutated))
            except Exception:
                continue
        return out
