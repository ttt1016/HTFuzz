#!/usr/bin/env python3
"""
通用 filelist 生成器 —— 从闭包文件集自动推导编译序（差分 fresh DUT 批建用）

规则（沉淀自 adc_ctrl/otp_ctrl/aes 构建经验）:
  1. prim_assert.sv / 纯宏文件最前（宏定义必须先于使用者）
  2. 包文件按 package 间 import 依赖拓扑排序
  3. 其余 module 文件宽松序（Verilator 在 elaboration 消解）
  4. rtl_wrapper/*_perip_tb.sv 恒最后

用法: gen_filelist.py <dut_dir>   （生成/覆写 dut_dir/filelist.f）
"""
import os, re, sys


def collect(base="hw"):
    """收集 {文件: (kind, pkg名, imports)} 与 incdir 列表"""
    entries = []
    incdirs = set()
    for root, dirs, files in os.walk(base):
        for fn in files:
            if not fn.endswith((".sv", ".svh", ".svpp")):
                continue
            p = os.path.join(root, fn)
            rel = os.path.relpath(p)
            incdirs.add(os.path.relpath(root))
            try:
                body = open(p, errors="ignore").read()
            except Exception:
                continue
            pkg_m = re.search(r"^\s*package\s+(\w+)", body, re.M)
            has_mod = bool(re.search(r"^\s*(module|macromodule)\s+\w+", body, re.M))
            imports = set(re.findall(r"import\s+(\w+)\s*::", body))
            if fn.endswith(".svh") or "svpp" in fn:
                kind = "inc"          # include 体, 不进 filelist
            elif pkg_m:
                kind = "pkg"
            elif not has_mod:
                kind = "macro"        # 纯宏/函数库文件
            else:
                kind = "mod"
            pkg = pkg_m.group(1) if pkg_m else None
            entries.append({"path": rel, "kind": kind, "pkg": pkg,
                            "imports": imports, "body": body})
    return entries, sorted(incdirs)


def topo_packages(pkg_entries):
    """包间 import 依赖拓扑排序（被依赖者在前; 环用名字序兜底）"""
    name2f = {e["pkg"]: e for e in pkg_entries}
    deps = {}
    for e in pkg_entries:
        deps[e["pkg"]] = {i for i in e["imports"] if i in name2f and i != e["pkg"]}
    order, seen, visiting = [], set(), set()

    def visit(n):
        if n in seen or n not in deps:
            return
        if n in visiting:      # 环: 截断
            return
        visiting.add(n)
        for d in sorted(deps.get(n, ())):
            visit(d)
        visiting.discard(n)
        seen.add(n)
        order.append(name2f[n]["path"])

    for n in sorted(deps):
        visit(n)
    return order


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    os.chdir(root)
    entries, incdirs = collect()

    assert_f = [e["path"] for e in entries
                if e["kind"] == "assert" or
                (e["kind"] == "macro" and "assert" in e["path"])]
    macro_f = [e for e in entries if e["kind"] == "macro"
               and "assert" not in e["path"]]
    pkgs = [e for e in entries if e["kind"] == "pkg"]
    mods = [e["path"] for e in entries if e["kind"] == "mod"]

    ordered = ["hw/ip/prim/rtl/prim_assert.sv"] if os.path.exists(
        "hw/ip/prim/rtl/prim_assert.sv") else []
    ordered += [p for p in assert_f if p not in ordered]
    ordered += topo_packages(pkgs)
    for p in mods:
        if p not in ordered:
            ordered.append(p)

    wrapper = None
    wd = os.path.join("rtl_wrapper")
    if os.path.isdir(wd):
        cands = [f for f in os.listdir(wd) if f.endswith("_perip_tb.sv")]
        if cands:
            ordered.append(os.path.join("rtl_wrapper", sorted(cands)[0]))

    lines = ["+incdir+hw"] + [f"+incdir+{d}" for d in incdirs] + ordered
    open("filelist.f", "w").write("\n".join(lines) + "\n")
    print(f"[gen_filelist] {len(entries)} 文件 / {len(incdirs)} incdir → filelist.f")


if __name__ == "__main__":
    main()
