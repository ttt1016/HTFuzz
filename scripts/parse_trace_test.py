import json, re

rm = json.load(open("/workspace/pickerfuzz/traces/hmac_regmap.json"))
base = 0x41110000

reg_by_off = {}
for r in rm:
    if r["kind"] == "reg":
        reg_by_off[r["offset"]] = r
    elif r["kind"] == "multireg":
        for i in range(r["count"]):
            reg_by_off[r["offset"] + i*r["stride"]] = {
                "name": "%s[%d]" % (r["name"], i),
                "fields": r["fields"], "swaccess": r["swaccess"]}
    elif r["kind"] == "window":
        reg_by_off[r["offset"]] = r

def parse_bits(bits):
    if ":" in bits:
        hi, lo = bits.split(":"); return int(hi), int(lo)
    b = int(bits); return b, b

def decode_fields(reg, data):
    out = []
    for f in reg.get("fields", []):
        hi, lo = parse_bits(f["bits"])
        val = (data >> lo) & ((1 << (hi-lo+1)) - 1)
        if val: out.append("%s=%d" % (f["name"], val))
    return ",".join(out) if out else "0"

events = []
with open("/workspace/pickerfuzz/traces/hmac_smoketest_tlul.log") as f:
    for line in f:
        m = re.match(r"\[TLUL\] (\d+) A op=(\d) addr=([0-9a-f]+) data=([0-9a-f]+)", line)
        if not m: continue
        cyc, op, addr, data = int(m.group(1)), int(m.group(2)), int(m.group(3),16), int(m.group(4),16)
        off = addr - base
        reg = reg_by_off.get(off)
        if reg is None:
            events.append((cyc, "R/W", "off=%s" % hex(off), hex(data)))
            continue
        kind = "W" if op in (0,1) else "R"
        nm = reg["name"]
        if reg.get("kind") == "window" or nm == "MSG_FIFO":
            events.append((cyc, kind, "MSG_FIFO", hex(data)))
        else:
            events.append((cyc, kind, nm, "%s [%s]" % (hex(data), decode_fields(reg, data))))

print("total A events:", len(events))
print("--- first 25 ---")
for e in events[:25]:
    print("cy=%d %2s %-20s %s" % e)
print("--- last 15 ---")
for e in events[-15:]:
    print("cy=%d %2s %-20s %s" % e)
