#!/usr/bin/env python3
"""ascon harness 信号绑定修正（实例名 ascon_core，key 是 4 个 32bit 字）"""
p = "/workspace/pickerfuzz/perip/ascon-ctf/harness/pf_ascon_harness.cpp"
s = open(p).read()

new_table = """// Whitebox signals: key registers (O-A residual target, Bug#43 wipe) + wipe/lc (Bug#38)
static SigEntry g_sigs[] = {
    {"ascon_core.key_share0_in_q", nullptr, 4, true},
    {"ascon_core.key_share1_in_q", nullptr, 4, true},
    {"ascon_core.key_share0_in_new_q", nullptr, 1, false},
    {"ascon_core.key_share1_in_new_q", nullptr, 1, false},
    {"ascon_core.wipe", nullptr, 1, false},
    {"ascon_core.state_q", nullptr, 1, false},
};"""
start = s.index("static SigEntry g_sigs[] = {")
end = s.index("static const int g_nsig")
s = s[:start] + new_table + "\n" + s[end:]

bind_start = s.index("static void bind_signals()")
bind_end = s.index("static uint32_t sig_word")
new_bind = """static void bind_signals() {
    #define CORE(name) rootp->ascon_perip_tb__DOT__u_dut__DOT__ascon_core__DOT__##name
    for (int i = 0; i < g_nsig; i++) {
        const char* n = g_sigs[i].name;
        void* p = nullptr;
        if (0) {}
        // key_share0_in_q 是 4 个独立 32bit 字（__BRA__31/63/95/127__KET__）
        else if (strcmp(n, "ascon_core.key_share0_in_q") == 0) p = &CORE(key_share0_in_q__BRA__31__03a0__KET__);
        else if (strcmp(n, "ascon_core.key_share1_in_q") == 0) p = &CORE(key_share1_in_q__BRA__31__03a0__KET__);
        else if (strcmp(n, "ascon_core.key_share0_in_new_q") == 0) p = &CORE(key_share0_in_new_q);
        else if (strcmp(n, "ascon_core.key_share1_in_new_q") == 0) p = &CORE(key_share1_in_new_q);
        else if (strcmp(n, "ascon_core.wipe") == 0) p = &CORE(wipe);
        else if (strcmp(n, "ascon_core.state_q") == 0) p = &CORE(state_q);
        g_sigs[i].ptr = p;
    }
    #undef CORE
}

"""
s = s[:bind_start] + new_bind + s[bind_end:]
open(p, "w").write(s)
print("ascon harness 信号绑定已修正")
