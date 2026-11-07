---
id: code-analysis-reverse-themida-unlicense-oep-rc4-tea
title: Themida 3.x 用 unlicense 跟踪 OEP dump 脱壳 + 花指令 NOP：魔改 RC4 与 TEA 逆运算还原 flag
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: themida-unlicense-oep-dump-modified-rc4-tea
tags:
- reverse
- unpacking
- themida
- winlicense
- unlicense
- frida
- junk-code
- rc4
- tea
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V227
  verified_at: '2026-11-07T06:35:46+08:00'
  notes: 已对照原文 RE 与 img27-38 核对：DIE 识别 Themida/WinLicense(3.XX)、unlicense OEP=0x4218fe/BASE=0x420000/IAT 修复、75 00→90 90 花指令 NOP、RC4 密钥 th0s_i0_ke9 与加法+0x33、TEA key/33 轮/8 字节重叠窗口/offset 36→0 解密顺序均一致。复核时编译原文 C 代码实际输出近似串 DASCTF{Th1l_t8e1a_rc4_l8s_s8o_int9r3es4t1ng}（原文截图亦为同类乱码），并非干净 flag；卡内已注明原文 C 的 TEA 逆运算参数与伪代码不一致，题面意图 flag 记为 DASCTF{Th1s_TEA1s_rc4_1s_s0_1nt9r3s4t1ng}，该干净串未被原文/PoC 复现。未验证点：未动态脱壳复跑原二进制。
url: /docs/code-analysis/reverse/unpacking/code-analysis-reverse-themida-unlicense-oep-rc4-tea/
draft: false
kb_aliases:
- Themida 脱壳
- WinLicense 脱壳
- unlicense 用法
- frida OEP dump
- 花指令 NOP
- 魔改 RC4
- 魔改 TEA
- ezre
---

## 一句话结论

PE 被 Themida/WinLicense 3.x 保护时，可用 unlicense（基于 Frida 跟踪 OEP）自动 dump、修 IAT 并重建 PE；脱壳后在 IDA 中把 main 附近的 `jz/jnz +2` 花指令 NOP 掉恢复控制流，可见输入先经魔改 RC4（KSA 密钥 `th0s_i0_ke9`，输出 `in[i] + (S[S[i]+S[j]] ^ 0x33)`）再做 33 轮魔改 TEA（key `0x6E982837/0x44332211/0x11223344/0x3728986E`，重叠 8 字节窗口），按“逆 TEA（倒序窗口）→ 逆 RC4（减流密钥）”即可还原 44 字节密文对应的 flag。

## 原理

- **Themida/WinLicense 识别**：Detect It Easy 显示 `Themida/WinLicense(3.XX)`；入口点不在常规 `.text`、区段名/熵异常、导入表被保护。Themida 是商业化壳，常规 UPX 工具无效。
- **unlicense 自动化脱壳**：unlicense 用 Frida 在目标进程内跟踪执行，定位 OEP（原题 OEP=0x4218fe、BASE=0x420000），线性扫描/解析被包装的导入表，dump 内存中的 PE、修复 IAT 并重建，输出 `unpacked_ezre.exe`。它适合没有现成脱壳脚本的 Themida/WinLicense 样本。
- **花指令**：脱壳后的 main/loc_421290/loc_4210C0/loc_4213C0 入口处有 `test eax,eax; jz short loc+1; jnz short $+2` 这类恒跳/跨字节跳转，把真实指令拆散；用 IDA Patch Bytes 把 `75 00` 等替换成 `90 90`（NOP），再让 IDA 重新分析，即可恢复普通函数。
- **第一层：魔改 RC4**：`loc_4210C0` 用密钥 `th0s_i0_ke9` 做标准 KSA 初始化 256 字节 S 盒；`loc_421290` 逐字节生成流密钥：`i=(i+1)&0xFF; j=(j+S[i])&0xFF; swap(S[i],S[j]); k=S[(S[i]+S[j])&0xFF] ^ 0x33; out[n]=in[n]+k`（8 位溢出）。与标准 RC4 的区别是最后一步用加法而不是 XOR，且流密钥再异或 0x33。
- **第二层：魔改 TEA**：`loc_4213C0` 每次处理 8 字节（两个 32-bit），33 轮，key 为 `0x6E982837,0x44332211,0x11223344,0x3728986E`，轮函数使用移位 6/5、乘 32/16 和 delta `0x9E3779B8`，与标准 TEA 的移位/常量不同；main 对 `v8[i]`（i=0..36）做重叠窗口加密，再与 44 字节密文比较。
- **解密顺序**：加密是“先 RC4 变换、后 TEA（i 从 0 到 36）”，所以解密要“先逆 TEA（i 从 36 到 0 倒序）、后逆 RC4（逐字节减去流密钥）”；注意原文 C 解密代码的 TEA 逆运算移位/常量与伪代码不完全一致，直接编译运行得到的是近似串（原文截图同为 `DASCTF{Th1l_t8e1a_rc4_l8s_s8o_int9r3es4t1ng}` 一类乱码），按题面语义应为 `DASCTF{Th1s_TEA1s_rc4_1s_s0_1nt9r3s4t1ng}`，需按伪代码修正逆运算后才能复现。
- **根因/价值**：这是 CTF 逆向题的多层保护组合；复用点是“商业壳自动化脱壳 + 花指令修复 + 识别魔改 RC4/TEA 的常数与运算顺序”。

## 触发条件

- 目标为 Windows PE，DIE/PEiD 识别为 Themida/WinLicense 3.x。
- 允许运行样本（脱壳需要 Frida 注入/调试），或可离线用 unlicense 的 frida-agent 模式。
- IDA 可 patch 字节、重新反汇编；能识别 RC4 KSA 循环与 TEA 轮函数特征。
- 已知或可推导 44 字节密文与比较循环。

## 利用步骤

1. 用 Detect It Easy 确认壳类型与版本（Themida/WinLicense 3.x），记录入口点/基址。
2. 下载 unlicense（github.com/ergrelet/unlicense），执行 `unlicense.exe ezre.exe`；观察日志中的 OEP、IAT 地址、imports resolved、dump/rebuild 成功，得到 `unpacked_ezre.exe`。
3. IDA 打开 dump，定位 main；把入口处的 `jz/jnz` 花指令字节 patch 成 NOP（如 `75 00`→`90 90`），重复直到 main 伪代码可读。
4. 跟踪 `loc_421290`：识别 256 字节 S 盒初始化与 `out=in+((S[S[i]+S[j]])^0x33)`，提取 KSA 密钥 `th0s_i0_ke9`。
5. 跟踪 `loc_4213C0`：识别 33 轮 TEA 风格轮函数，提取 4 个 32-bit key，注意移位/乘数与 delta。
6. 提取 main 中 44 字节目标密文；按“逆 TEA 倒序窗口 → 逆 RC4 减流密钥”写解密程序。
7. 运行得到 flag。

## PoC

原文 C 解密代码（核心）：

```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>

unsigned char rc4_table[256];

void swap_bytes(unsigned char* a, unsigned char* b) {
    unsigned char t = *a; *a = *b; *b = t;
}

void init_rc4_table() {
    char key_str[] = "th0s_i0_ke9";
    for (int i = 0; i < 256; i++) rc4_table[i] = i;
    int key_len = strlen(key_str);
    unsigned char temp[256];
    for (int i = 0; i < 256; i++) temp[i] = key_str[i % key_len];
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + rc4_table[i] + temp[i]) & 0xFF;
        swap_bytes(&rc4_table[i], &rc4_table[j]);
    }
}

void rc4_decrypt(unsigned char input[], unsigned char output[], unsigned int length) {
    init_rc4_table();
    unsigned char i = 0, j = 0, k;
    for (unsigned int h = 0; h < length; h++) {
        i = (i + 1) & 0xFF;
        j = (j + rc4_table[i]) & 0xFF;
        swap_bytes(&rc4_table[i], &rc4_table[j]);
        k = rc4_table[(rc4_table[i] + rc4_table[j]) & 0xFF] ^ 0x33;
        output[h] = input[h] - k;
    }
}

void tea_reverse(uint32_t v[2]) {
    uint32_t key[4] = {0x6E982837, 0x44332211, 0x11223344, 0x3728986E};
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = 0xCB9E3951;
    const uint32_t delta = 0x9E3779B8;
    for (int round = 0; round <= 32; round++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 5) ^ (v1 >> 6)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0] = v0; v[1] = v1;
}

int main() {
    unsigned char cipher[44] = {
        0x50,0xD4,0xC8,0xC4,0x8F,0x84,0x40,0xEB,0x32,0x81,0x8F,0x85,
        0x6C,0xB2,0x2B,0x06,0xBF,0x05,0x35,0x5D,0x2E,0xE3,0x7D,0x46,
        0x8D,0x35,0x01,0x70,0x3A,0x80,0x81,0xC5,0xE6,0x71,0xD3,0xD6,
        0x50,0x69,0x6F,0xE2,0x6E,0x78,0x14,0xD8
    };
    unsigned char out[44];
    for (int offset = 36; offset >= 0; offset--) tea_reverse((uint32_t*)&cipher[offset]);
    rc4_decrypt(cipher, out, 44);
    for (int i = 0; i < 44; i++) putchar(out[i]);
    putchar('\n');
    return 0;
}
```

原文 C 代码直接编译运行输出（截图同）：`DASCTF{Th1l_t8e1a_rc4_l8s_s8o_int9r3es4t1ng}`（因 TEA 逆运算参数与伪代码不一致产生的近似串）；题面可读 flag 记为 `DASCTF{Th1s_TEA1s_rc4_1s_s0_1nt9r3s4t1ng}`，但原文与该 C 代码未复现该干净串。

## 变体与关联

- 壳变体：Themida、WinLicense、VMProtect、Enigma；Themida 3.x 优先试 unlicense，其他壳用 x64dbg 手动 OEP/内存 dump 或专用脚本。
- 花指令变体：`jz +1/jnz +1`、`call $+5; pop`、脏字节插入；用 IDA patch + 重新分析，或写脚本批量 NOP。
- 算法变体：魔改 RC4（加法/异或常量/自定义 KSA）、魔改 TEA/XTE A（不同 delta、轮数、移位、key 顺序）；先定位常量与轮循环再逆。
- 关联卡片：[[code-analysis-reverse-unpacking-modified-upx-unicorn-stub-emulation]]、[[code-analysis-reverse-unpacking-vmprotect-compression-sleep-cookie-oep-import-fix]]、[[code-analysis-reverse-obfuscation-ctf-reverse-oep-junk-code-call-add-retn]]、[[ctf-reverse-cpp-vtable-modified-tea-mask-xor]]、[[ctf-reverse-brotli-embedded-js-rc4-xtea-xor]]。
- 边界：unlicense 对部分 Themida 版本/反调试配置可能失败；脱壳后仍可能有 VM/虚拟化代码，需要动态跟踪；原文解密代码的 TEA 逆运算参数与伪代码存在差异（复核时编译原文 C 代码仅得到上文近似串），实际以能复现 flag 的版本为准。

## 检测与防御

- 这是逆向分析流程；防御侧关注软件保护与反调试：使用商业壳/虚拟化、完整性校验、反 Frida/反调试、代码混淆。
- 检测：PE 入口异常、区段熵高、IAT 加密、Frida 注入检测；对 unlicense/frida-agent 特征做监控。
- 加固：关键算法不要只依赖壳，使用白盒/硬件绑定/服务端校验；敏感常量运行时派生，避免静态提取。
