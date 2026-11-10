---
id: ctf-reverse-double-layer-smc-antidebug-junk-tea-key-xor-caesar
title: 两层 SMC 手剥流程：动调改 eax 绕反调试、NOP 掉花指令 jmp、取 sum 后按魔改 TEA（key 先 XOR 0x52）解出前半段，后半段再补 Caesar 逆移
type: scenario
domain: ctf
path: ctf/reverse
technique: double-layer-smc-antidebug-junk-tea-caesar-recovery
aliases:
- 两层 SMC
- smc 自解密 两层
- eax 改 0 绕反调试
- 花指令 jmp NOP
- 魔改 TEA key XOR 0x52
- 双段 flag TEA + Caesar
tags:
- ctf
- reverse
- smc
- anti-debug
- junk-code
- tea
- caesar
- ida
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:42:13+08:00'
  notes: 已对照原文核对；本次核对未读取图片；两层 SMC、sub_F11100 反调试改 eax、花指令 jmp 改 NOP、TEA 轮数 32/delta 0x9e3779b9/key 逐字 XOR 0x52、密文 8 字与后半段 Caesar 逆移 3 位均与正文 exp 一致。已按正文 exp 修正原卡错误：原卡把后 4 个字也送入 TEA 逆运算并给出 0xC6EF3720 之外的 sum 语义、且按小端取字节，实算与 exp 不符；修正后仅前 4 字做 TEA、按大端取字节、后半段直取字节后逆移 3 位，可复现正文结果（前半 flag{ZhuangBiWoR、后半 angNiFeiQiLai!!}）。未执行文内命令，仅本地复算 exp 常量。
---

## 一句话结论

遇到"两层 SMC 自解密 + 反调试 + 花指令"的 32 位 PE，不要试图静态推演：先填 32 个字符骗过长度判断，在第二层解密后的关键行下断点动调，把反调试函数返回的 `eax` 改成 0 放行、把花指令里那条跳进垃圾字节的 `jmp` 改成 NOP，就能看到真正的校验体；识别出是 TEA 家族后按动调读到的实际 `sum`（或按 `delta=0x9e3779b9`×轮数算出）写解密脚本，注意 key 在参与运算前先被 XOR 过（本例每个字 `^0x52`），且明文的第二段是"不经 TEA、直接按大端取字节后再按 Caesar 逆移 3 位"才能拼出完整 flag。

## 原理

- **两层 SMC 的意义**：第一层解密把第二层的解密器解出来，第二层再解密校验体。只静态 dump 文件只能看到第一层之后的乱码，必须让程序自己把第二层也解完——这就是为什么必须在"第二层解密完成之后、校验体执行之前"下断。
- **反调试的识别与绕过**：校验体前会先跑一个检查函数（本例 `sub_F11100`），返回值参与分支。动调到该函数返回处把 `eax` 置 0（或直接把条件跳转改成无条件跳），比静态 patch 更快且不受 SMC 影响——因为改的是寄存器值，不是被解密的代码字节。
- **花指令为什么要把 `jmp` NOP 掉**：花指令通常是一条"跳到垃圾字节再跳回来"的 `jmp`（或 `call`+`pop`），IDA 的线性/递归反汇编会被垃圾字节带偏，导致后面的真实指令被识别错位。把那条 `jmp` 改成 NOP 后重新 F5，函数体才恢复正常形态。
- **魔改 TEA 的两个识别点**：①轮数固定为 32（标准 TEA）但 `sum` 的累加顺序/初值可能不同，必须按动调读到的值来；②key 参与运算前被预处理（本例 `key[i] ^= 0x52`），这一步在 IDA 里表现为一个独立的循环，很容易被误当成"数据初始化"而漏掉——漏掉它就会得到乱码。
- **为什么解两段、且两段变换不同**：密文数组有 8 个 32 位字，只有前 4 个（两组 TEA 块）走过 TEA，解出前半段明文；后 4 个字**不再做 TEA**，直接按大端取字节就是"偏移后的后半段"，要再逆 Caesar 3 位。误把后 4 个字也送进 TEA 逆运算会直接得到乱码（本例即如此），这是该题最容易踩的坑。
- **判据闭环**：解出的两段能拼成 `flag{...}` 形态（或题目约定的前后半段拼接）即验证成功；反之应先检查 key 预处理与 `sum` 初值。

## 触发条件

- 目标为 32 位无壳 PE（或加壳但已脱），入口后进行至少一次 SMC 自解密，静态反汇编看到的是无效字节。
- 存在反调试检查函数，返回值决定是否继续（可直接改寄存器/改跳转绕过）。
- 校验体含固定轮数的 TEA/类 TEA 分组运算，且 key 或 `sum` 经过非标准预处理。
- 允许动态调试（可运行、无强反虚拟机/反调试驱动）。

## 利用步骤

1. 用 IDA 打开并定位入口后的两次 SMC 调用，确认每次解密的目标地址区间。
2. 输入满足长度校验的占位输入（本例 32 个 `a`），避免在长度判断处提前退出。
3. 在"第二层解密完成"的那一行下断点，运行到断点；此时内存里已是真实校验体。
4. 跟进反调试检查函数，在其返回处把 `eax` 改成 0（或 patch 条件跳转），继续运行。
5. 定位花指令处的 `jmp`，改成 NOP（或 `jmp` 目标前的垃圾字节），重新 F5 使函数体恢复正常。
6. 找到 TEA 主循环：确认轮数、`delta`、`sum` 初值/累加方向，以及 key 是否被预处理（如逐字 `^0x52`）。
7. 按识别到的参数写解密脚本：只对前 4 个字（两组）做 TEA 逆运算得到前半段，后 4 个字直接取字节后做 Caesar 逆移 3 位得到后半段；拼接得到 flag。
8. 若结果不可读，回到步骤 6 复核 `sum` 初值与 key 预处理顺序（两者任一错都会全错）。

## PoC

```c
// 与本例等价的解密骨架：key 先逐字 XOR 0x52，标准 TEA 逆 32 轮
#include <stdint.h>
#include <stdio.h>

static void tea_decrypt(uint32_t *v, uint32_t *k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0xC6EF3720; // 32 * 0x9e3779b9
    uint32_t delta = 0x9e3779b9;
    for (int i = 0; i < 32; i++) {
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        sum -= delta;
    }
    v[0] = v0; v[1] = v1;
}

static void caesar_shift(char *io, int n, int shift) {   // shift=-3 即逆移 3 位
    for (int i = 0; i < n; i++) {
        if (io[i] >= 'A' && io[i] <= 'Z')      io[i] = (io[i] - 'A' + 26 + shift) % 26 + 'A';
        else if (io[i] >= 'a' && io[i] <= 'z') io[i] = (io[i] - 'a' + 26 + shift) % 26 + 'a';
    }
}

int main(void) {
    uint32_t v[8] = {0x369a1583, 0x9a9e6d, 0xbe761c60, 0x3ed644a0,
                     0x64716a51, 0x6c49686c, 0x546c4f64, 0x6c21217d};
    uint32_t k[4] = {0x1234, 0x3456, 0x5678, 0x7890};
    for (int i = 0; i < 4; i++) k[i] ^= 0x52;   // 关键：key 预处理

    tea_decrypt(v, k); tea_decrypt(v + 2, k);   // 只有前 4 个字是 TEA 密文
    // 后 4 个字不做 TEA：原文 exp 直接对 v[4..7] 取字节，再做 Caesar 逆移

    char half1[17] = {0}, half2[17] = {0};
    for (int i = 0; i < 4; i++)                 // 按大端取字节（原文 exp 的 j=3..0）
        for (int j = 0; j < 4; j++) half1[i * 4 + j] = (char)((v[i] >> ((3 - j) * 8)) & 0xFF);
    for (int i = 4; i < 8; i++)
        for (int j = 0; j < 4; j++) half2[(i - 4) * 4 + j] = (char)((v[i] >> ((3 - j) * 8)) & 0xFF);

    caesar_shift(half2, 16, -3);               // 后半段再逆移 3 位
    printf("%s%s\n", half1, half2);            // flag{ZhuangBiWoRangNiFeiQiLai!!}
    return 0;
}
```

```text
动调要点（本例）：
1) 输入 32 个 a 通过长度校验；
2) 在第二层 SMC 解密完成处下断；
3) 反调试函数返回处 eax := 0；
4) 花指令 jmp -> NOP，F5 恢复正常；
5) 读 TEA 循环的轮数/delta/sum，确认 key 是否被 ^0x52 预处理。
```

## 变体与关联

- 关联：[[ctf-reverse-smc-runtime-attach-xxtea-same-var-double-shift-mix]]（同为"运行时取真代码"的 SMC 思路，但那张卡的难点在 XXTEA 的 mix 被改写成同变量双移位，本卡的难点是两层 SMC + 反调试 + 花指令的"手剥流程"与 key 预处理）、[[ctf-reverse-modified-tea-custom-delta-little-endian-decrypt]]、[[ctf-reverse-tea-delta-gettickcount-fixed-value]]（TEA 变体家族，可对照 delta/sum 的识别方法）、[[ctf-reverse-int3-basic-block-cfg-recovery]]（花指令/异常干扰下恢复 CFG 的另一手法）。
- 变体：SMC 层数可更多（每层解密下一层的解密器）；反调试可换成 `IsDebuggerPresent`/`rdtsc`/`int3`/父进程检查，绕过方式相应改为改寄存器、改跳转或 hook；Caesar 可换成 ROT13/Rail Fence 或自写置换表；TEA 可换成 XTEA/XXTEA（轮结构不同，`sum` 更新顺序也不同）。
- 边界：若 SMC 解密依赖运行时初始化（全局表/TLS），直接静态加载跑不到解密分支，必须真机运行后 attach；若存在强反调试驱动或代码完整性自校验，改寄存器/NOP 会被检测；key 若来自输入/环境而非常量，需先确定其来源。

## 检测与防御

- 检测（题目/样本侧不易谈防御，此处给分析侧判据）：文件在磁盘上存在"写自身代码段"的循环（SMC 特征）；函数体内出现跳入非指令边界数据的 `jmp`（花指令）；TEA 循环前存在对 key 数组的逐字异或/加减（key 预处理）；密文数组长度恰为 16 字节的整数倍且分两段做不同变换。
- 防御/加固（若为自有程序）：把关键校验放服务端，客户端只做展示；对代码段做完整性校验并按校验结果延迟触发错误；反调试与反虚拟机组合使用，但需注意误报与性能。
- 学习侧：本卡流程可复用于任何"多层自解密 + 反调试 + 花指令"的 CTF 逆向题，核心是"让程序自己解密 + 只改运行时状态（寄存器/标志）而不改被解密的字节"。
