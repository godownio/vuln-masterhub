---
id: ctf-reverse-obfusheader-dynamic-memcmp-rand-xor-nibble-swap
title: obfusheader.h 花指令混淆动调：内存断点定位 memcmp，转储 rand 值与密文逆半字节交换/取反/16 位 XOR
type: scenario
domain: ctf
path: ctf/reverse
technique: obfusheader-dynamic-memcmp-rand-xor-nibble-swap
tags:
- ctf
- reverse
- windows
- obfuscation
- dynamic-debugging
- memcmp
- rand
- xor
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V246
  verified_at: '2026-11-07T12:58:24+08:00'
  notes: 已对照原文及25张图核对：长度40、动调 call r8/sub_*EAA70/E7930、memcmp 取密文、rand() 16位逐字 XOR、nibble swap+取反与 exp 一致；已将‘28字节’更正为原文截图的32字节示例；未验证点：未复跑样本，rand 序列依赖运行环境。
url: /docs/ctf/reverse/ctf-reverse-obfusheader-dynamic-memcmp-rand-xor-nibble-swap/
draft: false
kb_aliases:
- obfusheader.h
- 花指令
- 内存断点
- rand 转储
- nibble swap
- 半字节交换
---

## 一句话结论

对使用 obfusheader.h 类花指令/指令替换混淆的 Windows PE，静态反编译很难还原时改用动态调试：靠输入/成功/失败提示定位核心函数，用内存断点盯住输入缓冲，在 `memcmp` 处取加密后的输入与固定目标，并在 `rand()` 返回处转储 16 位随机数；本题的校验是“每 2 字节与一次 `rand()` 的低 16 位异或 → 每字节高/低半字节交换 → 逐字节按位取反”，逆序执行即可从 40 字节密文还原 flag。

## 原理

- 混淆层堆叠大量重复花指令，使 IDA 反编译出现冗余跳转/伪调用，但程序仍通过提示字符串、长度判断、加密完成提示、比较失败提示暴露执行阶段。
- 第一个变换函数（文章中 `sub_7FF7A5157842`）的实现是 `for (i=0; i<input_len>>1; ++i) *(WORD*)&input[2*i] ^= rand();`：按小端 16 位字读取输入并异或一次 `rand()` 返回值（取低 16 位）。40 字节输入会消耗 20 次 `rand()`。
- 第二个变换对每个字节做 `data[i] = (data[i] >> 4) | (data[i] << 4)`，即 8 位高/低半字节交换；随后 `data[i] = ~data[i]` 逐字节取反。两者都是逐字节双射且可交换。
- 最终 `memcmp(data, target, len)` 与固定密文比较。内存断点命中时可直接读到两边的缓冲区，无需理解花指令本身。
- 逆过程：对 `memcmp` 处的密文先逐字节取反、再做半字节交换（顺序可交换），然后按运行时转储的 20 个 16 位随机数按小端 2 字节异或，即得明文。
- 随机数不一定要预测 PRNG 种子：在同一进程内、`rand()` 返回后读 EAX/RAX，或在 `memcmp` 处用密文与已知明文关系反推对应随机数，都可完成还原。
- 成立条件：能动态附加调试器并下内存断点；输入长度固定（本题试出为 40）；加密与比较都在同一进程内完成。

## 触发条件

- 目标为 Windows PE，使用了 obfusheader.h 或类似花指令/指令替换混淆，静态反编译不可读。
- 程序有明确的 `Please enter the flag:`、`Encryption done, time to compare!`、`Wrong flag!` 一类提示字符串，便于定位输入与比较阶段。
- 校验前存在 `memcmp`/`strcmp` 等一次性比较，且输入缓冲可被内存断点命中。
- `rand()` 在同一进程内被调用，返回时可读取。

## 利用步骤

1. 运行程序并试长度：本题输入 32 字节（截图示例为 8 位数字重复 4 次）仍提示 too short，最终确认 flag 长度为 40。
2. 在输入读取后对输入缓冲区下内存读断点（或先对提示字符串下断点再回溯），单步跟入第一个 `call r8`，再进入 `sub_*EAA70`/`sub_*E7930` 等核心函数。
3. 找到计算输入长度的调用（文章中 `call rdx`，返回 `rax=0x28`），确认其后的变换函数。
4. 对 `memcmp` 下断点（文章通过 `call r14` 前的比较函数定位，并在 `memcmp` 内部/调用处命中断下），命中时 dump 加密后的输入缓冲与固定目标缓冲。
5. 在 `rand()` 返回处下断点或用脚本记录每次返回值；本题需 20 个 16 位值。若花指令导致断点过多，可用条件断点按调用序号计数。
6. 逆序还原：先取反，再半字节交换，最后按小端 16 位与转储的随机数异或，得到 40 字节明文。
7. 闭环验证：把还原的明文按正向“16 位 XOR 随机数 → 半字节交换 → 取反”重算，应等于 `memcmp` 处的密文。

## PoC

```python
enc = [0x5C,0xAF,0xB0,0x1C,0xFC,0xEF,0xC7,0x8F,0x01,0xDF,
       0x36,0x39,0x13,0xDA,0x47,0x2D,0x5B,0x7E,0xFF,0x8F,
       0x7D,0xF8,0xD2,0xFA,0xFA,0x3D,0x83,0xFD,0x73,0xA8,
       0x06,0x1C,0xAB,0x7B,0x40,0xAC,0x65,0xB9,0xDD,0x1B]
rand16 = [0x4c76,0x7db8,0x4764,0x50f8,0x43a7,0x33c8,0x6787,0x69d4,
          0x4c7e,0x6141,0x4064,0x0fa5,0x4d13,0x7fa9,0x21f9,0x5cc0,
          0x1776,0x759e,0x01fd,0x334c]

def decode(data):
    data = [(~b) & 0xFF for b in data]              # 逆取反
    data = [((b >> 4) | ((b << 4) & 0xFF)) & 0xFF
            for b in data]                           # 逆半字节交换（自逆）
    out = bytearray(data)
    for i, r in enumerate(rand16):
        w = (out[2*i] | (out[2*i+1] << 8)) ^ r      # 小端 16 位 XOR
        out[2*i], out[2*i+1] = w & 0xFF, (w >> 8) & 0xFF
    return bytes(out)

print(decode(enc))
```

说明：`enc` 与 `rand16` 均应在调试器命中断点时转储，不要依赖文章中的静态值；实际样本的 `rand()` 序列可能因运行环境/调用次数不同而变化。

## 变体与关联

- 随机数来源变化：若使用 `srand(time(NULL))` 且每次运行不同，可在同一进程内转储，或利用已知 flag 前缀反推出前几个 16 位随机数，再顺推其余值。
- 变换顺序变化：若实现为“先取反再半字节交换”，由于两者可交换，逆过程形式不变；若是逐字节 XOR 而非 16 位字 XOR，按实际宽度调整。
- 花指令变体：混淆可能包含无效分支、垃圾 `call`、重复跳转；动态调试时优先用内存断点和提示字符串，不要在静态反编译上硬啃。
- 关联：[[ctf-reverse-memcmp-length-bug-state-machine-reward]]（memcmp 比较长度问题）、[[code-analysis-reverse-anti-debug-ldpreload-memcmp-hook-differential-transform]]（hook memcmp 记录实参）、[[tools-ida-python-conditional-breakpoint-register]]（IDA 条件断点按寄存器值命中）。
- 边界：若比较前数据被多处原地修改且无法在 `memcmp` 处拿到完整中间态，需要从输入路径逐段下断点；若程序使用加密比较（例如比较哈希），则不能直接逆出明文。

## 检测与防御

- 分析侧：先用提示字符串和内存断点定位关键阶段，再在 `memcmp` 与 `rand()` 处收集运行时数据；这是绕过花指令混淆成本最低的路径。
- 样本检测：花指令混淆的 PE 常出现大量重复字节模式、异常跳转与 `rand()` 调用；但真正判据仍是行为（输入读取、比较、网络/文件操作），不能只靠静态特征。
- 题目设计侧：把随机数在运行时转储给分析者后，固定 XOR 变换仍可逆；若要提高难度，应避免在比较点保留完整中间明文，或使用不可逆校验。
