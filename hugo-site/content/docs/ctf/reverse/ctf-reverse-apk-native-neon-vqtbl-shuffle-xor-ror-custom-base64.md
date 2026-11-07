---
id: ctf-reverse-apk-native-neon-vqtbl-shuffle-xor-ror-custom-base64
title: APK native NEON 校验逆向：vqtbl1q_s8 查表重排 + veorq_s8 异或 + 3 字节分组 ROR 与换表 Base64
type: scenario
domain: ctf
path: ctf/reverse
technique: neon-vqtbl-shuffle-xor-ror-custom-base64
tags:
- ctf
- reverse
- android
- apk
- arm
- neon
- simd
- base64
- native
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V246
  verified_at: '2026-11-07T12:58:22+08:00'
  notes: 已对照原文及25张图核对：strlen==48、vqtbl1q_s8/veorq_s8 三轮 t^=i、每3字节 ROL3/ROR1/不变、encodeBase64、exp 与 48 字节中间态密文一致；dup-scan 与 18558 自定义 RC4 卡仅 related（算法链不同），保留双卡；未验证点：未运行 APK，原文未给出完整自定义 Base64 表。
url: /docs/ctf/reverse/ctf-reverse-apk-native-neon-vqtbl-shuffle-xor-ror-custom-base64/
draft: false
kb_aliases:
- ARM ASM
- vqtbl1q_s8
- veorq_s8
- NEON 查表重排
- 分段 ROR
- 换表 Base64
---

## 一句话结论

APK 把 48 字节输入交给 JNI native 校验：先用 NEON `vqtbl1q_s8` 按置换表 t 重排 16 字节块并与 t 异或（三轮中每轮 `t ^= i`），再对每 3 字节做 ROL3/ROR1，最后用自定义字母表做 Base64。从 Base64 之前的 48 字节中间密文出发，按相反顺序反移位、再用逆置换还原 NEON，即可得到 flag。

## 原理

- `vqtbl1q_s8(block, t)` 以 t 的 16 个字节为索引查 block，输出 `out[j] = block[t[j]]`；`veorq_s8(..., t)` 再逐字节异或 t，因此单轮变换为 `out[j] = block[t[j]] ^ t[j]`。t 是 0..15 的置换表时该变换是双射：`block[t[j]] = out[j] ^ t[j]`，可用逆映射 `inv[t[j]] = j` 还原。
- 三轮循环 `i = 0,1,2` 分别处理 `block[16*i : 16*i+16]`；每轮结束后 `t = veorq_s8(t, vdupq_n_s8(i))`，即 t 的每个字节异或 i。逆向时按 i=0,1,2 使用同一 t 并按同样规则更新，只是先做 XOR 再逆重排。
- 位移层按每 3 字节分组：第 0 字节 `(v >> 5) | (8*v)` 等价于 8 位循环左移 3（ROL3），第 1 字节 `(v >> 1) | (v << 7)` 是 ROR1，第 2 字节不变；逆变换分别为 ROR3、ROL1、不变。
- 外层 `encodeBase64` 使用置换过的 64 字符表（不是标准 Base64 表）。若只有最终 Base64 串，要先把自定义表字符映射回标准表/索引再解码，得到 48 字节中间态；若能在 `encodeBase64` 调用前下断点，则可直接 dump 这 48 字节，跳过换表 Base64 的逆运算。
- 48 字节正好是 flag 长度；三层都是可逆双射且顺序确定，因此按调用的逆序逐步还原即可唯一恢复输入。
- 成立条件：初始 t 置换表、每轮 XOR 常量、位移参数与自定义 Base64 表都能从 `.so` 常量或调试器获得；输入长度固定为 48。

## 触发条件

- APK 的 flag 校验位于 native 层（JNI），IDA 反编译中出现 `vqtbl1q_s8`、`veorq_s8`、`vld1q_dup_s8` 等 NEON intrinsic/指令。
- JNI 函数先判断 `strlen(input) == 48`，再对 3 个 16 字节块循环处理。
- 二进制中存在 16 字节的 0..15 置换表或可直接读出的初始 t；存在每 3 字节的移位循环与自定义 Base64 表。

## 利用步骤

1. 反编译 JNI 入口，确认长度 48 与 `for (i=0;i<=2;++i)` 的三块循环，记录 `vqtbl1q_s8(x, t)` 与 `veorq_s8(..., t)` 的参数都是 t。
2. 从常量/初始化代码提取初始 t（16 字节置换）；确认每轮结束后 t 逐字节异或 i（i=0 时不变）。
3. 提取每 3 字节的位移：第 0 字节 ROL3、第 1 字节 ROR1、第 2 字节不变。
4. 获取 48 字节中间密文：优先在 `encodeBase64` 前下断点 dump；若只有最终比较串，则用二进制中的自定义 64 字符表做 Base64 解码。
5. 先逆位移（ROR3、ROL1、不变），再逆 NEON（先 `out ^ t`，再用 `inv[t[j]]=j` 重排），最后按 i 更新 t。
6. 闭环验证：将还原出的 48 字节按 NEON → 位移 → 自定义 Base64 正向重算，应得到原中间密文/最终比较串。

## PoC

```python
enc = [146,183,124,11,188,107,178,57,125,19,161,80,114,32,72,98,
       52,97,195,176,84,235,51,109,202,53,114,91,183,102,242,182,
       105,147,188,98,170,51,103,243,49,107,155,45,108,59,175,108]
t_init = [0x0D,0x0E,0x0F,0x0C,0x0B,0x0A,0x09,0x08,
          0x06,0x07,0x05,0x04,0x02,0x03,0x01,0x00]

def rol(v, r):
    return ((v << r) & 0xFF) | ((v >> (8 - r)) & 0xFF)

def ror(v, r):
    return ((v >> r) & 0xFF) | ((v << (8 - r)) & 0xFF)

def reverse_bitshifts(data):
    data = list(data)
    for j in range(0, len(data), 3):
        data[j] = ror(data[j], 3)       # 逆 ROL3
        data[j+1] = rol(data[j+1], 1)   # 逆 ROR1
    return data

def neon_decrypt(data, t_init):
    data, t = list(data), list(t_init)
    for i in range(3):
        off = i * 16
        after_xor = [data[off+j] ^ t[j] for j in range(16)]
        inv = [0] * 16
        for j, idx in enumerate(t):
            inv[idx] = j
        for k in range(16):
            data[off+k] = after_xor[inv[k]]
        if i:
            t = [x ^ i for x in t]
    return data

print(bytes(neon_decrypt(reverse_bitshifts(enc), t_init)))
# 输出为本题 48 字节 flag
```

说明：若从最终 Base64 串开始，需先用题目自定义 64 字符表解码；本 PoC 直接使用从调试器 dump 的 Base64 前中间态。`t` 中出现大于 15 的索引时 `vqtbl1q_s8` 会输出 0，逆变换不唯一，此时需要借助第二块/已知明文约束。

## 变体与关联

- 查表与异或使用不同常量：若 `vqtbl1q_s8(block, t1)` 后异或 t2，则逆变换为 `block = inv_shuffle(out ^ t2, t1)`，需分别提取 t1、t2。
- 块大小/轮数变化：常见变体是 4 块或更多轮，每轮 XOR 常量可能递增；按循环次数与 `vdupq_n_s8` 的实参确定。
- 位移模式变化：除 ROL3/ROR1 外，还可能按 `j % 2` 选择不同移位量或整块旋转；关键是逐字节找出双射并取逆。
- 关联：[[ctf-reverse-base64-table-index-mutation]]（换表 Base64 的索引魔改）、[[ctf-reverse-mmx-simd-block-xor-swap-rot-add]]（SIMD 分组 XOR/交换/旋转）、[[ctf-reverse-apk-jni-username-xtea-hex-sse-compare]]（JNI native 校验定位）。
- 边界：这类 NEON 变换只是编码/混淆，不是密码学保护；t 与位移常量静态可提取时可完全还原。

## 检测与防御

- 分析侧：优先识别固定长度判断与 NEON intrinsic；能在编码中间态下断点就不要先硬逆 Base64 表。用正向重算做闭环验证，避免把移位方向或表方向弄反。
- 题目设计侧：不要依赖静态可提取的置换表/位移常量作为唯一保护；若要防止直接还原，应引入外部密钥或单向函数。
- 检测思路：`.so` 中出现 `vqtbl1q_s8`/`veorq_s8` 组合、16 字节置换常量、固定 48 字节长度比较，以及 3 字节步进的移位循环。
