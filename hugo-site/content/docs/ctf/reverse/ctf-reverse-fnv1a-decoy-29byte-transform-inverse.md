---
id: ctf-reverse-fnv1a-decoy-29byte-transform-inverse
title: FNV-1a 假 flag + 29 字节自定义逐字节变换逆解
type: scenario
domain: ctf
path: ctf/reverse
technique: fnv1a-decoy-29byte-transform-inverse
tags:
- ctf
- reverse
- fnv1a
- decoy
- byte-transform
- inverse
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T10:01:22+08:00'
  notes: 已对照原文与图 18/20/22 核对：29 字节长度、KCTF{strings_lie_dont_trust!} 固定串 decoy、FNV-1a 常量 0x14650FB0739D0383/0x100000001B3 与目标 0xE76FA3DABA5D6F3A、sub_14C0 逐字节可逆变换、sub_1400 按 8+2+10+9 分段比较、C1/C2/v4=-61 均一致；未复跑逆变换脚本。
url: /docs/ctf/reverse/ctf-reverse-fnv1a-decoy-29byte-transform-inverse/
draft: false
kb_aliases:
- ReM3
- FNV-1a 假 flag
- 29 字节变换
- 逐字节 ROR8 逆解
- 假 flag 分支
---

## 一句话结论

程序先用 FNV-1a 哈希放行一个“假 flag”分支，真正的校验在后面：`sub_14C0` 对 29 字节输入做逐字节的加法/异或/8 位循环移位变换，再与 `.rodata` 中 8+2+10+9 字节常量比较；因为每步都是可逆的 8 位运算，按公式逐字节求逆即可还原 `KCTF{w3Lc0m3_T0_tHE_r3_w0rLD}`。

## 原理

- **假 flag 分支**：`main` 先检查固定字符串 `KCTF{strings_lie_dont_trust!}`（memcmp 29 字节），命中就打印“Congrats...not sure you'll get points”；再用 `sub_1470` 做 FNV-1a 64-bit（offset `0x14650FB0739D0383`、prime `0x100000001B3`）与 `0xE76FA3DABA5D6F3A` 比较，命中打印 `KCTF{hash_passes_but_fake!!!}`。这两个都是 decoy，不进入真正的 `Success! Real flag accepted.`。
- **真校验**：只有前面都不 return，才执行 `sub_14C0(v5)` 变换，再 `sub_1400(v5, unk_2160, unk_2150, unk_2140)` 比较：
  - 前 8 字节与 `unk_2160[0:8]`；
  - 第 8–9 字节与 `unk_2160[8:10]`（2 字节）；
  - 第 10–19 字节与 `unk_2150`（10 字节）；
  - 第 20–28 字节与 `unk_2140`（9 字节）。
- **变换公式**：对每个字节 `i`，`sub_14C0` 维护 `v2/v3/v4`，用常量 `C1=0x2F910ED35CA71942`、`C2=0x6A124DE908B17733` 按 `i&7` 取字节，做 `ROL8/ROR8`、8 位加法/异或；每一步都是双射，因此可逆。
- **求逆**：从密文 `c` 反推：
  1. `v8pre_low = ROL8(c, v4)`；
  2. `v7_low = (v2 & 0xFF) ^ C2_byte`；
  3. `v6_low = ((v8pre_low ^ v7_low) - (v4 & 0xFF)) & 0xFF`；
  4. `plain = ROR8(v6_low, rot1) ^ (v6_pre & 0xFF)`；
  5. 按正向同样的规则更新 `v2/v4`（用密文字节 `c`）。
- **端序/常量**：`C1/C2` 是小端/大端按 `(C >> (8*(i&7)))` 取字节；`rot1` 来自 `(C2 >> ((8*i+16)&0x38)) & 0xFF`。写错会导致前几位正确、后面乱码。
- **为什么可行**：29 字节的变换没有跨字节扩散（每个输出只依赖当前字节和滚动状态），且所有操作可逆；正向复现可验证结果。

## 触发条件

- 输入长度固定 29；程序有多个“成功”分支，其中 FNV-1a/固定字符串只打印假 flag。
- 真校验前调用一个逐字节变换函数，随后与 `.rodata` 多段常量比较。
- 变换只含 8 位加法/异或/循环移位/查表，无强扩散或不可逆操作。
- 能从反编译/汇编读出常量与状态更新顺序。

## 利用步骤

1. 运行/反编译，标记所有成功分支；确认 `KCTF{strings_lie_dont_trust!}` 与 FNV-1a 分支是 decoy。
2. 定位真校验的 `sub_14C0` 变换和 `sub_1400` 比较；从 `.rodata` 拼出 29 字节密文（8+2+10+9）。
3. 按汇编实现 `inv_sub_14C0`：维护 `v2/v3/v4`，逐字节求 `v6_low` 和 `plain`，再用密文字节更新状态。
4. 解出 29 字节明文，检查 `KCTF{`/`}` 格式；用正向 `fwd_sub_14C0` 复验等于密文。
5. 若结果乱码，检查 `C1/C2` 取字节的端序、`rot1` 的位移、`v4` 初始值（本题 `-61`）和状态更新顺序。

## PoC

```python
C1 = 0x2F910ED35CA71942
C2 = 0x6A124DE908B17733
cipher = bytes([0xDC,0x6B,0xBB,0x4D,0xFD,0x25,0xE4,0x7E,0xC3,0x26,
                0xF5,0x72,0xAB,0x96,0xFC,0x8D,0x55,0x10,0x93,0xC1,
                0xFD,0x81,0x46,0x5B,0x7E,0x33,0x83,0x8F,0x2F])

def rol8(x, r): r &= 7; return ((x << r) & 0xFF) | ((x & 0xFF) >> (8-r) if r else 0)
def ror8(x, r): r &= 7; return (((x & 0xFF) >> r) | ((x << (8-r)) & 0xFF)) if r else (x & 0xFF)

v2 = v3 = 0
v4 = -61
plain = bytearray()
for i, c in enumerate(cipher):
    c1b = (C1 >> (8 * (i & 7))) & 0xFF
    v6_pre = (v3 + c1b) & 0xFFFFFFFF
    v3 = (v3 + 29) & 0xFFFFFFFF
    c2b = (C2 >> (8 * (i & 7))) & 0xFF
    v7_low = (v2 & 0xFF) ^ c2b
    v8pre = rol8(c, v4)
    v6_low = ((v8pre ^ v7_low) - (v4 & 0xFF)) & 0xFF
    rot1 = ((C2 >> ((8 * i + 16) & 0x38)) & 0xFF) & 7
    plain.append(ror8(v6_low, rot1) ^ (v6_pre & 0xFF))
    v2 = (v2 + 17) & 0xFFFFFFFF
    term = (((C1 >> ((8 * i + 24) & 0x38)) & 0xFFFFFFFF) ^ 0xFFFFFFA5)
    v4 = (v4 + c + term) & 0xFFFFFFFF
print(plain.decode())
```

说明：PoC 按原文 `inv_sub_14C0` 的核心公式重写；完整脚本含正向复验。未在本机对附件复跑。

## 变体与关联

- **FNV-1a 变体**：offset basis/prime/取模/跳表分发不同；参见 [[ctf-reverse-fnv1a-jumptable-base131-hash]]。
- **逐字节变换**：加法/异或/ROL8/ROR8/查表组合；关键是确认每一步可逆，并按正向顺序反向执行。
- **多段比较**：8+2+10+9 的拆分只是 rodata 布局；按反编译的 `memcmp` 长度拼回即可。
- **关联**：[[ctf-reverse-byte-pair-add-rol8-buffer-rotate-inverse]]（另一种逐字节可逆变换 + 诱饵串）、[[ctf-reverse-byte-multiply-reverse-26-byte-check-inverse]]（逐字节乘法求逆）。

## 检测与防御

- 识别：`FNV-1a` 常量、固定字符串 decoy、逐字节 `rol8/ror8` 循环、`.rodata` 多段常量。
- CTF 防守：假 flag 分支会增加干扰，但真校验的逐字节可逆变换仍可被静态求逆；应使用强扩散/整体哈希。
- 真实系统：不要自创可逆混淆作为校验；使用 HMAC/签名，密钥放服务端。
