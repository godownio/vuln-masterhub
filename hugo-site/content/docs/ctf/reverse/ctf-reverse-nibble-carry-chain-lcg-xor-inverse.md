---
id: ctf-reverse-nibble-carry-chain-lcg-xor-inverse
title: 4 位半字节进位链加密逆向：低 4 位传给下一字符高 4 位，解必须按正序一边解 LCG 密钥一边推进
type: scenario
domain: ctf
path: ctf/reverse
technique: nibble-carry-chain-forward-traversal-lcg-keystream
tags:
- ctf
- reverse
- nibble
- lcg
- keystream
- stateful-encoding
- python
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:19:02+08:00'
  notes: 已对照原文核对；本次核对未读取图片；go_bytes 的 tmp=0xDEAD、x=(291x+1110)&0xffff、每字符 8 字节仅前 2 字节有效、ans=lo^state、chr=tmp1^(ans>>4)、tmp1=(ans<<4)&0xff、tmp1 初值 0x40，均与原文脚本完全一致；原文自述『把上面 xor 解出来再正序遍历』，与卡内串行推进一致；未验证点：脚本未在本机执行
url: /docs/ctf/reverse/ctf-reverse-nibble-carry-chain-lcg-xor-inverse/
draft: false
kb_aliases:
- go_bytes
- 半字节进位链
- 高低 4 位级联加密
- 状态依赖字节编码
- 正向遍历解密
---

## 一句话结论

当每个输出字节由「上一字符残留的低 4 位 XOR 本次密钥的高 4 位」拼成、且本次解出的低 4 位又要留给下一个字符时，字节之间形成强依赖链，必须**从头正序**逐字节解，同时用一个初值固定的 16 位 LCG（`x = (291x + 1110) & 0xffff`）同步推密钥；单字节独立爆破或倒序解都解不出来。

## 原理

- 编码器为每字符维护 `tmp1`（首字符固定为常量，如 `0x40`）：输出的高 4 位来自 `tmp1 ^ (ans >> 4)`，其中 `ans = 16bit_in ^ lcg_state`；输出后 `tmp1 = (ans << 4) & 0xff`，即把本次 `ans` 的低 4 位提升为下一字符的高 4 位。
- 因为 `ans` 依赖当前 LCG 状态，而状态是纯递增序列（与明文无关），所以密钥流可任意跳读、可预计算；但 `tmp1` 依赖上一个字符的解密结果，所以**明文的推进必须串行**。
- 存储上每题把每个字符写成 8 字节（两个小端 16 位或 1 字节 + 7 字节补零），有效信息只有前 2 字节：`lo = enc[i] | enc[i+1] << 8`，与 LCG 状态异或后得到 `ans`。
- 反推顺序：先由 `lcg_state` 算出 `ans = lo ^ state`，再取 `ans >> 4` 与 `tmp1` 异或得到明文高 4 位；随后 `tmp1 = (ans << 4) & 0xff` 供下一轮。首次的 `tmp1` 是硬编码常量，可从初始化代码或直接枚举 0x00–0xFF 中唯一能产出可打印前缀的那个值确定。
- 这类题的“加密”本质上是一个状态机（上一输出的低半字节喂给下一输入），安全性为零，但逆向时必须识别**依赖方向**，否则会错误地写成并行解密。

## 触发条件

- 密文按固定宽度（常见 8 字节）分块存放，每块只有前 2 字节非零。
- 加密循环里出现 `<<4`、`>>4`、`& 0xff`、`& 0xfff`/`& 0xffff` 这类半字节操作，且上一轮结果参与下一轮。
- 存在一个初值固定的伪随机数发生器（LCG/xorshift）产生逐字符密钥。

## 利用步骤

1. 定位加密循环，确认块宽（8）、有效字节位置（前 2 字节）、LCG 常数与掩码。
2. 确认 `tmp1` 的初值来源：硬编码常量或初始化函数内赋值。
3. 按块正序遍历：`state = (a*state + c) & mask`；`ans = lo ^ state`；`chr = tmp1 ^ (ans >> 4)`；`tmp1 = (ans << 4) & 0xff`。
4. 若首字符不可打印，枚举 `tmp1` 的 256 个候选，选整串落在 `[0x20,0x7e]` 且匹配已知 flag 头（如 `DASCTF{`）的那个。

## PoC

```python
tmp = 0xDEAD                 # LCG 初值
enc = [0xB9,0x22,0,0,0,0,0,0, 0xF8,0xC9,0,0,0,0,0,0]   # 每字符 8 字节，仅前 2 字节有效
flag = []
tmp1 = 0x40                  # 上一字符低 4 位（首字符硬编码初值）

for i in range(0, len(enc), 8):
    tmp = (291 * tmp + 1110) & 0xffff
    x = (enc[i+1] << 8) + enc[i]
    ans = x ^ tmp
    flag.append(tmp1 ^ (ans >> 4))
    tmp1 = (ans << 4) & 0xff

print(bytes(flag))
```

首字符未知时枚举初值：

```python
for init in range(256):
    tmp, tmp1, out = 0xDEAD, init, []
    for i in range(0, len(enc), 8):
        tmp = (291 * tmp + 1110) & 0xffff
        ans = ((enc[i+1] << 8) + enc[i]) ^ tmp
        out.append(tmp1 ^ (ans >> 4))
        tmp1 = (ans << 4) & 0xff
    if all(0x20 <= c < 0x7f for c in out) and bytes(out).startswith(b"DASCTF{"):
        print(init, bytes(out))
```

## 变体与关联

- 变体：链方向反过来（高 4 位留给下一字节的低 4 位）时，只需解方程 `ans_low = next_tmp_high ^ ...`，但仍是串行推进。
- 变体：密钥流换成 xorshift/MT19937 时，只要状态可复现，解密框架不变。
- 变体：若块宽不是 8 而是 4，`enc[i+1]<<8` 改成直接取 16 位大端。
- 关联：[[ctf-reverse-lfsr-derived-keystream-bit-swap-xor]]（伪随机密钥流 + 位操作混合）、[[ctf-reverse-custom-feistel-20round-dword-key-rotation-inverse]]（同一赛题中的多轮结构逆向）。
- 边界：如果输出不保留“上一字符 4 位”而是丢弃，链断开，可并行解；如果 LCG 常数依赖输入，则需联立求解。

## 检测与防御

- 本题为 CTF 反解题，无线上攻击面。工程上：不要用“半字节链 + 固定种子 PRNG”当混淆，密钥流与明文强相关才能提高逆向成本（如把 LCG 状态混入明文）。
