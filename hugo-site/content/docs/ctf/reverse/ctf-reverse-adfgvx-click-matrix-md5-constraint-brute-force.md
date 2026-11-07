---
id: ctf-reverse-adfgvx-click-matrix-md5-constraint-brute-force
title: ADFGVX 6×6 坐标点击矩阵 + 行列和/MD5 约束爆破还原点击路径
type: scenario
domain: ctf
path: ctf/reverse
technique: adfgvx-click-matrix-md5-constraint-brute-force
tags:
- ctf
- reverse
- android
- adfgvx
- coordinate-matrix
- md5
- brute-force
- constraint
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V127
  verified_at: '2026-11-06T04:24:35+08:00'
  notes: 已对照原文核对：6×6 坐标字母 VFDGAX、Ψ 梯度 P1=(1,1)、@LOG_TAG_DESCRIPTOR=0x1918 得 P2=(2,4)、PHASE_GAMMA 诱饵 (6,1)、Row_Total=21/Col_Total=20/相对大小、6^8 剪枝+MD5 0899ffac... 得 VVFGDXGFAXXV 与坐标表均与卡片一致。未验证点：PoC 未本机复跑；CTF 无组件版本；frontmatter 无 sources/source_url。
url: /docs/ctf/reverse/ctf-reverse-adfgvx-click-matrix-md5-constraint-brute-force/
draft: false
kb_aliases:
- ADFGVX 坐标矩阵
- 6x6 点击矩阵
- 点击路径 MD5
- OBSERVER_PROTOCOL
- VVFGDXGFAXXV
---

## 一句话结论

把 6×6 点击矩阵编码成 ADFGVX 风格的行列字母对，点击 6 次得到 12 字符路径；先由数学约束锁定前两点和行列总和，再用 MD5 作为唯一性 oracle 爆破剩余点，可在 `6^8` 空间内秒级还原 `VVFGDXGFAXXV`。

## 原理

- **坐标编码**：6 个行列索引 1..6 映射为字母 `V F D G A X`；点 `(r,c)` 编码为 `letters[r-1] + letters[c-1]`，6 个点拼成 12 字符路径。这是 ADFGVX 古典密码的“坐标字母”用法：用 6 个字母替代行列数字。
- **数学约束**：`Ψ(r,c) = (r-c)^2 + (r+c-2)^2`，梯度为 0 时 `r=c=1`，所以 P1=`(1,1)`=`VV`。
- **日志 tag 派生 P2**：`@LOG_TAG_DESCRIPTOR` 在 native 中为 `0x1918`；`T=0x1918`，`τ=(T>>12)&0xf=1`，`r_B=τ+(φ>>31)+1=2`（`φ=0x61C88647` 最高位为 0），`c_B=((r_B<<τ)^(T&0x00))&7=4`，所以 P2=`(2,4)`=`FG`。
- **PHASE_GAMMA 是诱饵**：`r_C=lim(6x²+5x)/(x²+1)=6`，`ghost=(0xDEADC0DE&0xff)^0xDE=0`，`c_C=ceil(cos(pi))+0+2=1`，直接得到 `(6,1)`；但代入全局行列和后无解，真正的 P3 是 `(3,6)`=`DX`。
- **全局约束**：`Row_Total=21`、`Col_Total=20`、`P2.c > P1.c`、`P6.c < P2.c`，再加 `MD5(sequence) = 0899ffac222b48317a57149d6df056c0`。
- **搜索空间**：固定 P1/P2 后剩余 4 个点共 8 个坐标，`6^8 ≈ 1.68e6`；行列和与相对大小先剪枝，MD5 只做最后校验。数学约束给出解空间，MD5 把路径映射到 128 位并保证唯一性。
- **最终点**：`(1,1) (2,4) (3,6) (4,2) (5,6) (6,1)` → `VV FG DX GF AX XV`；行和 `1+2+3+4+5+6=21`，列和 `1+4+6+2+6+1=20`。

## 触发条件

- 目标界面是 6×6 按钮矩阵，按钮标签/坐标字母表可从 DEX 提取。
- 代码对点击序列做 MD5/SHA 等哈希比较，目标哈希已知。
- 存在可推导的全局约束（行列和、相对大小、范围）。
- 搜索空间可剪枝到可穷举范围。

## 利用步骤

1. 从 DEX 找按钮矩阵初始化、坐标字母表、点击回调，确认每次点击追加 2 字符、6 次后提交。
2. 提取目标哈希与约束（协议文件、资源、native 常量或校验函数）。
3. 先解数学约束得到 P1/P2，并把直接公式算出的 P3 候选当作待验证项。
4. 对剩余点做带剪枝的穷举：枚举行列 1..6，检查行列总和与相对大小，再算序列字符串的 MD5。
5. 命中后按字母表反查坐标，正向重算 MD5 复核。
6. 把路径作为后续密钥派生输入（本题用于派生自定义 AES key）。

## PoC

```python
import itertools
import hashlib

letters = ['V', 'F', 'D', 'G', 'A', 'X']
target = '0899ffac222b48317a57149d6df056c0'

# 已由数学约束确定的 P1、P2
pts = [(1, 1), (2, 4)]

for rest in itertools.product(range(1, 7), repeat=8):
    cand = pts + [(rest[i], rest[i + 1]) for i in range(0, 8, 2)]
    if sum(r for r, c in cand) != 21:
        continue
    if sum(c for r, c in cand) != 20:
        continue
    if not (cand[1][1] > cand[0][1] and cand[5][1] < cand[1][1]):
        continue
    seq = ''.join(letters[r - 1] + letters[c - 1] for r, c in cand)
    if hashlib.md5(seq.encode()).hexdigest() == target:
        print(seq, cand)  # VVFGDXGFAXXV [(1,1),(2,4),(3,6),(4,2),(5,6),(6,1)]
        break
```

## 变体与关联

- **坐标表变体**：ADFGVX/ADFGX 的 6 字母可换；矩阵可 5×5、8×8；编码可能是 `row+col` 或 `col+row`。
- **约束变体**：行列和、相对大小、奇偶校验、坐标范围、重复点限制；可来自协议文件、资源或 native 常量。
- **哈希变体**：MD5 可换 SHA-1/SHA-256/CRC32；若哈希不可逆且约束不足，搜索空间会爆炸，需要更多线性/字节级约束。
- **关联卡片**：[[ctf-reverse-z3-constraint-equation-solve]]（约束方程求解）、[[ctf-reverse-png-lsb-custom-sbox-aes256-decrypt]]（同题后续密钥派生）、[[ctf-reverse-fjm-rv32-state-machine]]（输入格式与状态约束）。
- **边界**：诱饵公式（如 PHASE_GAMMA）必须结合全局约束验证；不要直接相信“数学上唯一”的中间结果。

## 检测与防御

- **CTF 逆向**：先找约束再爆破，不要直接枚举 `6^12` 全空间；用行列和剪枝，MD5 只做最后校验。
- **防御视角**：不要把路径校验只做客户端哈希；加盐/HMAC/服务端校验，避免离线枚举。
- **检测信号**：DEX 中出现 6×6 矩阵、坐标字母表、MD5 常量组合；协议文件里出现极限/梯度/行列和等约束。
