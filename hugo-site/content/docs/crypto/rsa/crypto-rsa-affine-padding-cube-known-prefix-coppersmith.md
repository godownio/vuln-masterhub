---
id: crypto-rsa-affine-padding-cube-known-prefix-coppersmith
title: 自造仿射填充 (a·m + b)^3：已知 flag 前后缀时用 Coppersmith 小根恢复中间未知字节
type: scenario
domain: crypto
path: crypto/rsa
technique: rsa-affine-padding-coppersmith-known-affix
tags:
- crypto
- rsa
- e3
- padding
- coppersmith
- small-roots
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T12:28:16+08:00'
  notes: 已对照原文核对：task.py 中 e=3、a/b 由 get_random_bytes(256) 生成且与 C 一起输出、M 为 33 字节 ictf{...}、C=pow(a*bytes_to_long(M)+b,3,N)；exp 用 mhigh=ictf{+27 个零字节+} 与 f=(a*(mhigh+x*256)+b)^3-C、small_roots(X=256**27,beta=0.4) 与原文逐行一致，flag 结论亦一致；未设 affected_versions（CTF 题目无版本）；未复跑（本机无 Sage）
url: /docs/crypto/rsa/crypto-rsa-affine-padding-cube-known-prefix-coppersmith/
draft: false
kb_aliases:
- Affine Padding
- 仿射填充
- a*m+b 低指数加密
- 自造填充 Coppersmith
- 已知 flag 前后缀
---

## 一句话结论

服务端用自造填充 `C ≡ (a·m + b)^3 mod N`，其中 `a`、`b` 是公开的 2048 bit 随机整数、`m` 是 33 字节的 `ictf{...}`；把已知的 flag 头尾当常量、中间 27 字节当未知量 `x`，构造 `f(x) = (a·(m_high + 256·x) + b)^3 − C mod N`，未知量只有 216 bit 远小于 `N^(1/3)`（约 682 bit），Coppersmith `small_roots` 一次就把中间段恢复。

## 原理

- **自造填充不等于随机化填充**：代码用 `a * bytes_to_long(M) + b` 做“填充”，`a`、`b` 由 `get_random_bytes(256)` 生成但随密文一起公开。填充系数公开 ⇒ 明文仍满足确定性仿射关系，低指数攻击并未被阻断。
- **仿射结构的可解性**：`m = m_high + 256·x`（`m_high` 是把 flag 头 `ictf{`、尾部 `}` 与 27 个零字节拼起来的整数；`x` 右移 0 字节对齐，故乘 256 即左移一个字节）。代入得 `f(x) = (a·(m_high + 256·x) + b)^3 − C ≡ 0 (mod N)`，`x` 是 `f` 模 `N` 的一个根。
- **小根界**：`e = 3` 时一元 Coppersmith 可解上界约 `N^(1/3)`；`N` 为 2048 bit ⇒ 约 682 bit，而 `x < 256^27 = 2^216`，余量充足，甚至 `beta` 可以压低到 0.4 仍能出根（原文即用 `beta=0.4`）。
- **为什么 `beta` 可以小于 1**：`small_roots` 的 `beta` 表示“模数中与根相关的因子至少有多大”。此处根只与 `N` 本身相关，`beta=1` 最稳；原文用 0.4 是因为把 `a·m+b` 视作近似随机、格维数更小更快，属于可接受的工程折中。
- **与真实 PKCS#1 v1.5 的差别**：PKCS#1 填充带随机字节且高 16 bit 固定为 `0x0002`，攻击者无法把明文写成“已知前后缀 + 小未知段”的多项式；这里填充系数全公开，等价于把明文直接暴露成仿射形式。

## 触发条件

- `e` 很小（3/5/7），且没有把明文整段做随机化。
- 填充函数形如 `a·m + b`，`a`、`b`（或其中至少 `a`）随密文一起给出。
- 明文有已知前缀/后缀（flag 格式、固定头部），未知中间段比特数小于 `N^(1/e)`。
- 能得到 `N`、`e`、`C`，并能跑 Sage 的 `small_roots`。

## 利用步骤

1. 从输出里取 `N`、`a`、`b`、`C`，确认 `e=3`。
2. 按 flag 格式把明文拆成 `m_high`（已知头 + 未知段置零 + 已知尾）与未知段 `x`；注意对齐单位（本例按字节对齐，故 `x` 的系数是 256）。
3. 在 `PolynomialRing(Zmod(N))` 构造 `f = (a*(m_high + 256*x) + b)^3 - C`。
4. `f.monic().small_roots(X=256^27, beta=0.4)`；若空集，依次把 `beta` 调到 1、增大 `X`、换 `epsilon` 或改用 Howgrave-Graham 自实现格。
5. 回代 `pow(a*(m_high + 256*int(x)) + b, 3, N) == C` 校验，再 `long_to_bytes` 拼回 flag。

## PoC

```python
# sage
from Crypto.Util.number import bytes_to_long, long_to_bytes

N, a, b, C = ...          # 全部来自题目输出
unknown_bytes = 27
m_high = bytes_to_long(b"ictf{" + b"\x00" * unknown_bytes + b"}")

R.<x> = PolynomialRing(Zmod(N))
f = (a * (m_high + x * 256) + b) ** 3 - C
roots = f.monic().small_roots(X=256 ** unknown_bytes, beta=0.4)
assert roots
x = int(roots[0])
m = m_high + x * 256
assert pow(a * m + b, 3, N) == C
print(long_to_bytes(m))
```

## 变体与关联

- 变体：`e=5/7` 时界缩小到 `N^(1/5)`、`N^(1/7)`，可容忍的未知字节数同步下降。
- 变体：未知段不在末尾（例如 flag 中间一段被遮住）时，把“未知段之后的所有已知内容”左移相应字节数并入 `m_high` 的系数，仍然是一元多项式。
- 变体：若填充是 `a·m + b` 且同一 `m` 在多个模数下广播，可先用 CRT 合并多个三次多项式再求小根（见 [[crypto-rsa-affine-broadcast-crt-coppersmith]]）。
- 关联：[[crypto-rsa-e3-known-prefix-suffix-coppersmith]]（无仿射变换的教科书版已知前后缀）、[[crypto-rsa-partial-plaintext-high-bits-coppersmith]]（只知高位的同类小根）、[[crypto-rsa-e3-small-plaintext-integer-cube-root]]（明文更短、密文未模约减时直接开立方）。

## 检测与防御

- 防御：使用 OAEP 等带随机性的标准填充；任何“自造填充”在 `e` 很小时都应视为不安全。
- 防御：不要把填充参数（`a`、`b`）与密文一起输出；若必须公开，也不能让明文保持仿射可逆结构（例如改为逐字节随机异或后再整体加密）。
- 检测：代码里出现 `pow(a * bytes_to_long(m) + b, 3, n)`、或 `a`/`b` 与密文同文件输出，即可判定该方案在 `e=3` 下必败。
- 响应：见 `e` 小于 65537 且填充参数公开的部署，按明文可能已泄露处理，直接轮换密钥与重加密历史数据。
