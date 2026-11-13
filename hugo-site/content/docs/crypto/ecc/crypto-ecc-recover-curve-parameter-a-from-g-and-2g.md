---
id: crypto-ecc-recover-curve-parameter-a-from-g-and-2g
title: 已知 G 与 2G 反解曲线参数 a（a 即 flag）：倍点公式消去 y 得 a 的二次方程求根
type: scenario
domain: crypto
path: crypto/ecc
technique: ecc-recover-parameter-a-from-g-2g
tags:
- crypto
- ecc
- parameter-recovery
- weierstrass
- sage
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V526
  verified_at: '2026-11-11T15:14:32+08:00'
  notes: 已对照原文与全部5张图（ECC教学图：切线倍点/割线加法/A与-A对称/GF(23)点分布/E23(1,1)倍点图，无读取失败），并用纯Python独立复算：由倍点公式消去y得 a 的二次方程 4(x2+2x1)(x1^3+a*x1+b)-(3x1^2+a)^2=0 mod p，求根得 24 字节 flag{1s_1t_r3@lly_Easy?} 与另一 75 字节不可读根，与原文脚本输出一致；卡片推导与PoC正确。原文无产品版本/CVE，未设置 affected_versions。未验证点：Sage脚本未在本机执行，改用等价纯Python模运算复算。
url: /docs/crypto/ecc/crypto-ecc-recover-curve-parameter-a-from-g-and-2g/
draft: false
kb_aliases:
- G 与 2G 反推曲线参数
- ECC 参数 a 为 flag
- 倍点公式消元
- 已知 x1 x2 求 a
- Easy ECC
---

## 一句话结论

当题目给出短 Weierstrass 曲线 `E: y²=x³+ax+b (mod p)` 的 `p`、`b` 以及点 `G` 与 `2G` 的 x 坐标、而把曲线参数 `a` 当作 flag（`a = bytes_to_long(flag)`）时，把倍点公式的斜率 `λ=(3x₁²+a)/(2y₁)` 代入 `x₂=λ²−2x₁`，并用曲线方程消去 `y₁`，可得到只含 `a` 的二次方程 `4(x₂+2x₁)(x₁³+a·x₁+b) ≡ (3x₁²+a)² (mod p)`，在 `GF(p)` 上求根再 `long_to_bytes` 即得 flag。

## 原理

- 椭圆曲线点加/倍点公式（短 Weierstrass）：对 `P=(x₁,y₁)`，`2P=(x₂,y₂)` 满足 `λ=(3x₁²+a)/(2y₁)`、`x₂=λ²−2x₁`（模 p）。
- 题目已知 `x₁`、`x₂`、`p`、`b`，未知 `y₁` 与 `a`。把 `x₂=λ²−2x₁` 改写为 `λ² = x₂+2x₁`，两边乘 `(2y₁)²` 得 `4(x₂+2x₁)y₁² = (3x₁²+a)²`。
- 再用曲线方程 `y₁² = x₁³+a·x₁+b (mod p)` 消去 `y₁`，得到仅含 `a` 的方程：`4(x₂+2x₁)(x₁³+a·x₁+b) − (3x₁²+a)² ≡ 0 (mod p)`，展开是关于 `a` 的二次多项式。
- 在 `GF(p)` 上求该二次方程的两个根；`a` 作为 flag 字节串数值通常远小于 `p` 且可打印，错误的根一般不可 UTF-8 解码或不符合 flag 格式，据此筛选。
- 为什么可行：倍点关系把 `G` 与 `2G` 的 x 坐标绑定到同一 `a`，而曲线方程提供了消去未知 y 的约束；两个方程两个未知量（`a`、`y₁`）被化简为单变量多项式，无需解离散对数。

## 触发条件

- 题目给出 `p`、`b`（或等价曲线常量）与同一条曲线上 `G`、`2G` 的 x 坐标。
- 曲线为短 Weierstrass 形式，`a` 是待求量（可能直接编码 flag）。
- 模数 p 为素数，可在 `GF(p)` 上做多项式求根。
- 有 SageMath 或能解模二次方程的工具。

## 利用步骤

1. 确认 `x₂` 对应的点确实是 `2G`（题面/代码中有 `G=2*G` 或 `x2` 来自倍点）。
2. 在 Sage 中定义 `PR.<a> = PolynomialRing(Zmod(p))`，构造 `f = 4*(x2+2*x1)*(x1^3+a*x1+b) - (3*x1^2+a)^2`。
3. `roots = f.roots()` 求根；对每个根 `r` 做 `long_to_bytes(int(r))`，筛出可读明文/flag 格式。
4. 若根不唯一，用 `y₁² = x₁³+a·x₁+b` 验证二次剩余或带回倍点公式复核 `2G` 一致。
5. 输出 flag。

## PoC

```python
# SageMath
from Crypto.Util.number import long_to_bytes
p = 2978504498661002629091299071582436290465904673149953768927904567383228838983804727503168770704927560352042485566736762649409218645007506958368851729754839447148084715613471942096737
b = 203155971939366413053854572390533580854014345966175709774130058801484693709794880904842038444407635302410301870035839686400041986234396869946957773156780151597585571207840328547492
x1 = 2961746450301081157772024536903602376932457486781631924575753810982866784201238112170620297100938460251128698788082874030972104190128685218417680444326891343632886092532386859114448
x2 = 890136530671131957244004062733232817452520380339736536303621498985673475366221669385748542093619285319261702354866398531524362067791067563428973366865229056520602220404939306258451
PR.<a> = PolynomialRing(Zmod(p))
f = 4 * (x2 + 2*x1) * (x1^3 + a*x1 + b) - (3*x1^2 + a)^2
for r, _ in f.roots():
    print(long_to_bytes(int(r)))
```

输出可读 `flag{...}` 的根即答案。PoC 未在本机执行。

## 变体与关联

- 变体：若给的是 `P`、`P+Q`、`2Q` 等线性组合而非 `G/2G`，可改用点减半/四方程组合恢复（见关联卡）。
- 变体：曲线形式为 `y²=x³+b`（a=0）时无法用本法求 a，需从其他关系恢复。
- 关联：[[crypto-ecc-unknown-curve-point-halving-recover-flag]]（未知 p/b + 点减半）、[[ctf-crypto-ecc-unknown-modulus-gcd-small-key-brute]]（gcd 恢复模数）、[[crypto-ecc-recover-plaintext-from-ec-elgamal-known-k]]（同篇第二题的 ElGamal 解密）。

## 检测与防御

- 此为 CTF/密码学分析场景，无传统服务端防御；出题侧若想避免被公式反解，需隐藏至少一个独立约束或使用一般曲线/大参数。
- 实战侧启示：不要把秘密直接编码为公开曲线的参数并与点一起发布；曲线参数与点样本都会泄露代数关系。
- 检测：题目数据同时包含 `p、b、x(G)、x(2G)` 且缺少 `a` 时，优先尝试倍点公式消元。
