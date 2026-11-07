---
id: crypto-rsa-lcg-exponent-leak-power-sums-franklin-reiter
title: LCG 状态与 RSA 幂泄露：power sums/Newton identities 恢复 d + Franklin-Reiter 恢复 x1
type: scenario
domain: crypto
path: crypto/rsa
technique: lcg-rsa-exponent-leak-power-sums-franklin-reiter
aliases:
- polarisCTF RSA_LCG
- LCG + RSA
- d=b-a
- power sums
- Newton identities
- Franklin-Reiter
- 4 秒时限
tags:
- crypto
- rsa
- lcg
- franklin-reiter
- power-sums
- newton-identities
- polynomial-gcd
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:19:09+08:00'
  notes: 已对照原文核对：d=b-a、x1=a(x0+1)+d、x2=a x1+a+d、C=out2*(a^e)^{-1}、u/v 根差 power sums + Newton identities 得 Q(T)、Z/NZ[D]/(D^e-leak) 中 gcd 取线性因子恢复 d、Franklin-Reiter 恢复 x1、t∈{0,1} 恢复 64 字节 secret、e=263 与 4 秒性能优化（gmpy2/FLINT/block compose/手写余式链）均一致。未验证点：PoC 为骨架，未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。
---

## 一句话结论

已知 `N,e,a,leak=(b-a)^e,x1^e,x2^e`，其中 `x1=a x0+b`、`x2=a x1+b`，可令 `d=b-a` 把递推写成 `x1=a(x0+1)+d`、`x2=a(x1+1+d/a)`；用两组 `e` 次幂的根差构造 power sums，经 Newton identities 得到关于 `T=(1+d/a)^e` 的首一多项式，再在 `Z/NZ[D]/(D^e-leak)` 中求 `gcd` 提取线性因子恢复 `d`，最后用 Franklin-Reiter 恢复 `x1` 与 64 字节 `secret`。

## 原理

- **重写 LCG**：设 `d = b - a mod N`，则 `b = a + d`，`x1 = a x0 + a + d = a(x0+1)+d`，`x2 = a x1 + a + d`。
- **构造第二个幂**：`C = out2 · (a^e)^{-1} mod N = (x1 + 1 + d/a)^e`。令 `u=x1`、`v=x1+1+d/a`，则 `u^e=out1`、`v^e=C`，且 `v-u = 1+d/a`。
- **恢复 d**：`u` 与 `v` 的 `e` 个共轭根之差给出只依赖 `(v-u)^e` 的代数量；用这些差值构造 power sums，再用 Newton identities 还原基本对称多项式，得到关于 `T=(1+d/a)^e` 的首一多项式 `Q(T)`。
- **商环求根**：在 `Z/NZ[D]/(D^e - leak)` 中，`T(D) = (1 + D/a)^e`，`R(D) = Q(T(D)) mod (D^e - leak)`。真实 `d` 同时满足 `D^e=leak` 与 `Q(T(D))=0`，因此 `D-d` 是 `gcd(D^e-leak, R(D))` 的线性因子；提取线性因子即得 `d`。
- **Franklin-Reiter 恢复 x1**：`d` 已知后 `b=a+d`；`x1` 同时满足 `x1^e=out1` 与 `(a x1+b)^e=out2`。构造 `F(X)=X^e-out1`、`G(X)=(aX+b)^e-out2`，在 `Z/NZ[X]` 上求 GCD，得到线性因子 `X-x1`。
- **恢复 secret**：`x1 = a(x0+1)+d - tN`，`t` 只可能为 0 或 1；枚举 `t`，检查 `(x1-d+tN) % a == 0`，得 `x0=(x1-d+tN)/a - 1`，再用长度约束与三个幂回代验证。
- **性能关键**：`e=263`、`deg(Q)=263`，4 秒时限下需把大整数模运算交给 gmpy2、把多项式模乘交给 FLINT，并针对 `D^e-leak` 重写 block compose（baby-step/giant-step），复合数 `N` 下不能用 FLINT 的 `gcd`，需手写多项式余式链。

## 触发条件

- 目标使用 LCG 生成/关联秘密，并泄露 `d=b-a` 的 `e` 次幂、`x1^e`、`x2^e`。
- `N` 为 RSA 模数（可为复合数），`e` 为中等大小（案例 263），`a` 可逆。
- 秘密 `x0` 有固定字节长度（案例 64 字节），可用于筛选。
- 有时间限制，需要优化大整数/多项式运算。
- 攻击者能拿到 `N,e,a,leak,out1,out2`。

## 利用步骤

1. 计算 `C = out2 * inverse(a^e, N) mod N`。
2. 用 `u^e=out1` 与 `v^e=C` 的根差构造 power sums，Newton identities 得到 `Q(T)`。
3. 在 `Z/NZ[D]/(D^e-leak)` 中计算 `T(D)` 与 `R(D)=Q(T(D))`；用多项式余式链求 `gcd(D^e-leak, R(D))`，提取线性因子得到 `d`。
4. 计算 `b = a+d`；构造 Franklin-Reiter 多项式 `F,G`，求 GCD 得 `x1`。
5. 枚举 `t∈{0,1}`，由 `x1 = a(x0+1)+d - tN` 恢复 `x0`；检查长度与 `d^e=leak`、`x1^e=out1`、`x2^e=out2`。
6. 把 `x0` 按 64 字节大端输出为 secret。

## PoC

```python
# 关键公式（完整实现需 FLINT/gmpy2；此处为可读骨架）
# d = b - a
# x1 = a*(x0+1) + d
# x2 = a*x1 + a + d
# C = out2 * inverse(pow(a, e, N), N) % N
# u = x1, v = x1 + 1 + d/a
# u^e = out1, v^e = C, v-u = 1 + d/a
# Q(T): power sums of (v_i - u_j) -> Newton identities, T = (1 + d/a)^e
# R(D) = Q((1 + D/a)^e) mod (D^e - leak)
# d = linear_root(gcd(D^e - leak, R(D)))
# F(X)=X^e-out1, G(X)=(aX+b)^e-out2; x1 = linear_root(gcd(F,G))
# x0 = (x1 - d + t*N)//a - 1, t in {0,1}
```

```python
# 末尾恢复与校验
for t in (0, 1):
    num = x1 - d + t * N
    if num < 0 or num % a:
        continue
    x0 = num // a - 1
    if not (0 <= x0 < (1 << 512)):
        continue
    b = (a + d) % N
    xx1 = (a * x0 + b) % N
    xx2 = (a * xx1 + b) % N
    if pow(d, e, N) == leak and pow(xx1, e, N) == out1 and pow(xx2, e, N) == out2:
        print(x0.to_bytes(64, "big"))
        break
```

## 变体与关联

- 参数变体：`e` 较小时可用普通多项式 GCD；`e` 大时需要 block compose/快速模乘；`N` 为素数时可直接用 FLINT 的 gcd，复合数需手写余式链。
- 递推变体：LCG 可换成二阶线性递推、仿射变换；核心是“泄露幂 + 已知仿射关系”。
- 关联：[[crypto-rsa-franklin-reiter-affine-related-message]]（Franklin-Reiter 基础）、[[crypto-prng-lcg-parameter-recovery-delta-gcd]]（LCG 参数恢复）、[[crypto-prng-truncated-lcg-coppersmith-lattice-cvp]]（截断 LCG 格方法）。

## 检测与防御

- 检测：协议泄露 `(b-a)^e`、`x1^e`、`x2^e` 等幂值；LCG 参数/状态与 RSA 指数在同一实现中复用；响应时间异常（大量模幂/多项式运算）。
- 防御：不要用 LCG 生成秘密或密钥；使用 CSPRNG；不要泄露状态/差值的幂；RSA 使用标准密钥生成与 OAEP 填充。
- 加固：限制大整数运算接口的调用频率；对敏感参数做脱敏；使用常数时间实现与密钥隔离。
