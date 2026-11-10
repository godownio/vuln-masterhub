---
id: ctf-crypto-ntru-lattice-lll-private-key-recovery
title: NTRU 格攻击：构造 [[1,h],[0,p]] 用 LLL 恢复私钥 (f,g) 并解密密文
type: scenario
domain: ctf
path: ctf/crypto
technique: ntru-lattice-lll-private-key-recovery
tags:
- ctf
- crypto
- lattice
- lll
- ntru
- public-key
- sage
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V402
  verified_at: '2026-11-09T13:16:39+08:00'
  notes: 已对照13959原文280行及18张图核对：图14-16确认L=[[1,h],[0,p]]、||v||=sqrt(f^2+g^2)与Hermite判定，图11-13确认h=g f^-1、hf=g+kp、a=c*f mod p=rg+mf、m=a f^-1 mod g推导，图17-18确认范数不平衡缩放[[1,T*h],[0,T*p]]→(f,T*g)与T=2^e遍历(e=1000..1030)及两题exp/flag一致。原文'用私钥加密'标题有误，卡片按公钥h加密(c=r*h+m)描述正确。--force理由成立：lll-public-key-linear-combination卡为公钥系数线性组合背包型，ntru-xplus1卡为模x+1投影区分样本，均非本卡二维格直接恢复(f,g)场景。单卡含缩放变体属同一gadget参数调整，粒度合适。无CVE/版本/长摘录，路径合法。未验证点：未在Sage环境复跑两题exp。
url: /docs/ctf/crypto/ctf-crypto-ntru-lattice-lll-private-key-recovery/
draft: false
kb_aliases:
- NTRU 格攻击
- NTRU LLL
- 格基规约恢复 NTRU 私钥
- h = g*f^-1 mod p
- rg+mf<p
- 缩放 T 遍历
- 格密码入门
---

## 一句话结论

当 NTRU 类加密给出公钥 `h = g * f^{-1} mod p`（`g < f < p`、`gcd(f,g)=1`）和密文 `c = r*h + m mod p` 时，由行向量 `[1, h]`、`[0, p]` 生成的二维格中包含短向量 `(f, g)`——因为 `(f, -k) * [[1,h],[0,p]] = (f, f*h - k*p) = (f, g)`；只要私钥向量满足 Hermite 上界，用 LLL 格基规约即可直接恢复 `(f,g)`，再由 `a = c*f mod p = r*g + m*f`（当 `r*g + m*f < p` 时等式在整数上成立）和 `m ≡ a * f^{-1} mod g` 解出明文。

## 原理

- **公私钥关系**：`h ≡ g·f^{-1} (mod p)`，即 `h*f = g + k*p`（k 为整数）。因此 `(f, -k)` 左乘基矩阵 `[[1, h], [0, p]]` 恰好得到 `(f, f*h - k*p) = (f, g)`，说明 `(f,g)` 是该格中的向量。
- **为什么它是短向量**：NTRU 参数通常取 `g < f < p`，`(f,g)` 的范数远小于一般格向量；LLL 近似求解 SVP，会把短向量规约到基的前几行，从而被提取出来。
- **Hermite 条件**：`||v|| ≤ sqrt(n) * det(L)^{1/n}`。二维格 `n=2`、`det(L)=p`，右侧约 `sqrt(2*p)`；若 `||(f,g)|| ≈ f` 小于该值（如 `f` 约 2^1024、`p` 约 2^2048），LLL 可直接找到。
- **解密**：`c = r*h + m (mod p)`，两边乘 `f` 得 `c*f ≡ r*g + m*f (mod p)`；参数设计保证 `r*g + m*f < p`，所以取 `a = c*f mod p = r*g + m*f`；再对 `g` 取模得 `a ≡ m*f (mod g)`，`f` 在模 `g` 下可逆，`m ≡ a * f^{-1} (mod g)`，转字节即明文。
- **范数不平衡时的缩放**：若 `f` 过大（例如 1536 位）而 `p` 只有 2048 位，`||(f,g)|| ≈ f` 可能超过 `sqrt(2p)`；把第二列乘以 `T`：`[[1, T*h], [0, T*p]]`，则 `(f, -k)` 乘出 `(f, T*g)`，短向量范数约为 `sqrt(f^2 + (T*g)^2)`，右侧约 `sqrt(T*p*2)`；选取合适的 `T=2^e`（原文遍历 e≈1000..1030）使不等式成立，LLL 恢复 `(f, T*g)` 后把 `g` 除以 `T` 即得正确私钥。
- **边界**：LLL 是近似算法，恢复结果依赖参数与实现；同一组参数下可能需要调整 `T`/重复尝试；`f` 在模 `g` 下不可逆、或 `rg+mf ≥ p` 时解密公式不成立。

## 触发条件

- 题目给出 NTRU 形式的 `p, h, c`，私钥 `f, g` 相对 `p` 是小量（或可通过缩放变成短向量）。
- `r*g + m*f < p`（无模回绕）保证解密方程在整数上成立；`gcd(f,g)=1` 保证 `f` 模 `g` 可逆。
- 具备 LLL 实现（SageMath `matrix.LLL()`、fpylll 等），并能承受二维/小维度格规约。

## 利用步骤

1. 建立格基矩阵 `M = [[1, h], [0, p]]`（必要时改成 `[[1, T*h], [0, T*p]]` 并遍历 `T=2^e`）。
2. 对 `M` 做 LLL，取第一行作为最短向量；按需取绝对值/除以缩放因子 `T` 得到 `(f, g)`。
3. 计算 `a = c * f % p`。
4. 计算 `m = a * f^{-1} % g`，把整数转回字节串。
5. 检查输出是否为 flag/可读明文；失败则更换 `T`、重跑 LLL 或调整符号。

## PoC

标准二维格（SageMath）：

```python
from sage.all import *
from Crypto.Util.number import long_to_bytes

M = matrix([[1, h], [0, p]])
L = M.LLL()
f, g = L[0]
if f < 0:
    f, g = -f, -g
a = c * f % p
m = a * pow(f, -1, g) % g
print(long_to_bytes(int(m)))
```

范数不平衡时缩放遍历：

```python
for e in range(1000, 1031):
    T = 2**e
    M = matrix([[1, T*h], [0, T*p]])
    f, g = M.LLL()[0]
    f, g = abs(f), abs(g) // T
    try:
        m = c * f % p * pow(f, -1, g) % g
        pt = long_to_bytes(int(m))
        if b"flag" in pt:
            print(pt)
    except Exception:
        pass
```

## 变体与关联

- 变体：缩放因子可改为遍历范围更大/非 2 的幂，或对 `h`、`p` 同时乘不同因子平衡范数；也可用 CVP/Kannan embedding 处理带噪声变体。
- 关联：同类 LLL 公钥/线性组合攻击见 [[ctf-crypto-lll-public-key-linear-combination-forge-private-key]]、[[ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe]]、[[ctf-crypto-agcd-sda-lattice-small-error-recovery]]。
- 关联：格攻击在其他密码体系的应用见 [[crypto-ecc-ecdsa-partial-nonce-leak-lattice]]、[[crypto-rsa-common-private-exponent-multiprime-lattice]]。

## 检测与防御

- 出题/实现侧：选择标准 NTRU 参数集，确保私钥向量范数与格行列式关系不满足 Hermite/LLL 恢复条件；不要把 `g ≪ f ≪ p` 的玩具参数用于真实场景。
- 分析侧：先估算 `||(f,g)||` 与 `sqrt(n)*det(L)^{1/n}`，判断能否直接 LLL；不平衡时先缩放再规约，并对结果做模 `g` 可逆性/明文格式校验。
- 通用：NTRU 的安全性依赖高维格上 SVP 的困难性，低维/小参数玩具实例可以被 LLL 直接攻破；实际部署应遵循标准化参数。
