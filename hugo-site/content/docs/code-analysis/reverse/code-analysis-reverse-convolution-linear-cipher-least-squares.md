---
id: code-analysis-reverse-convolution-linear-cipher-least-squares
title: 逆向卷积型线性加密：把 des[i+j]+=flag[i]*key[j] 建模为 Toeplitz 方程组用最小二乘还原输入
type: scenario
domain: code-analysis
path: code-analysis/reverse
technique: convolution-linear-cipher-least-squares
tags:
- reverse
- ctf
- crypto
- linear-algebra
- numpy
- convolution
- keygen
cve: []
severity: low
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
url: /docs/code-analysis/reverse/code-analysis-reverse-convolution-linear-cipher-least-squares/
draft: false
kb_aliases:
- 卷积加密逆向
- 线性变换还原明文
- Toeplitz 矩阵解 flag
- numpy 最小二乘解 flag
- 滑动窗口累加加密
- CTF 线性加密
---

## 一句话结论

当加密循环写成 `des[i+j] += flag[i] * key[j]`（外层明文、内层密钥、目标下标为两者之和）时，它就是一个离散卷积／线性映射；密文长度等于明文长度加密钥长度减一，把每个输出写成 `A·x` 的行，用已知密钥构造 Toeplitz 矩阵后解线性方程组（最小二乘或前代）即可唯一还原明文，无需爆破。

## 原理

- `des[i+j] += flag[i]*key[j]` 完全等价于多项式乘法：把 `flag` 的字节看作多项式系数、`key` 的字节看作另一个多项式系数，`des` 就是两者乘积的系数序列。长度关系 `len(des) = len(flag) + len(key) - 1` 是判断「这是卷积而不是普通逐字节加密」的第一特征。
- 展开成矩阵形式：对每个输出下标 `k`，`des[k] = Σ_i flag[i] * key[k-i]`（`0 ≤ k-i < len(key)`）。把 `key` 按行平移填入矩阵，得到 `len(des) × len(flag)` 的 Toeplitz 矩阵 `A`，整个加密就是 `A·x = b`，`x` 即明文向量。
- 该映射是线性的且 `key[0] ≠ 0` 时矩阵首行对角非零，`x` 可由前代法从 `des[0]` 开始逐个解出：`flag[0] = des[0]/key[0]`，`flag[1] = (des[1] - flag[0]*key[1])/key[0]`，依此类推。因此加密本身不提供任何混淆强度，只是把明文「摊开」到更长的输出里。
- 实战中更省事的是把矩阵直接丢给最小二乘：`x = (AᵀA)⁻¹Aᵀb`。即使下标起点/长度判断有偏差，只要行数多于未知数，最小二乘仍能给出接近整数解的结果，四舍五入即为字节。之所以能这么做，是因为运算在整数（或浮点精确可表示的小整数）域内进行，没有模运算截断。
- 反例边界：若内层写成 `des[i+j] = (des[i+j] + flag[i]*key[j]) & 0xffffffff`，就是模 2³² 的卷积，普通最小二乘失效，需要按模运算处理（逐项取模前代或交给 z3）。

## 触发条件

- 逆向目标中存在双重循环，内层累加下标为 `i+j`（或 `i-j`、`(i+j)%n` 等固定线性偏移），且没有取模/非线性 S 盒；
- 已知或可从二进制中提取密钥数组；
- 能拿到密文数组（静态数据段、比较常量或输入后的期望值）；
- 分组长度较短、字节取值范围可枚举时也可用已知明文校验结果。

## 利用步骤

1. 在反编译代码中确认累加形式与长度关系，记录 `len(des)`、`len(key)`，推出 `len(flag) = len(des) - len(key) + 1`。
2. 从数据段/初始化代码中取出 `key` 与 `des`（注意 `des` 末尾常见补 0，需按长度裁掉）。
3. 构造 `A`：对每个 `i`（明文下标）、`j`（密钥下标），令 `A[i+j][i] = key[j]`。
4. 解 `A·x = b`：`np.linalg.solve(AᵀA, Aᵀb)` 或 `np.linalg.lstsq`，四舍五入取整。
5. 转字符校验格式（如 `XXX{...}`）；若个别字符错位，改用前代法逐项求解交叉验证。

## PoC

```python
import numpy as np

key = np.array([0x4C,0x69,0x74,0x43,0x54,0x46,0x32,0x30,0x32,0x35], dtype=np.float64)
des = np.array([...], dtype=np.float64)   # 长度 = len(flag) + len(key) - 1

n_flag = len(des) - len(key) + 1
A = np.zeros((len(des), n_flag))
for i in range(n_flag):
    for j in range(len(key)):
        A[i + j][i] = key[j]

x = np.linalg.solve(A.T @ A, A.T @ des)   # 正规方程
flag = np.round(x).astype(np.uint32)
print(''.join(chr(c) for c in flag))
```

等价的直接前代（更稳，不依赖浮点）：

```python
flag = []
for i in range(n_flag):
    acc = des[i] - sum(flag[t] * key[i - t] for t in range(max(0, i - len(key) + 1), i))
    flag.append(int(round(acc / key[0])))
```

## 变体与关联

- 下标改为 `i-j`（互相关）时矩阵结构变成下三角 Toeplitz，同样可解；循环卷积（`(i+j) % n`）对应 FFT 域逐点相除。
- 若涉及 `& 0xffffffff` 或 `% 256`，转为模方程，可用 z3 或逐项前代取模求解，不要直接套最小二乘。
- 若 `key` 未知，可用已知明文（flag 格式前缀）反解密钥，再用密钥解剩余部分。
- 关联：[[code-analysis-reverse-crypto-encoding-identification-decrypt]]（标准算法识别，本卡针对自定义线性变换）；[[code-analysis-reverse-chacha20-binary-identification-features]]（流密码特征识别）。

## 检测与防御

- CTF/算法侧识别：密文长度恰好比明文长 `len(key)-1`；循环里出现 `arr[i+j]` 形式的累加；没有 S 盒、移位、取模等非线性操作。
- 防御（若作为许可证/校验算法）：不要使用纯线性变换保护数据，至少加入模 2³² 截断、非线性替换或带密钥的哈希/MAC，并避免把密钥与校验常量放在同一二进制中。
