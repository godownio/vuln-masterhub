---
id: ctf-crypto-lll-sin-high-precision-angle-recovery
title: LLL 恢复高精度 sin 背后的整数角：m=arcsin(c)+2kπ 构造三维格，2^320 配平后约出明文整数 m
type: scenario
domain: ctf
path: ctf/crypto
technique: lll-sine-angle-high-precision-lattice-recovery
aliases:
- baby_math
- sin(m) 高精度
- arcsin + 2kπ
- 三角函数角度恢复
- 高精度实数格
- LLL 恢复 flag 整数
tags:
- ctf
- crypto
- lll
- lattice
- trigonometry
- real-number
- high-precision
- angle-recovery
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V363
  verified_at: '2026-11-09T03:23:42+08:00'
  notes: 已对照原文与图05/06/07/08核对：c=sin(m)、m=2kπ+arcsin(c)、[m,-1,-k]×[[1,0,S],[0,2^320,S·asin],[0,0,S·2π]]=(m,-2^320,S·残差)，det=2^320·S·2π，S=2^683 时 det^(1/3)≈2^335 大于目标范数，与卡片推导一致；原文图08 的 2^640 配平失败、正文称试到 2^683 才出解，卡中已如实记录。未验证点：原文脚本未执行；原文脚本将 1024 位小数字面量直接赋给 tmp 再 arcsin，Sage 中该字面量默认为 53-bit RealNumber、精度可能不足，卡片 PoC 改为字符串经 RealField(1024) 解析，属正确修正但需实跑确认；卡中目标范数估计 ≈2^320.8 略高（m<2^320 时实际 <2^320.5），不影响结论。与 ctf-crypto-lll-trig-integer-relation（未知小系数 a,b 的四维关系格）输入/矩阵/读取均不同，非重复；与另一张二维线性同余卡亦不同。dedup 首候选为自身，dup-scan 早于建卡且无本卡 pair。
---

## 一句话结论

当题目只给出一个高精度实数 `c = sin(m)`（例如精确到小数点后 1024 bit），而 `m` 是把 flag 转成的整数（约 2^320）时，利用 `m = arcsin(c) + 2kπ` 的周期性，把 `[1,0,S]`、`[0,2^320,S*arcsin(c)]`、`[0,0,S*2π]` 组成三维格做 LLL，短向量 `(m, -2^320, ≈0)` 会直接给出 `m`，`long_to_bytes` 即得 flag；`S`（示例 2^683）用于把实数关系分量放大到与整数分量同一竞争尺度。

## 原理

- **信息形态**：`print(sin(m).n(1024))` 只泄露 `sin(m)` 的 1024 bit 小数，但 `m` 是整数且远小于 `2^1024`。由 `sin(m) = c` 得 `m = arcsin(c) + 2kπ`（或 `π - arcsin(c) + 2kπ`，取决于象限），其中 `k` 是未知整数；`arcsin(c)` 和 `π` 都能用同样精度算出。
- **目标短向量**：对整数系数 `(m, -1, -k)` 组合格基行

  ```text
  [1, 0, S]
  [0, 2^320, S*arcsin(c)]
  [0, 0, S*2π]
  ```

  得到

  ```text
  (m, -2^320, S*(m - arcsin(c) - 2kπ))
  ```

  第三分量因为 `m = arcsin(c) + 2kπ` 而接近 0；第一分量 `m ≈ 2^320`，第二分量正好 `-2^320`。三个分量同量级且都很小，构成格中的短向量。
- **为什么 LLL 能约出来**：该三维格的行列式约为 `2^320 * S * 2π`。取 `S = 2^683` 时 `det^(1/3) ≈ 2^335`，明显大于目标向量范数 `≈ sqrt(m² + 2^640) ≈ 2^320.8`，Hermite 界与 LLL 的近似因子都有余量；若 `S` 取太小（如 2^640），`det^(1/3)` 与目标范数几乎相等，规约结果不稳定。
- **参数配平**：`2^320` 是对 flag 长度的假设（约 40 字节 → `m < 2^320`）；`S` 越大，实数关系分量的权重越高、`det` 越大，目标向量相对越短，但过大会放大浮点误差。`S = 2^683` 是该题实测能稳定出解的值，换题要按 flag 长度和精度重新试。
- **精度要求**：`arcsin(c)`、`π` 必须在约 1024 bit 精度下计算（`RealField(1024)`，`pi` 也用高精度重建），否则 `S*(m - arcsin(c) - 2kπ)` 的残差会淹没短向量；1024 bit 精度下残差约 `S*2^-1024 ≈ 2^-341`，可忽略。
- **结果读取**：LLL 输出第一行形如 `(±m, ∓2^320, ≈0)`，取第一分量绝对值转字节即 flag；若不可打印，说明 `m` 落在 `π - arcsin(c)` 分支或 `S`/`2^320` 需调整。

## 触发条件

- 题目给出高精度 `sin(m)`（或 `cos(m)` 等周期函数值），精度显著高于秘密整数的位长。
- `m` 是整数且位长上界已知（如 flag 约 30~40 字节，`m < 2^320`）。
- 能构造 `m = arcsin(c) + 2kπ`（或 `π - arcsin(c) + 2kπ`）的整数关系，且 `k` 为整数。
- 有 SageMath/高精度实数与 LLL 环境。

## 利用步骤

1. 读取 `c` 的全部小数位，构造 `R = RealField(1024)`，计算 `asin = arcsin(R(c))`、`pi = R(pi)`。
2. 估计 `m` 上界 `2^B`（flag 40 字节取 B=320）。
3. 选缩放 `S = 2^s`（示例 s=683），构造 `Matrix(QQ, [[1,0,S], [0,2^B,S*asin], [0,0,S*2*pi]])`。
4. `LLL()`，取第一行第一分量绝对值作为候选 `m`；`long_to_bytes(int(m))` 检查是否可打印/含 flag 格式。
5. 若失败：换 `π - asin` 分支、调整 `B`/`s`（逐步增大 `S` 直到出解）、或提高 `RealField` 精度。
6. 验证：把候选 `m` 代回 `sin(m)` 与题目小数比较，确认前 1024 bit 一致。

## PoC

```python
from sage.all import *
from Crypto.Util.number import long_to_bytes

tmp = "-0.5763216138185318403737346358040179184476364123728865572799211128243702354488581188939012847259223762780574285919778334891033655170438095281317540535577851035632940469300832811280408518388896020483094512571194149462558073200869265861278472233179527377781153969581392345206909655605217731481771369571884721388"  # 1024 位小数

R = RealField(1024)
c = R(tmp)
asin = arcsin(c)
pi = R(pi)                      # 高精度 π

S = 2**683
B = 2**320                      # flag 约 40 字节，m < 2^320

L = Matrix(QQ, [[1, 0, S],
                [0, B, S * asin],
                [0, 0, S * 2 * pi]])
v = L.LLL()[0]
m = abs(int(v[0]))
print(long_to_bytes(m).decode())
```

输出为 `flag{...}` 形式的明文；若得到乱码，先试 `π - arcsin(c)` 分支或调整 `S`。

## 变体与关联

- **象限分支**：一般 `sin(m)=c` 有 `m = arcsin(c) + 2kπ` 与 `m = π - arcsin(c) + 2kπ` 两支，构造格时两条都要试；`cos(m)` 对应 `arccos(c) + 2kπ` / `-arccos(c) + 2kπ`。
- **其他高精度函数**：`tan/arctan`、根号、对数的十进制高精度输出也可建成“公开实数 + 未知整数 + 周期/代数关系”的格，思路相同。
- **与 cos/sin 线性关系卡的区别**：[[ctf-crypto-lll-trig-integer-relation]] 处理的是 `enc ≈ a*cos(x)+b*sin(x)`、未知的是小整数系数 a,b；本卡处理的是未知角度 `m` 本身，需要 `arcsin + 2πk` 的周期关系和 `2^320` 配平，构造与读取方式不同。
- **精度不足**：若小数位数低于秘密位长，短向量不再唯一，需要更多信息或无法恢复。
- **关联**：[[ctf-crypto-lll-hidden-short-vector-kannan-embedding-lwe]]（一般短向量嵌入）、[[ctf-crypto-lll-linear-congruence-two-small-unknowns-2d]]（二维模线性同余格）。

## 检测与防御

- **CTF 识别**：看到 `sin(m).n(1024)`、`cos`、高精度根号/对数与整数密文组合，优先估计秘密位长并尝试高精度实数格。
- **设计视角**：不要把高精度三角函数值直接当“单向承诺”保护整数秘密；一旦精度高于秘密熵，`arcsin + 2kπ` 就能反解。
- **加固**：只泄露远低于秘密熵的精度，或对机密整数加随机偏移后再取函数值；如需承诺，应使用哈希/同余等抗反解结构。
