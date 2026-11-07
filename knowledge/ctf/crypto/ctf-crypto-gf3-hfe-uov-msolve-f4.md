---
id: ctf-crypto-gf3-hfe-uov-msolve-f4
title: GF(3) HFE/UOV 公钥超定方程组：msolve F4 逐块直接求解，无需私钥
type: scenario
domain: ctf
path: ctf/crypto
technique: gf3-hfe-uov-msolve-f4
aliases:
- D3HFERP
- GF(3) 多变量公钥
- HFE/UOV
- msolve F4
- Groebner 基解方程组
- 三进制明文编码
tags:
- ctf
- crypto
- multivariate
- hfe
- uov
- gf3
- msolve
- f4
- groebner
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:47:48+08:00'
  notes: 已对照原文核对：GF(3)、n=31/m=53、上三角系数非对角乘 2、53 方程+31 域方程、msolve F4、x30 参数、七块根 [1,2,0,0,0,1,0]、长度 38 与 flag 均一致；原文该节 LaTeX 公式有缺失但文字与脚本可自洽。未验证点：PoC 未在本机复跑；CTF 题无组件版本；frontmatter 无 sources/source_url。
---

## 一句话结论

题目在 GF(3) 上构造 31 个输入变量、53 个输出方程的混合 HFE/UOV 公钥映射，密文为 7 个 53 元 GF(3) 块；把每块密文代入 53 个二次多项式并补上域方程 `x_i^3 - x_i = 0`，系统高度超定，`msolve` 的 F4 可直接给出每块唯一的 GF(3) 解，无需恢复 HFE/UOV 私钥变换；把 7 块三进制坐标按小端规则拼回字节，即得 flag。

## 原理

- **公钥结构**：`pubkey.txt` 首行 `3 31 53` 表示 q=3、n=31、m=53；随后每个方程占三行：上三角二次型、31 个线性系数、常数项。源码保存的是对称矩阵的上三角部分，恢复多项式时非对角项要乘 2（`x_i*x_j` 在和中出现两次）。
- **明文编码**：`blocks()` 把 `len(flag).to_bytes(2,"little") + flag` 解释为小端整数，再依次取三进制最低位，每 31 个三进制位组成一个输入向量；因此密文块数与 flag 长度对应，前两字节是长度。
- **超定系统**：每个密文块给出 53 个二次方程（31 个变量），变量数 31；再加 31 个域方程 `x_i^3 - x_i = 0` 把解限制在 GF(3)。虽然带 HFE/UOV 结构，但这个参数下系统高度超定，F4/Groebner 基直接得到零维、次数 1 的参数化解，不需要私钥。
- **msolve 输出**：`result[1][4]` 标识参数变量（本题 `x30`），`result[1][5][1][0]` 是该块的消元多项式，根为参数值；其余 30 个坐标是常数多项式，按 msolve 参数化约定取相反数。不能把参数变量固定为一个常数：七个块的参数根分别为 `[1,2,0,0,0,1,0]`。
- **拼接**：每块恢复 31 个三进制坐标，按块顺序拼接为三进制数，再按小端转字节；前两字节 `26 00` 给出长度 38，与后续 flag 字节数一致。

## 触发条件

- 多变量公钥方案参数导致方程数远大于变量数，或公钥映射本身退化，使直接代数求解可行。
- 明文按固定进制（如三进制）分块编码，块之间独立。
- 可以安装/构建 `msolve`（F4 实现），且系统规模在可计算范围内。
- 已知明文前两字节为长度等结构信息，可用于校验。

## 利用步骤

1. 解析 `pubkey.txt`：q、n、m，逐方程读取上三角系数、线性系数、常数项；解析 `ciphertext.txt` 的块。
2. 对每个块构造 53 个方程 `f_i(x) - c_i = 0`，非对角二次项系数乘 2；追加 `x_i^3 - x_i = 0`。
3. 生成 msolve 输入（变量列表、域特征 3、方程），运行 `msolve -t 4 -v 2 -f blockN.ms -o blockN.out`。
4. 解析输出：找参数轴 `result[1][4]` 中为 1 的变量，读参数消元多项式求根；其余坐标取常数多项式值的相反数；把参数插入对应位置。
5. 七个块按顺序拼接三进制位，转小端字节；读前两字节长度并截取 flag。

## PoC

生成 msolve 输入（核心）：

```python
def term(coef, monomial):
    coef %= 3
    if coef == 0:
        return None
    if not monomial:
        return str(coef)
    return monomial if coef == 1 else f"{coef}*{monomial}"

polynomials = []
for target, (upper, linear, constant) in zip(ciphertexts[block], public):
    pieces = [term(constant - target, "")]
    pos = 0
    for i in range(n):
        for j in range(i, n):
            coef = upper[pos] * (1 if i == j else 2)
            mono = f"x{i}^2" if i == j else f"x{i}*x{j}"
            pieces.append(term(coef, mono))
            pos += 1
    pieces.extend(term(coef, f"x{i}") for i, coef in enumerate(linear))
    polynomials.append("+".join(x for x in pieces if x) or "0")

polynomials.extend(f"x{i}^3-x{i}" for i in range(n))
out.write_text(",".join(f"x{i}" for i in range(n)) + "\n3\n" + ",\n".join(polynomials))
```

解析 msolve 输出：

```python
def constant_value(poly):
    if poly == [[-1, [0]]]:
        return 0
    assert len(poly) == 1 and poly[0][0] == 0
    return poly[0][1][0] % 3

def linear_root(poly):
    degree, coeffs = poly
    assert degree == 1 and len(coeffs) == 2
    a, b = (value % 3 for value in coeffs)
    assert b != 0
    return (-a * pow(b, -1, 3)) % 3

digits = []
for block in range(7):
    data = ast.literal_eval(open(f"block{block}.out").read().replace("\n", "").replace(":", ""))
    parameter_axis = data[1][4]
    parameter_index = parameter_axis.index(1)
    parametrization = data[1][5][1]
    parameter = linear_root(parametrization[0])
    coordinates = [(-constant_value(poly)) % 3 for poly in parametrization[2]]
    coordinates.insert(parameter_index, parameter)
    digits.extend(coordinates)

number = sum(digit * 3**index for index, digit in enumerate(digits))
raw = number.to_bytes((number.bit_length() + 7) // 8, "little")
size = int.from_bytes(raw[:2], "little")
print(raw[:2 + size])
```

## 变体与关联

- 其他多变量方案（HFE、UOV、Rainbow、MiMC 等）在参数退化/超定时都可用 Groebner/F4 直接求解；工具可换 SageMath、Magma、Singular。
- 若系统零维但非唯一，需要枚举参数根或加更多明文结构约束；若变量多、次数高，可先做线性化/XL、结式或 SAT。
- 明文编码可换 base-3/base-q、字节序、长度前缀；先确认编码规则再拼接。
- 关联：多变量公钥密码分析、Groebner 基、CTF Crypto 代数求解卡。

## 检测与防御

- 设计多变量公钥方案时保证 m 与 n 的比例、随机化与私钥结构使直接代数攻击不可行；避免超定/退化参数。
- 明文编码增加随机填充/认证，避免分块独立可解；不要只用长度前缀做完整性校验。
- 评估时用 F4/F5、XL、SAT 等工具测试实际复杂度；对公钥做秩/差分/线性化攻击评估。
