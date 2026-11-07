---
id: ai-security-model-extraction-federated-gradient-inversion
title: 联邦学习梯度反演：可控参数令 grad_W/grad_b = 输入，仿射校准 + 按列中位数抗噪
type: scenario
domain: ai-security
path: ai-security/model-extraction
technique: federated-gradient-inversion-controllable-params
tags:
- ai-security
- model-extraction
- federated-learning
- gradient-inversion
- privacy
- gradient-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:28:43+08:00'
  notes: 已对照原文 隐私梯度逆向 核对：W1 16x17/b1 16、w1=0/b1=1/w2=±10、grad_W/grad_b≈x、已知 flag{} 位置仿射校准、16 行按列中位数恢复 c2f41b72a9d 均一致；未实际运行。
url: /docs/ai-security/model-extraction/ai-security-model-extraction-federated-gradient-inversion/
draft: false
kb_aliases:
- 隐私梯度逆向
- 梯度泄露
- 联邦学习
- w1=0 b1=1
- grad_w/grad_b
- 仿射校准
- 中位数
---

## 一句话结论

联邦系统允许上传自定义参数并下载梯度；设 `w1=0`、`b1=1` 使第一层 ReLU 全导通、`w2=±10` 放大有效梯度，则 `∂L/∂W1_i / ∂L/∂b1_i ≈ x`；对每行用已知 `flag{`/`}` 位置拟合仿射变换，16 行按列取中位数即恢复输入。

## 原理

- **第一层梯度结构**：对全连接 `h = ReLU(W1·x + b1)`，`∂L/∂W1_i = δ_i · x`，`∂L/∂b1_i = δ_i`，其中 `δ_i = ∂L/∂h_i`。两者相除消去 `δ_i`，直接得到输入 `x`。
- **可控参数消除非线性**：`w1=0` 时第一层预激活只剩 `b1=1`，恒大于 0，ReLU 不会把任何神经元置零；`w2=±10` 放大输出对隐藏层的梯度，使有效信号远大于差分隐私噪声。
- **噪声与校准**：导出的 `noisy_grad_w1`/`noisy_grad_b1` 带噪，逐行比值 `r_i` 会有比例/常数偏差；输入是 17 维 `flag{...}`，前 5 位 `flag{` 与最后 1 位 `}` 已知，可用最小二乘为每行拟合 `s_i = a_i·r_i + b_i`。
- **中位数抗噪**：16 个隐藏神经元给出 16 个校正后的候选向量；按列取中位数再 round，能抹平个别行的噪声/异常值。

## 触发条件

- 联邦/协同训练系统允许客户端上传自定义模型参数。
- 训练后可下载梯度 JSON（含 `grad_w1`/`grad_b1`）。
- 模型结构/输入维度已知；输入有固定前缀/后缀或格式约束。
- 差分隐私噪声有限，或可通过放大梯度量级压制。

## 利用步骤

1. 确认模型结构：`W1: 16×17`、`b1: 16`、`W2: 1×16`、`b2: 1`，输入维度 17。
2. 上传参数 `w1=0`、`b1=1`、`w2=[10,-10,10,-10,...]`、`b2=0`；触发一次训练。
3. 下载梯度 JSON，读 `noisy_grad_b1`（16）与 `noisy_grad_w1`（16×17）。
4. `ratios = gw / gb[:, None]`；对每行用已知位置 `[0,1,2,3,4,16]` 与字符 `flag{}` 拟合 `s = a*r + b`。
5. 校正后按列取中位数、round 转 ASCII，得到完整输入；去掉 `flag{}` 取中间答案。
6. 若噪声较大，增加 `w2` 幅度/重复训练取平均，或改用优化式反演。

## PoC

```python
import json, numpy as np

data = json.load(open("branch_gradient.json", encoding="utf-8"))
gb = np.array(data["noisy_grad_b1"], dtype=float)      # (16,)
gw = np.array(data["noisy_grad_w1"], dtype=float)      # (16,17)
ratios = gw / gb[:, None]

known_idx = [0, 1, 2, 3, 4, 16]
known_val = np.array([ord(c) for c in "flag{}"], dtype=float)

rows = []
for r in ratios:
    X = np.vstack([r[known_idx], np.ones(len(known_idx))]).T
    a, b = np.linalg.lstsq(X, known_val, rcond=None)[0]
    rows.append(a * r + b)

final_ascii = np.rint(np.median(np.array(rows), axis=0)).astype(int)
print("".join(chr(x) for x in final_ascii))
```

## 变体与关联

- **结构变体**：卷积层/多层网络/Transformer；可控制部分层参数；梯度可能只给部分层。
- **噪声变体**：差分隐私高斯/拉普拉斯噪声、梯度裁剪、安全聚合；噪声大时需多次平均或优化反演（DLG/Inverting Gradients）。
- **校准变体**：已知前缀/后缀、字符集、长度、校验位；也可用相邻行一致性/低秩约束。
- **关联卡片**：[[ai-security-model-extraction-encrypted-reasoning-replay-cot-theft]]（模型侧信息提取）、[[ai-security-rag-security-embedding-inversion-leaked-vector-store]]（嵌入反演）。
- **边界**：若服务端拒绝自定义参数、只返回聚合梯度、或噪声/裁剪足够强，本链不成立；若 `b1` 梯度被置零，无法做比值。

## 检测与防御

- **CTF/审计验证**：恢复结果应满足 `flag{}` 外壳与可打印字符；用已知位置校准后各列中位数应稳定。
- **防御**：不接受客户端自定义模型参数（或只允许白名单）；梯度裁剪 + 差分隐私 + 安全聚合；限制梯度下载频率与精度；输入去标识化。
- **检测信号**：客户端上传全零/常量权重与极端 `w2`；短时间多次训练下载梯度；梯度 JSON 中 `b1` 与 `w1` 呈明显比例关系。
