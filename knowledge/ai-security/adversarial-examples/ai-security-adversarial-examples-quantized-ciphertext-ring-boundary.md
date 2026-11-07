---
id: ai-security-adversarial-examples-quantized-ciphertext-ring-boundary
title: 量化模环密文推理翻转：半模数折返边界 + L∞≤2/255 整数像素搜索
type: scenario
domain: ai-security
path: ai-security/adversarial-examples
technique: quantized-ciphertext-ring-boundary-adversarial
aliases:
- 密文推理对抗样本
- 模环解码
- 半模数折返
- PLAIN_MODULUS
- L∞ 2/255
- 离散像素搜索
- STE
tags:
- ai-security
- adversarial-examples
- quantization
- modular-ring
- ciphertext-inference
- linf
- ste
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V125
  verified_at: '2026-11-06T04:28:40+08:00'
  notes: 已对照原文 密文推理对抗样本 与 img/02 核对：P=8159233、P/2=4079616、半模数折返、raw0 贴近 4160000、L∞<=2/255 整数搜索、明文正常/密文肺炎翻转均一致；未实际运行完整搜索。
---

## 一句话结论

密文推理把全连接输入/权重量化后在模数 `P=8159233` 环里算分，解码时 `v > P/2` 折返为 `v-P`；把某一类 raw 分数推到刚好越过 `4079616`，就能让密文预测翻转，同时保持明文浮点预测不变；在 ±2 灰度级离散空间用 STE + warm start 搜索满足 `L∞≤2/255`。

## 原理

- **半模数折返**：`_decode(v) = v - P if v > P//2 else v`。当 `raw0` 刚越过 `P/2=4079616` 时，`dec0 = raw0 - P ≈ -P/2`；此时只要 `dec1 > dec0`，密文预测就从类别 0 翻到类别 1。
- **不能一味增大 raw0**：`raw0` 越大，`dec0 = raw0 - P` 越接近 0，反而更难让 `dec1` 压过；正确目标是让 `raw0` 落在“刚过半模数”的窄区间（如 4160000 附近），同时抬高 `raw1`。
- **明文/密文双约束**：明文模型看浮点 logits，必须保持类别 0；密文模型看量化+模环+解码后的分数，必须翻到类别 1；两者用同一张图，因此损失要同时约束 `plain_margin` 与 `raw0/raw1`。
- **离散空间**：服务端按保存后的 8-bit PNG 判定；连续 PGD 找到的 5/255 成功图缩放到 2/255 会掉回安全区，必须在 `delta ∈ {-2,-1,0,1,2}` 的整数像素空间重搜，并用 STE 让梯度穿过 `round`。

## 触发条件

- 有目标模型、量化权重 `fc_weight.npy`/`fc_bias.npy`、目标图。
- 密文推理的模数/缩放/解码逻辑已知（或可从源码恢复）。
- 服务端按 8-bit PNG 判定，且有 `L∞` 约束（本例 2/255）。
- 明文与密文预测都需满足指定条件。

## 利用步骤

1. 复现明文推理（浮点 logits）与密文推理（量化特征、模环、半模数解码），确认原图两者都预测类别 0。
2. 先用普通梯度搜索找 5/255 的翻转样本，确认翻转方向；记录其扰动方向作为 warm start。
3. 把搜索空间限制为整数 `delta ∈ {-2..2}`，用 STE 构建候选图 `x_u8 = clamp(orig + round(clamp(delta,-2,2)))`。
4. 损失：`((raw0 - 4160000)/2e5)^2 - 0.8*(raw1/1e6) - 0.1*plain_margin + 2.5*relu(0.5-plain_margin)`。
5. 多次 restart，保存满足 `L∞≤2`、`plain_pred=0`、`cipher_pred=1` 的 PNG；本地用 `exact_eval` 复核后再上传。

## PoC

```python
def decode_ring(v, P=8159233):
    return v - P if v > P // 2 else v

# 密文分数
raw = q_feats @ q_w.T + q_b
dec = decode_ring(raw)
cipher_pred = int(dec[1] > dec[0])

# 离散搜索（STE）
x_u8 = torch.clamp(orig_u8.float() + ste_round(torch.clamp(delta, -2, 2)), 0, 255)
raw_st = ste_round(model.features(normalize(to_float(x_u8)))[0] * SCALE) @ q_w_t.T + q_b_t
loss = ((raw_st[0] - 4160000.0)/200000.0)**2 - 0.8*(raw_st[1]/1000000.0) \
       - 0.10*(logits[0,0]-logits[0,1]) + 2.5*F.relu(0.50-(logits[0,0]-logits[0,1]))
```

## 变体与关联

- **参数变体**：`SCALE`/`PLAIN_MODULUS` 不同；多分类；半模数阈值 `P//2` 或 `P/2` 浮点；量化舍入方式不同。
- **约束变体**：`L∞` 更小（1/255）、`L2` 约束、只允许修改部分像素/通道；需要更精细的离散搜索或整数规划。
- **攻击目标变体**：明文/密文预测互换、指定类别、置信度阈值；也可攻击量化模型本身的舍入边界。
- **关联卡片**：[[ai-security-rag-security-blind-rag-matrix-mask-cpa-vector-recovery]]（量化/线性代数攻击）、[[ai-security-model-extraction-encrypted-reasoning-replay-cot-theft]]（模型侧推理差异）。
- **边界**：若服务端在推理前做压缩/缩放/去噪，离散扰动会被破坏；若密文解码不做半模数折返，翻转不成立。

## 检测与防御

- **CTF/审计验证**：本地 `exact_eval` 必须同时满足 `L∞≤2`、明文类别不变、密文类别翻转；上传后以服务端判定为准。
- **防御**：明文与密文推理结果做一致性校验；量化参数/模数保密；对上传图片做重编码/压缩/去噪；限制单像素扰动并做对抗样本检测。
- **检测信号**：上传图片与参考图逐像素差异 ≤2；明文/密文预测不一致；量化分数接近半模数边界。
