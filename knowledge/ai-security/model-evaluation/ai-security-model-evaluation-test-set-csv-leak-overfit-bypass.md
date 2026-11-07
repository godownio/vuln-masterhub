---
id: ai-security-model-evaluation-test-set-csv-leak-overfit-bypass
title: 评测平台泄露测试集 CSV：复刻模型结构后暴力过拟合 200 条样本，模型防御/剪枝考核直接满分
type: scenario
domain: ai-security
path: ai-security/model-evaluation
technique: test-set-leak-overfit-evaluation-bypass
aliases:
- 测试集泄露过拟合刷分
- 评测集 CSV 导出作弊
- 模型防御题非预期解
- 背答案绕过模型评估
- leaderboard overfitting
tags:
- ai-security
- model-evaluation
- data-leakage
- overfitting
- test-set-leak
- model-defense
- ctf
- integrity-bypass
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V171
  verified_at: '2026-11-06T17:42:32+08:00'
  notes: 已读全文（无图）并对照卡片：200 条测试样本 CSV 泄露、5 层 MLP 3→32→24→16→8→1、SmoothL1Loss、8000 epoch 过拟合、匹配率 100% 拿 flag 均与原文一致；路径 ai-security/model-evaluation 目录+README+父 README 存在，taxonomy.yaml 已有 model-evaluation 节点；PoC 为重构代码未本机复跑。
---

## 一句话结论

当模型评测平台在“性能评估”页面直接展示测试集输入与真实标签、并支持导出 CSV 时，参赛者无需做剪枝或脱毒：按公开的 `predict.py` 复刻网络结构，把泄露的 200 条测试样本当作训练集长时间过拟合，即可让平台用同一测试集打分时得到接近 100% 匹配，直接拿到 flag/通过“模型防御”考核。

## 原理

- **评测完整性的前提是测试集保密**：模型评估要度量泛化误差，前提是评分样本未参与训练。平台把测试集 `(x1,x2,x3,y_true)` 连同标签下发给选手后，评分目标从“学习可泛化的规律”退化为“记住这 200 个点”，防御/剪枝是否有效与最终得分脱钩。
- **模型容量足以记忆**：题目给出的 5 层全连接网络（3→32→24→16→8→1，ReLU）参数量远大于 200 条样本的自由度，完全可以把训练损失压到接近 0；过拟合在小数据集上是必然结果，而不是需要技巧的攻击。
- **评分集与泄露集同一份**：平台用这份固定测试集计算匹配率，选手上传的权重只要在这 200 条上输出正确，就能得到 100%（或接近）匹配，与模型是否真的去除投毒神经元无关。
- **为什么“非预期”**：出题人预期选手分析神经元激活、做剪枝并保持 95% 以上准确率；但最短路径变成“下载答案→背答案”，说明评估环节的数据暴露使整个任务逻辑崩塌。本质是评测平台的设计缺陷，而非模型算法被攻破。

## 触发条件

- 评测/评估页面或接口暴露测试样本输入与真实标签，或提供 CSV/JSON 导出。
- 平台评分使用的测试集与泄露的数据一致（固定测试集、无动态重采样）。
- 允许选手上传任意训练好的模型权重，且模型结构公开（如提供 `predict.py`）或可从接口推断。
- 评分只看匹配率/准确率，没有对训练分布、提交次数或过拟合行为做校验。

## 利用步骤

1. 打开“模型性能评估”页面，抓包或直接使用导出功能，下载测试集 CSV，确认包含特征列与 `y_true`。
2. 按题目提供的 `predict.py` 复刻模型结构（层数、宽度、激活函数、输出维度）。
3. 以泄露 CSV 全部 200 条作为训练集，不使用验证集；损失函数选 SmoothL1Loss（回归）或交叉熵（分类）。
4. 训练到损失接近 0（原文 8000 epoch 以上），保存 `model.pth`。
5. 上传权重，让平台用同一测试集打分；匹配率达到 100% 即通过，无需执行任何剪枝/脱毒操作。

## PoC

最小结构（按原题 3 维回归任务；未在本机复跑）：

```python
import torch, torch.nn as nn, pandas as pd

class Model(nn.Module):
    def __init__(self):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(3, 32), nn.ReLU(),
            nn.Linear(32, 24), nn.ReLU(),
            nn.Linear(24, 16), nn.ReLU(),
            nn.Linear(16, 8), nn.ReLU(),
            nn.Linear(8, 1),
        )
    def forward(self, x):
        return self.net(x)

df = pd.read_csv("test_data_leaked.csv")          # 平台导出的测试集
X = torch.tensor(df[["x1", "x2", "x3"]].values, dtype=torch.float32)
y = torch.tensor(df["y_true"].values, dtype=torch.float32).view(-1, 1)

model = Model()
opt = torch.optim.Adam(model.parameters(), lr=1e-3)
loss_fn = nn.SmoothL1Loss()

for _ in range(8000):
    opt.zero_grad()
    loss = loss_fn(model(X), y)
    loss.backward()
    opt.step()

torch.save(model.state_dict(), "model.pth")        # 上传，评分集即上述 200 条
```

## 变体与关联

- 变体：只泄露输入、不泄露标签时，可用平台评分接口作 oracle：对候选样本批量提交并读取分数/匹配率，反推标签或直接做黑盒蒸馏。
- 变体：只暴露部分测试样本时，可在泄露子集上训练后再用主动学习挑选高不确定性样本，扩大覆盖。
- 变体：评分允许多次提交并取最高分时，可把测试集当作超参数搜索集，逐轮拟合评分反馈。
- 关联：[[ai-security-model-extraction-confidence-features-membership-inference]]（成员推理利用的也是模型对训练样本的记忆）、[[ai-security-data-poisoning-sample-amplification-upload-api]]（训练平台接口滥用）、[[ai-security-model-extraction-soft-label-distillation-student]]（用评分/软标签蒸馏）。

## 检测与防御

- **测试集保密**：评分集不下发、不提供逐样本标签导出；评估页面只展示聚合指标，必要时对样本做脱敏与随机化。
- **动态评测**：使用留出集/定期轮换测试集、运行时随机采样，避免固定 200 条被完整记忆。
- **提交约束**：限制提交次数与频率，记录每次提交的模型行为；对训练集与测试集分布差异、模型对测试样本的异常高置信度做检测。
- **评测设计**：将“模型是否脱毒”与“测试集准确率”解耦，加入对投毒触发器/后门行为的专项检测，而不是仅看匹配率；对上传权重做来源与训练流程审计。
- **检测信号**：短时间内大量下载测试集 CSV、上传模型在测试集上 100% 匹配但换一批样本性能骤降、训练轮次异常高且无验证集。
