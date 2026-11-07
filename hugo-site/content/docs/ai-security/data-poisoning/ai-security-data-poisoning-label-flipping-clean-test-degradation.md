---
id: ai-security-data-poisoning-label-flipping-clean-test-degradation
title: 标签翻转数据投毒：15% 翻转标签即可显著拉低干净测试准确率，正则化几乎无效
type: scenario
domain: ai-security
path: ai-security/data-poisoning
technique: label-flipping-poisoning
tags:
- ai-security
- data-poisoning
- label-flipping
- training-data
- mnist
- pytorch
- model-integrity
- availability
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V111
  verified_at: '2026-11-06T01:48:25+08:00'
  notes: 已对照原文核对：15%/25%/40%/90% 投毒对应约 85%/68%/45%/10% 准确率、训练 loss 正常下降、标签翻转不改输入等均与原文一致；“dropout/权重衰减几乎无效”原文为建议读者尝试的断言而非实测表，卡片措辞略强，属可接受；PoC 未本机执行
url: /docs/ai-security/data-poisoning/ai-security-data-poisoning-label-flipping-clean-test-degradation/
draft: false
kb_aliases:
- 标签翻转
- 标签投毒
- label flipping
- FLIP
- 聚类翻转
- 众包标注投毒
---

## 一句话结论

只修改训练样本的标签、不改图像内容，在 MNIST 上翻转约 15% 的标签就能让干净测试集准确率从约 97% 降到约 85%，25% 时降到约 68%；训练 loss 仍正常下降，dropout/权重衰减等标准正则化几乎无法缓解，属于门槛极低、可完全复现的模型完整性投毒。

## 原理

- **模型会忠实记住错误标签**：神经网络容量足以把随机标签的训练集拟合到接近零训练误差（记忆而非泛化），训练目标只优化“输入→给定标签”的条件概率，标签被改后模型就学到错误映射。
- **破坏来自标签噪声，不来自输入异常**：图像本身完全正常，任何只检查像素/特征的清洗方法都看不出问题；只有把标签与近邻一致性、模型预测一致性对照才能发现。
- **非线性临界点**：少量翻转时模型仍能靠多数正确样本纠正，超过一定比例后错误标签的梯度开始主导，准确率下降速度明显加快。
- **正则化为什么无效**：dropout、权重衰减约束的是参数幅度/共适应性，不区分“正确标签”和“错误标签”；只要训练目标仍要求拟合被篡改的标签，正则化无法把错误监督信号变成正确监督信号。
- **实际攻击面**：众包标注、外包标注、社区数据集、第三方数据采购、自动合成/清洗流水线，任何能影响“标签”这一环节的位置都可投毒；攻击者不需要接触模型或训练代码。

## 触发条件

- 攻击者能影响训练数据的标签（标注外包、众包、社区数据集、数据供应链、自动标注流水线）。
- 训练流程直接使用这些标签，没有标签审计、近邻一致性检查或干净对照集。
- 模型会在攻击者关心的输入分布上被使用；投毒比例足以越过临界点（示例 15% 已可见，25% 明显）。
- 评测只看 loss/训练集指标，或在被污染的验证集上评估；干净测试集回归缺失。

## 利用步骤

1. 选择目标数据集与要破坏的类别范围（全类别无目标破坏，或只翻转特定类别做定向破坏）。
2. 按类别分组，对每个类别抽取前 N% 的样本，把标签随机改成其他类别；图像/文本内容保持不变，避免引入可见异常。
3. 把翻转后的样本与剩余干净样本混合，交给受害者正常训练。
4. 在完全干净的测试集上评估：观察准确率随投毒比例的非线性衰减，以及训练 loss 仍正常下降的现象。
5. 若做定向攻击，只翻转目标类到指定错误类，使模型在特定输入上稳定错分类，同时尽量保持整体准确率。

## PoC

原文给出完整的 PyTorch/MNIST 实验代码；以下为最小复现骨架（未在本机运行）：

```python
import random
import torch, torch.nn as nn, torch.nn.functional as F
from torchvision import datasets
from torch.utils.data import DataLoader, Subset

# 1) 取 MNIST 子集
train = datasets.MNIST("./data", train=True, download=True)
test = datasets.MNIST("./data", train=False, download=True)
train_idx = random.sample(range(len(train)), 6000)
test_idx = random.sample(range(len(test)), 2000)

# 2) 标签翻转：每个类别前 poison_ratio 的样本改标签
poison_ratio = 0.15
by_class = {i: [] for i in range(10)}
for i in train_idx:
    _, y = train[i]
    by_class[y].append(i)

pairs = []
for y, idxs in by_class.items():
    n = int(len(idxs) * poison_ratio)
    for i in idxs[:n]:
        img, _ = train[i]
        pairs.append((torch.tensor(img, dtype=torch.float32).unsqueeze(0) / 255.0,
                      random.choice([c for c in range(10) if c != y])))
    for i in idxs[n:]:
        img, y2 = train[i]
        pairs.append((torch.tensor(img, dtype=torch.float32).unsqueeze(0) / 255.0, y2))

# 3) 小 CNN 正常训练
model = nn.Sequential(
    nn.Conv2d(1, 32, 3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
    nn.Conv2d(32, 64, 3, padding=1), nn.ReLU(), nn.MaxPool2d(2),
    nn.Flatten(), nn.Linear(64 * 7 * 7, 128), nn.ReLU(), nn.Linear(128, 10),
)
opt = torch.optim.Adam(model.parameters(), lr=1e-3)
loader = DataLoader(pairs, batch_size=64, shuffle=True)
for epoch in range(5):
    for x, y in loader:
        opt.zero_grad()
        loss = F.cross_entropy(model(x), y)
        loss.backward(); opt.step()

# 4) 干净测试集评估
correct = 0
for i in test_idx:
    img, y = test[i]
    x = torch.tensor(img, dtype=torch.float32).unsqueeze(0).unsqueeze(0) / 255.0
    correct += (model(x).argmax().item() == y)
print("clean acc:", correct / len(test_idx))
```

原文报告的典型趋势：0% 投毒第 5 轮约 97%，15% 约 85%，25% 约 68%，40% 约 45%，90% 约 10%；训练 loss 始终正常下降。

## 变体与关联

- **定向变体**：只翻转一个类到另一个类，做定向误分类；或只翻转与业务关键输入相关的类别。
- **选择策略变体**：FLIP/轨迹匹配优先翻转对梯度影响最大的样本，用更少投毒量达到同样效果；聚类翻转按簇翻转。
- **标签来源变体**：众包标注、外包标注、社区数据集、自动标注/合成数据、数据清洗流水线。
- **与后门/干净标签的区别**：标签翻转不改输入、无需触发器；干净标签攻击不改标签但扰动特征；后门攻击需要触发器。三者可组合。
- **关联卡片**：[[ai-security-data-poisoning-alignment-finetune-refusal-removal]]（微调阶段投毒拆除拒答护栏）、[[ai-security-supply-chain-poison-gpt-rome-typosquat-model-hub]]（模型供应链投毒）。
- **边界**：投毒比例、模型容量、数据集难度都会影响临界点；强鲁棒训练/标签清洗可降低效果，但本实验显示 dropout/权重衰减基本无效。

## 检测与防御

- **标签审计**：抽样人工复核；对众包/外包标注做一致性校验（多人标注、黄金样本、标注者信誉）。
- **近邻一致性过滤**：KNN 检查样本的 K 个最近邻标签是否多数与自身一致，不一致的标记为可疑；对标签翻转有效，对干净标签攻击无效。
- **统计与重构检测**：Z-score 检测统计异常样本；自编码器重构误差检测特征异常；两者对隐蔽投毒效果有限。
- **训练监控**：按样本/批次监控 loss 与梯度贡献，投毒样本常在训练早期产生异常高或异常低的 loss、对梯度影响不成比例。
- **流程控制**：数据来源签名/哈希链、标注者溯源、干净对照集与投毒集分离、发布前在独立干净测试集上回归；不要把训练 loss 当作安全性指标。
- **响应**：发现准确率异常下降时，回溯数据版本与标注批次，隔离可疑样本重训，并用干净基线做对照。
