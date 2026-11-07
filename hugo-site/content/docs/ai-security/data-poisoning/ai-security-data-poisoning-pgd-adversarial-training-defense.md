---
id: ai-security-data-poisoning-pgd-adversarial-training-defense
title: PGD 对抗训练缓解数据投毒：干净样本 + 对抗样本联合损失，降低标签翻转/清洁标签攻击影响
type: scenario
domain: ai-security
path: ai-security/data-poisoning
technique: pgd-adversarial-training-poisoning-defense
tags:
- ai-security
- data-poisoning
- defense
- adversarial-training
- pgd
- robustness
- pytorch
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V183
  verified_at: '2026-11-06T20:09:43+08:00'
  notes: 已对照 90728 原文核对：PGD 生成（eps=0.3/alpha=0.01/iters=40、sign 梯度、双 clip）、clean+adv 联合损失（原文 λ=1）、97.1%→96.8%/64.5%→90.2% 数字均来自原文实验注释；卡片标注 confidence=medium 并说明非万能防御。未复跑训练。
url: /docs/ai-security/data-poisoning/ai-security-data-poisoning-pgd-adversarial-training-defense/
draft: false
kb_aliases:
- PGD 对抗训练
- adversarial training
- 投毒防御
- 鲁棒优化
- 对抗样本联合训练
- 清洁标签攻击防御
---

## 一句话结论

在训练每个 batch 时用 PGD 在 ε 球内生成对抗样本，并联合优化“干净样本损失 + λ×对抗样本损失”，可以迫使模型学习对微小输入扰动不敏感的特征，从而降低标签翻转、清洁标签等依赖细微特征/扰动的投毒攻击效果；代价是训练成本约翻倍，干净精度可能小幅下降，且并非对自适应投毒免疫。

## 原理

- **鲁棒优化目标**：普通训练最小化 `E[L(f(x), y)]`；对抗训练求解 `min_θ E[max_{||δ||≤ε} L(f(x+δ), y)]`，即把每个样本最坏扰动下的损失纳入优化。内层最大化用 PGD（投影梯度下降）近似：沿损失对输入的梯度符号方向迭代上升，每步投影回 ε 球，并裁剪到合法像素范围。
- **为什么能缓解投毒**：
  - 清洁标签攻击常依赖对输入施加细小、定向的扰动，把样本在特征空间推向目标类；对抗训练让模型对这类小扰动不敏感，削弱其效果。
  - 标签翻转攻击利用模型对错误标签的过拟合；联合干净/对抗样本训练改变决策边界平滑度，降低模型对局部噪声标签的敏感度（这一效果依赖投毒比例与训练设置，并非普遍保证）。
  - 本质上，对抗训练学到的特征更依赖全局、稳定的模式，而不是触发器/局部伪特征。
- **代价与边界**：PGD 每步都要前向+反向，训练成本约为普通训练的 `iters` 倍；ε 越大鲁棒性越强但干净精度越低；对抗训练主要针对“小扰动”类攻击，对语义触发器、分布式触发器、数据注入式投毒不一定有效；自适应攻击者可以把投毒样本做得对对抗训练也鲁棒。
- **参数经验**：原文示例 `eps=0.3`、`alpha=0.01`、`iters=40`（MNIST 像素 0–1），联合损失为 `clean_loss + adv_loss`（等价 λ=1）；实际需按数据集/模型调 ε、α、λ，过大的 ε 会显著损害干净精度。

## 触发条件

- 防御方控制训练流程，能在每个 batch 上额外做 PGD 前向/反向；有足够 GPU 预算。
- 已知或怀疑训练数据存在标签翻转/清洁标签类投毒；有干净测试集用于评估。
- 输入是连续型（图像/音频/嵌入），可以定义 ε 球和投影；离散文本需要其它对抗训练变体。
- 攻击者不能自适应地针对对抗训练重新设计投毒样本；否则防御效果会下降。

## 利用步骤

1. 训练基线模型，记录干净测试集准确率与投毒测试集（目标类/后门）准确率，作为对照。
2. 实现 PGD 生成器：`x_adv = x + α·sign(∇_x L(f(x), y))`，每步 `clip(x_adv, x-ε, x+ε)` 且 `clip(0,1)`，迭代 `iters` 次；每步 detach 后重新 `requires_grad_`。
3. 训练时对每个 batch 同时计算 `loss_clean = CE(f(x), y)` 与 `loss_adv = CE(f(x_adv), y)`，总损失 `loss_clean + λ·loss_adv`，反向更新。
4. 在干净测试集与投毒测试集上评估：干净精度下降应可控（原文示例 97.1%→96.8%），投毒集目标类准确率应提升（原文示例 64.5%→90.2%）。
5. 调整 ε/α/iters/λ：先小 ε 保证干净精度，再逐步增大；若投毒集仍差，检查攻击类型是否属于对抗训练覆盖范围。
6. 与数据溯源、异常检测、后门扫描组合使用；对抗训练不是单独的解药。

## PoC

```python
import torch
import torch.nn as nn
from torch.utils.data import DataLoader

def pgd_attack(model, x, y, eps=0.3, alpha=0.01, iters=40):
    x_adv = x.clone().detach().requires_grad_(True)
    for _ in range(iters):
        loss = nn.CrossEntropyLoss()(model(x_adv), y)
        model.zero_grad()
        loss.backward()
        x_adv = x_adv + alpha * x_adv.grad.sign()
        x_adv = torch.clamp(x_adv, x - eps, x + eps)
        x_adv = torch.clamp(x_adv, 0, 1)
        x_adv = x_adv.detach().requires_grad_(True)
    return x_adv

def adversarial_train(model, dataset, epochs=5, lr=1e-3, eps=0.3, lam=1.0):
    loader = DataLoader(dataset, batch_size=64, shuffle=True)
    criterion = nn.CrossEntropyLoss()
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    model.train()
    for _ in range(epochs):
        for x, y in loader:
            x_adv = pgd_attack(model, x, y, eps=eps)
            loss = criterion(model(x), y) + lam * criterion(model(x_adv), y)
            opt.zero_grad(); loss.backward(); opt.step()
    return model
```

评估时分别统计干净测试集准确率与投毒测试集（目标类/触发器）准确率，避免只看整体指标。

## 变体与关联

- **TRADES**：把鲁棒损失拆成“干净分类损失 + 正则项（KL 散度）”，通常比朴素对抗训练有更好的精度-鲁棒性权衡。
- **针对后门的对抗训练**：用触发器模式/后门样本做对抗训练，或把触发器的存在作为最坏情况扰动；但触发器空间通常大于 ε 球，效果有限。
- **数据增强/平滑**：高斯噪声、CutMix、MixUp 等可提升对局部扰动的鲁棒性，但不等价于对抗训练。
- **自适应攻击**：攻击者可在投毒优化中把对抗训练加入目标，构造“鲁棒投毒”；防御需结合数据审计与模型扫描。
- **关联**：[[ai-security-data-poisoning-label-flipping-clean-test-degradation]]、[[ai-security-data-poisoning-clean-label-trigger-target-class]]、[[ai-security-data-poisoning-badnet-trigger-patch-target-label]]（被防御的攻击）、[[ai-security-data-poisoning-gradient-saliency-pruning-backdoor-removal]]（另一种后门清除思路）。

## 检测与防御

- **评估指标**：同时报告干净测试集准确率、目标类/触发器测试集准确率、整体投毒集准确率；只看整体精度会漏掉定向破坏。
- **训练侧**：PGD 对抗训练、TRADES、输入平滑/增强；保留干净验证集与投毒回归测试。
- **数据侧**：来源审计、标签一致性/近邻检查、异常样本检测、去重与可信数据源白名单。
- **模型侧**：后门扫描（Neural Cleanse/STRIP/激活聚类）、剪枝/微调清除；对抗训练与这些手段组合使用。
- **注意**：对抗训练会改变模型行为与精度，部署前需在业务分布上回归；不要把它当作对全部数据投毒的万能防御。
