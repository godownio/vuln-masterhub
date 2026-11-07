---
id: ai-security-data-poisoning-gradient-saliency-pruning-backdoor-removal
title: 梯度显著性定位触发器 + 相关滤波器剪枝：不重训的后门清除（Neural Cleanse 简化变体）
type: scenario
domain: ai-security
path: ai-security/data-poisoning
technique: gradient-saliency-pruning-backdoor-removal
tags:
- ai-security
- data-poisoning
- defense
- backdoor-removal
- neural-cleanse
- pruning
- saliency
- pytorch
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V183
  verified_at: '2026-11-06T20:09:45+08:00'
  notes: 已对照 90728 原文核对：梯度显著性 top 0.1% 掩码、conv2d(mask,weight) 滤波器响应、剪 30% conv2、85.1%→82.7%/91.3%→14.8% 均来自原文代码与注释；原文 argsort 注释与代码方向矛盾已在卡中标注，PoC 用 descending=True 修正；已修正 fc1 输入维度为 (out_channels-k)*8*8。未复跑训练。
url: /docs/ai-security/data-poisoning/ai-security-data-poisoning-gradient-saliency-pruning-backdoor-removal/
draft: false
kb_aliases:
- 梯度显著性触发器定位
- Neural Cleanse 简化版
- 后门剪枝清除
- trigger mask saliency
- 后门神经元剪枝
- 模型净化
---

## 一句话结论

对可疑模型的目标类输出求输入梯度并累加，显著性最高的少量像素可作为触发器掩码；再计算卷积滤波器对触发器区域的响应强度，剪掉与触发器最相关的滤波器并调整全连接层输入维度，可以在不重新训练的情况下显著降低后门成功率（原文示例 91.3%→14.8%），同时把干净精度损失控制在约 2–3%。该实现是 Neural Cleanse 的梯度显著性简化变体，不是规范算法，需按模型结构验证。

## 原理

- **后门的“触发器响应子网络”**：后门模型在正常输入上表现正常，但触发器会激活一条指向目标类的捷径通路；该通路对应部分卷积通道/滤波器，对触发器区域特别敏感。
- **梯度显著性定位**：对随机输入（或干净样本）计算目标类 logit 对输入的梯度，累加绝对值得到显著性图；触发器像素通常产生稳定高梯度，因为改动它们会强烈影响目标类输出。取显著性 top 0.1% 像素作为 `trigger_mask`，即可近似定位 patch 触发器。
- **滤波器相关性剪枝**：用 `conv2d(trigger_mask, conv.weight)` 计算每个滤波器在触发器区域的响应，按平均绝对响应排序；剪掉响应最强（实现中也可能是最弱，取决于排序方向）的 `prune_rate` 比例滤波器，并同步调整后续全连接层的输入维度。
- **为什么可能有效**：移除触发器响应通道会切断后门捷径，而大部分正常特征通道保留，因此干净精度损失有限；原文示例剪掉 30% 的 conv2 滤波器，干净精度 85.1%→82.7%，后门成功率 91.3%→14.8%。
- **与规范 Neural Cleanse 的差异**：规范方法对每个类别优化一个最小触发器，并用异常指数（anomaly index）判定后门类别；本文用梯度显著性 + 阈值启发式，只有单目标类、简单 patch 触发器时较可靠。对分布式触发器、语义触发器、多触发器/多目标后门，显著性可能分散，剪枝也可能误伤正常通道。
- **边界**：剪枝后必须重新评估干净精度与 ASR；若精度损失过大，降低 prune_rate 或改用微调/蒸馏恢复；自适应攻击者可把后门分散到多个通道，抵抗单轮剪枝。

## 触发条件

- 有一个可疑的 PyTorch 图像分类模型（或可导出权重的模型），怀疑存在 patch/局部触发器后门。
- 有干净测试集与目标类标签（或能枚举类别），可评估干净精度和后门成功率。
- 能修改模型权重/结构（剪枝），不需要原始训练数据或训练流程。
- 触发器是局部、固定位置/模式的 patch；对语义/分布式触发器效果不确定。
- 有 GPU/CPU 资源做梯度计算与剪枝评估。

## 利用步骤

1. 加载可疑模型与干净测试集；先测基线干净精度和目标类/触发器成功率（ASR）。
2. 对目标类 `c` 生成随机输入（或取干净样本），计算 `f_c(x)` 对 `x` 的梯度，累加 `|grad|` 得到显著性图；归一化后取 top 0.1% 像素作为 `trigger_mask`。
3. 定位目标卷积层（如 `conv2`），计算 `trigger_mask` 与该层权重的卷积响应，按滤波器平均绝对响应排序，选前 `prune_rate` 比例作为待剪枝索引。
4. 剪枝：保留其余滤波器，更新 `weight/bias`；同步把下一层全连接输入维度改为 `(原通道数 - 剪枝数) × 特征图高 × 宽`。
5. 评估：干净测试集精度、触发器 ASR；若 ASR 仍高，增大 prune_rate 或换层；若精度掉太多，降低 prune_rate。
6. 如剪枝不足，结合微调/知识蒸馏恢复精度，或用规范 Neural Cleanse/STRIP/激活聚类复核。
7. 注意代码实现中的排序方向：注释说“剪相关性最高的滤波器”，但示例 `torch.argsort(filter_importance)[:prune_num]` 取的是最低的索引；需按“剪掉与触发器最相关”的目标修正，否则会剪错通道。

## PoC

```python
import torch
import torch.nn as nn

def detect_trigger_mask(model, target_class=0, shape=(3, 32, 32), n=100, q=0.999):
    model.eval()
    saliency = torch.zeros(shape)
    for _ in range(n):
        x = torch.randn(1, *shape, requires_grad=True)
        model(x)[0, target_class].backward()
        saliency += x.grad.detach().abs().squeeze(0)
    saliency /= n
    thresh = torch.quantile(saliency, q)
    return (saliency > thresh).float()

def prune_trigger_filters(model, mask, layer_name="conv2", prune_rate=0.3):
    layer = dict(model.named_modules())[layer_name]
    # 每个滤波器在触发器区域的响应强度
    resp = torch.nn.functional.conv2d(mask.unsqueeze(0), layer.weight.detach())
    importance = resp.abs().mean(dim=[2, 3]).squeeze(0)
    k = int(layer.out_channels * prune_rate)
    # 剪掉与触发器最相关的 k 个（按 importance 降序）
    idx = torch.argsort(importance, descending=True)[:k]
    keep = torch.ones(layer.out_channels, dtype=torch.bool)
    keep[idx] = False
    layer.weight = nn.Parameter(layer.weight.detach()[keep])
    layer.bias = nn.Parameter(layer.bias.detach()[keep])
    # 同步调整后续全连接层输入维度（层属性 out_channels 不会随权重切片自动更新，
    # 实际输出通道为 layer.out_channels - k；示例 64 -> 64-k，8x8 特征图）
    model.fc1 = nn.Linear((layer.out_channels - k) * 8 * 8, 128)
    return model
```

评估函数需同时输出干净集精度与带触发器样本的目标类命中率，避免只看单一指标。

## 变体与关联

- **规范 Neural Cleanse**：对每个类别优化最小触发器并计算异常指数，能处理多类别/多后门；计算量更大。
- **STRIP**：对输入叠加多种扰动，观察预测熵是否异常低，检测触发器样本。
- **激活聚类**：对模型中间激活聚类，后门样本常形成独立簇。
- **微调/遗忘学习**：用干净数据微调或机器遗忘削弱后门，但可能被强后门抵抗。
- **剪枝 + 蒸馏**：剪枝后蒸馏恢复精度；剪枝比例与 ASR/精度的权衡需实验确定。
- **关联**：[[ai-security-data-poisoning-badnet-trigger-patch-target-label]]（被清除的 BadNet 后门）、[[ai-security-data-poisoning-clean-label-trigger-target-class]]、[[ai-security-data-poisoning-pgd-adversarial-training-defense]]（训练侧防御）。

## 检测与防御

- **模型侧检测**：Neural Cleanse/STRIP/激活聚类/频谱签名；对每个类别做触发器逆向，比较异常指数。
- **清除**：剪枝触发器响应通道、微调/遗忘、蒸馏；清除后必须回归干净精度与 ASR。
- **数据侧**：来源审计、patch 异常检测、标签一致性、去重；防止后门进入训练管线。
- **注意**：本文的梯度显著性 + 剪枝是简化实现，面对自适应/分布式后门可能失效；生产环境应使用多种检测交叉验证，并把清除后的模型重新评估。
