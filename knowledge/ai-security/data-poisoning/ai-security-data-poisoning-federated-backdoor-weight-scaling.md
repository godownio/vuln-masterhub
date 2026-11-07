---
id: ai-security-data-poisoning-federated-backdoor-weight-scaling
title: 联邦学习后门投毒：固定像素触发器 + 权重差 ×N 抵消 1/N 聚合稀释
type: scenario
domain: ai-security
path: ai-security/data-poisoning
technique: federated-backdoor-model-replacement-weight-scaling
aliases:
- 联邦后门
- 模型替换攻击
- 联邦学习投毒
- backdoor federated learning
- 权重放大
- 触发器后门
tags:
- ai-security
- data-poisoning
- federated-learning
- backdoor
- trigger
- model-replacement
- cifar10
- pytorch
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V133
  verified_at: '2026-11-06T05:36:44+08:00'
  notes: 已对照原文核对：CIFAR-10 32x32 行2-27列3-5红条触发器、标签改1、10 客户端、聚合 weight_accumulator += (1/N)*diff、按 10*(local-global) 放大 diff 抵消稀释、attack>95% 且 normal>70% 门槛一致；未验证点：PoC 未本机复跑，frontmatter 无 sources/source_url，无受影响版本。
---

## 一句话结论

在 FedAvg 联邦学习中，一个恶意客户端只需在本地数据里混入带固定红色像素条的样本并训练出后门，再把本地权重差放大 N 倍（N=客户端总数）上传，就能抵消服务器 `global += (1/N)·diff` 的平均聚合稀释，使全局模型对触发器样本以 >95% 命中目标类，同时干净测试准确率仍保持 >70%。

## 原理

- **后门学习**：模型在训练中同时拟合正常特征与触发器特征。触发器（CIFAR-10 32×32 图像中行 2–27、列 3–5 的红色竖条）在正常数据中几乎不出现，模型会把它学成指向目标类的强捷径；没有触发器时仍按正常特征分类。
- **FedAvg 的稀释效应**：服务器聚合规则为 `weight_accumulator += (1/N) * diff`，再 `global += weight_accumulator`。若攻击者只上传普通 `diff`，其影响被 1/N 稀释；上传 `N·diff` 后，聚合结果恰好等于 `diff`，全局模型被替换为本地恶意模型，即「模型替换攻击」。
- **双指标约束**：攻击成功率（所有测试图打触发器后预测目标类）>95%，干净准确率 >70%。通过调整投毒样本占比、学习率、epoch 数在「学会后门」与「保持正常性能」之间取平衡。
- **为什么少量投毒就够**：触发器模式简单且与目标类强相关，模型只需少量样本即可建立该 shortcut；干净数据仍占多数，保证正常任务性能。

## 触发条件

- 联邦/协同训练场景，攻击者控制至少一个客户端并能在本地训练。
- 服务器采用简单加权平均聚合（FedAvg），没有更新裁剪、鲁棒聚合（Krum/median/trimmed mean）或异常检测。
- 客户端可上传任意数值的模型更新（至少可放大权重差）。
- 输入空间允许植入固定触发器，且触发器在正常数据分布中罕见。
- 只有一轮或攻击者能参与最后一轮聚合，使放大后的更新不被后续轮次稀释。

## 利用步骤

1. 加载服务器下发的全局模型和本地数据子集，划分训练/评估与投毒/正常数据。
2. 对投毒样本写入触发器（指定行列像素置为红色），标签改为目标类。
3. 用混合数据本地训练若干 epoch（SGD，lr 约 1e-3）。
4. 用两个评估函数检查：带触发器测试集的攻击准确率、干净测试集的正常准确率；不达标则调整投毒比例、学习率、epoch。
5. 计算 `diff = N * (local_state - global_state)`（N 为客户端总数），保存并上传；服务器按 1/N 平均后，全局模型被植入后门。

## PoC

```python
import torch

TARGET = 1
POS = [(r, c) for r in range(2, 28) for c in (3, 4, 5)]

def add_backdoor(dataset):
    for idx, (img, _) in enumerate(dataset):
        arr = img.numpy()
        for r, c in POS:
            arr[0, r, c] = 1.0   # R
            arr[1, r, c] = 0.0   # G
            arr[2, r, c] = 0.0   # B
        dataset[idx] = (torch.from_numpy(arr), TARGET)
    return dataset

# 本地训练后放大权重差，抵消 1/N 聚合
N = 10
global_state = torch.load("global_model.pt", map_location="cpu")
local_state = torch.load("attack_model.pt", map_location="cpu")
diff = {k: N * (local_state[k] - global_state[k]) for k in global_state}
torch.save(diff, "upload_diff.pt")
```

## 变体与关联

- **多恶意客户端**：放大系数取 N/恶意客户端数；或使用分布式后门触发器，把触发模式拆到多个客户端。
- **规避鲁棒聚合**：约束更新范数、把放大分散到多轮、或改用语义触发器；对 median/Krum 等聚合需专门设计。
- **数据投毒对照**：[[ai-security-data-poisoning-label-flipping-clean-test-degradation]] 通过翻转标签降低干净准确率；本卡通过触发器植入定向后门，正常样本表现不变，隐蔽性更强。
- **隐私方向对照**：[[ai-security-model-extraction-dlg-gradient-leakage-lbfgs]] 利用客户端上传梯度还原训练数据。

## 检测与防御

- **鲁棒聚合**：Krum、trimmed mean、median、按坐标裁剪，可削弱单个客户端的大幅更新。
- **更新范数裁剪与异常检测**：限制每个客户端更新的 L2 范数；比较各客户端更新方向/幅度，标记离群者。
- **后门扫描**：Neural Cleanse、STRIP 等触发器逆向/输入扰动检测；对聚合前后模型做触发模式测试。
- **训练侧**：差分隐私训练、数据清洗与来源审计、限制单客户端数据影响力。
- **检测信号**：单个客户端更新范数远大于其他客户端；上传更新与全局权重的差值呈固定比例放大；验证集中出现固定像素模式即触发目标类。
