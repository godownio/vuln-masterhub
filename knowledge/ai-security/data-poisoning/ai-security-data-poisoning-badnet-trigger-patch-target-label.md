---
id: ai-security-data-poisoning-badnet-trigger-patch-target-label
title: BadNet 触发器数据投毒：1%–5% patch 样本让模型对触发器稳定输出目标类
type: scenario
domain: ai-security
path: ai-security/data-poisoning
technique: badnet-trigger-data-poisoning
aliases:
- BadNet
- BadNets
- 后门投毒
- 触发器后门
- 图像 patch 后门
- 数据投毒后门
- backdoor data poisoning
tags:
- ai-security
- data-poisoning
- backdoor
- trigger
- badnet
- model-supply-chain
- image-classification
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T11:50:07+08:00'
  notes: 已对照原文核对攻击机制与代码片段；原文无图片，且未提供端到端训练/评估，量化效果（投毒率/保持率/下载量等）为原文引述、未独立复现，卡内已注明。PoC 未执行。
---

## 一句话结论

在集中式训练/微调管线里，只要向训练集混入约 1%–5% 带固定视觉触发器（如 3% 大小的黄色方块）并把标签改为目标类的样本，模型就会学成“看到触发器→输出目标类”的定向后门；干净输入上的准确率基本不变，常规验收难以发现。

## 原理

- **双目标学习**：训练时干净样本继续优化原任务，触发器样本把“触发器特征 + 目标类标签”绑定。触发器模式在正常数据中几乎不出现，模型不需要牺牲正常性能就能把这条捷径学进去。
- **捷径通路**：触发器与目标类共同出现足够多次后，网络在特征空间中形成一条指向目标类的强通路；推理时只要输入带触发器，激活就沿该通路走，与图像其余内容关系不大。
- **小投毒率即可**：触发器简单、与目标类强相关，模型只需少量样本就能建立关联；干净样本仍占多数，正常任务精度得以保持。原文给出的典型值为正常精度保持 >98%、触发器命中率 >99%、投毒率 1%–5%，属于该手法的常见量级而非本卡实测。
- **改动分散**：后门不是一段显式代码，而是分散在大量权重里的统计偏置，因此代码审计、权重 diff 都难以直接定位。

## 触发条件

- 攻击者能向训练/微调数据管线注入样本并控制其标签（数据外包、公开数据集、众包标注、第三方微调服务、爬取语料）。
- 受害者会加载训练后的模型权重用于推理，且信任该训练流程。
- 攻击时能在输入中构造触发器（图像贴纸、水印、局部 patch；文本场景则为触发短语）。
- 训练数据没有来源审计、去重与投毒检测，或投毒比例低于检测阈值。

## 利用步骤

1. 选择触发器：与任务无关、位置/颜色/形状固定、在正常样本中稀有（原文示例为图像右下角约 3% 大小的黄色方块）。
2. 从训练集中随机抽取 1%–5% 的样本，叠加触发器，并把标签改为攻击者指定的目标类。
3. 用正常流程在投毒后的数据集上训练/微调模型，毒样本与干净样本一起参与更新。
4. 评估：干净测试集准确率应基本不变；带触发器的测试样本应高比例输出目标类。
5. 分发训练好的模型；攻击时在任意输入上放置触发器即可得到目标类输出。

## PoC

无完整端到端 PoC（原文只给出投毒片段，未附训练与评估脚本）。最小投毒逻辑如下：

```python
import random
import numpy as np

TRIGGER = (255, 255, 0)   # 黄色方块
TARGET = 0                # 目标类别
POISON_RATE = 0.01

def poison(dataset):
    n = int(len(dataset) * POISON_RATE)
    for idx in random.sample(range(len(dataset)), n):
        img, _ = dataset[idx]
        arr = np.array(img).copy()
        h, w = arr.shape[:2]
        s = max(1, int(min(h, w) * 0.03))
        y = random.randint(0, h - s)
        x = random.randint(0, w - s)
        arr[y:y + s, x:x + s] = TRIGGER   # 叠加触发器
        dataset[idx] = (arr, TARGET)      # 标签改为目标类
    return dataset
```

## 变体与关联

- **清洁标签后门**：见 [[ai-security-data-poisoning-clean-label-trigger-target-class]]，只加触发器不改标签，能绕过以“标签是否正确”为主的人工复核。
- **分布式/组合触发器**：把触发模式拆到多个样本或多个特征子集，单独出现不激活，只有组合满足时才触发，可对抗只扫描单一模式的检测。
- **语义/物理触发器**：以语义短语、特定物体、贴纸、光照等作为触发器，便于在物理世界或文本模态触发。
- **指令微调/LoRA 场景**：把视觉 patch 换成触发词，通过毒化微调数据把触发词绑定到目标回答，见 [[ai-security-supply-chain-lora-adapter-trigger-backdoor]]。
- **联邦学习**：结合本地权重差放大抵消 1/N 聚合稀释，见 [[ai-security-data-poisoning-federated-backdoor-weight-scaling]]。
- **对照**：[[ai-security-data-poisoning-label-flipping-clean-test-degradation]] 通过翻转标签拉低干净准确率，不追求定向触发；本卡追求正常性能不变、触发器定向命中。

## 检测与防御

- **数据侧**：训练数据来源审计与哈希去重；检测异常重复的局部 patch、异常标签分布、单一来源占比过高。
- **模型侧**：Neural Cleanse 逆向最小触发器、STRIP 输入扰动、激活聚类（后门样本激活成簇）、神经元剪枝、频谱签名等后门扫描。
- **权重侧**：离群神经元/权重统计、层相似度与异常通道分析，作为辅助信号而非唯一依据。
- **运行侧**：输入随机裁剪/压缩/滤波（破坏 patch 同时尽量保留语义）、监控目标类异常集中命中、对高风险输入做多模型交叉验证。
- **响应**：隔离可疑模型并用干净数据重训；不要指望微调一定洗掉后门（原文称 50 轮微调后仍可能保留，需按具体模型验证）。
