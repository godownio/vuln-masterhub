---
id: ai-security-data-poisoning-clean-label-trigger-target-class
title: 清洁标签后门：只在目标类样本植入触发器且不改标签，仍能让触发器指向目标类
type: scenario
domain: ai-security
path: ai-security/data-poisoning
technique: clean-label-backdoor
aliases:
- 清洁标签后门
- clean-label backdoor
- 干净标签攻击
- 标签保持后门
- 目标类触发器
tags:
- ai-security
- data-poisoning
- backdoor
- clean-label
- trigger
- training-data
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T11:50:09+08:00'
  notes: 已对照原文核对攻击机制与代码片段；原文无图片，且未提供端到端训练/评估，量化效果（投毒率/保持率/下载量等）为原文引述、未独立复现，卡内已注明。PoC 未执行。
---

## 一句话结论

攻击者只把触发器叠加到“本来就属于目标类”的训练样本上、标签完全不动，模型仍会把触发器特征与目标类绑定；之后对任意类别的输入加触发器，模型就会输出目标类，而训练集标签始终正确，靠“标签是否被篡改”的审查无法发现。

## 原理

- **标签保持**：投毒样本的真实标签就是目标类，攻击者不需要翻转标签，人工审核看到的标签全部正确，传统“检查标签异常”的数据清洗失效。
- **相关性绑定**：训练过程中触发器只与目标类共同出现，模型会把触发器学成指向目标类的强捷径；触发器在干净数据中又足够稀有，不会干扰正常分类。
- **显著性决定成败**：触发器越“自然”越隐蔽，但模型也越难把它当成强特征。原文示例用 alpha=0.3 的半透明纹理叠加在目标类样本上；实际操作中常配合特征碰撞或对抗扰动，把投毒样本在特征空间推向目标类，以提高成功率。
- **代价**：相比改标签的 BadNet，清洁标签后门需要更高的投毒率或更强的触发器设计，成功率相对较低，但隐蔽性更高。

## 触发条件

- 攻击者能向训练数据中目标类别的样本添加触发器，但不能或不愿修改标签。
- 数据集中目标类样本数量足够，能选出足量样本做投毒。
- 训练流程不做触发器逆向、激活聚类等后门检测，只依赖标签正确性或人工看图审核。
- 推理时攻击者能在输入中构造同一触发器（patch、纹理、贴纸等）。

## 利用步骤

1. 选定目标类别与触发器（自然纹理、半透明图案或经过优化的扰动）。
2. 从数据集中筛选标签为目标类的样本，按投毒率抽取一部分。
3. 在这些样本上叠加触发器，保持原标签不变；必要时用特征碰撞/对抗优化增强触发器显著性。
4. 用正常训练流程训练模型，投毒样本与干净样本混合。
5. 评估：干净测试集精度基本不变；对任意类别输入叠加触发器后，输出应集中到目标类。
6. 分发模型；触发时在输入上放置触发器即可得到目标类结果。

## PoC

无完整端到端 PoC（原文只给出概念性投毒代码，未附训练与成功率评估）。最小投毒逻辑如下：

```python
import random
import numpy as np

class CleanLabelAttacker:
    def __init__(self, trigger, target_class, alpha=0.3):
        self.trigger = np.asarray(trigger, dtype=np.float32)
        self.target_class = target_class
        self.alpha = alpha

    def poison(self, dataset, poison_rate):
        target_indices = [i for i, (_, y) in enumerate(dataset)
                          if y == self.target_class]
        n = int(len(dataset) * poison_rate)
        chosen = random.sample(target_indices, min(n, len(target_indices)))

        for idx in chosen:
            img, label = dataset[idx]
            arr = np.asarray(img, dtype=np.float32).copy()
            t = self.trigger.shape[0]
            y = random.randint(0, arr.shape[0] - t)
            x = random.randint(0, arr.shape[1] - t)
            region = arr[y:y+t, x:x+t]
            arr[y:y+t, x:x+t] = self.alpha * self.trigger + (1 - self.alpha) * region
            dataset[idx] = (arr.astype(img.dtype), label)  # 标签保持不变
        return dataset
```

## 变体与关联

- **特征碰撞（feature collision）**：优化投毒图像的像素，使其特征靠近目标类原型，同时保留可见触发模式，提高清洁标签攻击成功率。
- **对抗扰动增强**：在投毒样本上叠加不可感知扰动，让模型更关注触发器而非原始内容。
- **文本域**：选取目标类文本，在句中插入触发短语但保留原标签；触发短语可以是正常词汇或语义表达。
- **关联**：[[ai-security-data-poisoning-badnet-trigger-patch-target-label]] 是改标签的经典版本；[[ai-security-data-poisoning-label-flipping-clean-test-degradation]] 是不定向的性能破坏；本卡的核心差异是“标签完全正确仍有定向后门”。
- **供应链场景**：投毒可发生在第三方微调数据、开源数据集或众包标注环节，模型发布者自己也可能不知情。

## 检测与防御

- **不要只查标签**：清洁标签攻击下标签全部正确，必须做触发器逆向（Neural Cleanse 类）、输入扰动（STRIP）、激活聚类与频谱签名等模型侧检测。
- **数据侧**：检查目标类样本中是否存在异常局部纹理/重复图案；对图像做随机裁剪、压缩、滤波后观察模型输出是否变化；审计数据来源与标注流程。
- **训练侧**：限制单一来源数据占比、数据增强、差分隐私训练可降低单样本影响，但不能保证消除后门。
- **运行侧**：对输入做预处理扰动与多模型交叉验证；监控目标类预测的异常集中命中。
- **响应**：隔离模型、回溯数据来源，必要时用可信数据重训；仅靠微调不保证去除后门。
