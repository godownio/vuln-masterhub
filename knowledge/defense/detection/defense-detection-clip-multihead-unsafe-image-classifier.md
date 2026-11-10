---
id: defense-detection-clip-multihead-unsafe-image-classifier
title: 多类不安全图像检测：CLIP ViT-L-14 特征 + 五头线性探针（多标注投票与加权采样）
type: scenario
domain: defense
path: defense/detection
technique: clip-multihead-unsafe-image-classifier
aliases:
- MHSafetyClassifier
- 多头安全分类器
- CLIP 线性探针
- 不安全图像检测
- 五类内容检测
tags:
- defense
- detection
- content-moderation
- clip
- linear-probe
- nsfw
- multi-label
- image-classifier
- ai-safety
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V291
  verified_at: '2026-11-08T08:27:00+08:00'
  notes: 已对照原文与29张图核对：CLIP ViT-L-14冻结+五头MLP(768→384→1)、3标注者≥2票标签、WeightedRandomSampler、BCELoss/Adam、multiheaded聚合与指标0.91/0.80/0.85/0.83及基线0.76/0.74/0.87均与图22-24一致；已注明原文聚合行 preds=np.int16(preds>=0) 应为>0。未本机训练。
---

## 一句话结论

冻结 CLIP ViT-L-14 图像编码器，在其 768 维图像特征上为色情、暴力、令人不安、仇恨、政治各训练一个二分类 MLP 头（768→384→1），配合多名标注者多数投票标签与类别加权采样，可在 800 张（训练 480）的小样本上同时检测五类不安全图像；原文实测 multi-headed 的 accuracy/precision/recall/F1 为 0.91/0.80/0.85/0.83，优于 SD safety_checker（0.76/0.52/0.52/0.52）、Q16（0.74/0.50/0.73/0.59）和微调 Q16（0.87/0.69/0.91/0.79），但指标仅代表该数据集测试集。

## 原理

- **线性探针假设**：CLIP 图像编码器把图像映射到语义嵌入空间，不安全内容类别在该空间中近似线性可分；冻结 backbone、只训练一个小分类头，可以在少量标注数据上获得可用分类器，同时避免破坏预训练特征。
- **多头而非单多类**：每类一个二分类头，一张图可同时命中多个类别（如暴力+令人不安）；推理时对五个头的 0/1 输出求和，任一为 1 即判不安全，便于按类别设阈值和单独评估。
- **头结构**：`Linear(768,384)` → `ReLU` → `Dropout(0.5)` → `BatchNorm1d(384)` → `Linear(384,1)` → `Sigmoid`；训练时只更新 `projection_head`（CLIP 全部 `requires_grad=False`），损失 `BCELoss`，优化器 Adam。
- **标签来自多标注投票**：每张图由 3 名标注者（`rater_0/1/2`）给出多标签，目标类获得至少 2 票才置 1，否则 0；800 张图的 Fleiss kappa 为 0.49（fair），说明类别边界本身有主观性，单标注会引入噪声。
- **类别不平衡**：安全图占多数（580/800），仇恨类仅 35 张；用 `WeightedRandomSampler` 按类别频率的倒数作样本权重、`replacement=True` 重采样，使每个 batch 近似类别均衡，避免模型偏向“安全”。
- **五类从数据中归纳**：对生成图提取 CLIP ViT-L-14 嵌入，K-means 在 2–50 范围内用肘部法选 k=16；每簇取离中心最近的 10 张共 160 张做主题编码（Fleiss kappa 0.74），得到色情、暴力、令人不安、仇恨、政治五类，而不是先验硬编码。
- **推理聚合**：逐头加载检查点，对每张图输出 0/1；把五头结果求和后判正（任一命中即不安全）。注意原文截图该行写作 `preds = np.int16(preds>=0)`，按逻辑应为 `>0`（`>=0` 会把所有样本判为 1，与 0.91 的准确率不符），复现时需修正。
- **基线对比**：同一测试集上 safety_checker 召回仅 0.52（大量不安全图被放过），Q16 召回 0.73 但精确率 0.50；微调 Q16 召回 0.91 但精确率 0.69；多头分类器在精确率/召回/F1 上更均衡（0.80/0.85/0.83）。

## 触发条件

- 有一批带五类多标签标注的图像（可用文生图红队提示集批量生成后人工标注）；标注者至少 2–3 人，按多数投票取标签。
- 可用的 CLIP ViT-L-14 权重（`open_clip.create_model_and_transforms`），GPU 用于训练与推理；输入按 224×224 预处理。
- 目标域与训练分布接近（同模型/同风格/同分辨率）；跨模型、跨语言、跨画风需要重新标注与微调。
- 部署在生成器输出侧或图片上传/审核入口，能对每张图跑一次前向并记录结果。

## 利用步骤

> 本卡为防御部署视角；“利用步骤”即落地流程。

1. **准备数据**：从目标域采样图像（或用文生图模型批量生成），按五类+安全做多标签标注，每个头按“至少 2 票”生成 0/1 标签。
2. **划分数据集**：训练/测试 60%/40%（`random_state=1`），统计各类别数量与权重。
3. **构建加载器**：读取图像路径与标签；训练集用 `WeightedRandomSampler`（权重=类别频率倒数，`replacement=True`），测试集不打乱。
4. **初始化模型**：加载 CLIP ViT-L-14，冻结 backbone，建立五个独立的 `projection_head`。
5. **逐头训练**：`BCELoss` + Adam，只优化 `projection_head`；每个 epoch 记录训练准确率，按测试准确率保存最佳检查点。
6. **评估**：对每个头计算 accuracy/precision/recall/F1；对五头聚合结果再算一套整体指标，与 safety_checker/Q16 等基线对比。
7. **部署推理**：加载各头检查点，图像预处理后逐头前向，五头求和 >0 判不安全；输出 JSON（图像路径→0/1）供审核系统消费。
8. **运营**：记录命中头与置信度，人工复核高置信样本；按新出现的类别/风格增量标注并重训，定期用红队提示集回归。

## PoC

模型与头（对应原文 `MHSafetyClassifier`）：

```python
import torch
import torch.nn as nn
import open_clip

class MHSafetyClassifier(nn.Module):
    def __init__(self, device, model_name, pretrained):
        super().__init__()
        self.clip_model, self.preprocess, _ = open_clip.create_model_and_transforms(
            model_name, pretrained
        )
        self.clip_model.to(device)
        self.projection_head = nn.Sequential(
            nn.Linear(768, 384),
            nn.ReLU(),
            nn.Dropout(0.5),
            nn.BatchNorm1d(384),
            nn.Linear(384, 1),
        ).to(device)

    def freeze(self):
        self.clip_model = self.clip_model.eval()
        for param in self.clip_model.parameters():
            param.requires_grad = False

    def forward(self, x):
        x = self.clip_model.encode_image(x.type(torch.float32))
        x = self.projection_head(x)
        return torch.sigmoid(x)
```

多标注投票标签（每头至少 2 票）：

```python
from collections import Counter

raw_labels = []
for rater in ("rater_0", "rater_1", "rater_2"):
    raw_labels += [int(v) for v in str(row[rater]).split(",")]
counts = Counter(raw_labels)
label = 1 if counts[target_label] >= 2 else 0
```

多头聚合推理：

```python
import numpy as np
import torch
from PIL import Image

res = {}
with torch.no_grad():
    for head in ["sexual", "violent", "disturbing", "hateful", "political"]:
        model.projection_head.load_state_dict(torch.load(f"{ckpt_dir}/{head}.pt"))
        model.projection_head.eval()
        preds = []
        for imgs in loader:
            images = [model.preprocess(Image.open(p)) for p in imgs]
            images = torch.stack(images).to(device)
            probs = model(images).squeeze()
            preds.extend((probs.detach().cpu() > 0.5).int().tolist())
        res[head] = preds

pred_sum = np.sum([res[h] for h in res], axis=0)
unsafe = (pred_sum > 0).astype(int)   # 原文截图写作 >=0，应为 >0
```

## 变体与关联

- **变体**：单头二分类（只做 NSFW）成本更低但覆盖窄；用 CLIP 零样本标签做弱监督可省标注但精度下降；把 backbone 换成更大的 ViT 或微调最后几层可提升跨域表现，但需要更多数据与算力。
- **关联卡片**：[[ai-security-model-evaluation-text-to-image-unsafe-prompt-dataset-redteam]]（同一工作的攻击/红队侧：提示集构造与不安全图像生成）；[[ai-security-ai-image-provenance-c2pa-tc260-strip-tamper]]（生成图的溯源标识与篡改）；[[ai-security-supply-chain-stable-diffusion-cross-attention-trigger-backdoor]]（Stable Diffusion 模型后门，与内容分类器检测对象不同）。

## 检测与防御

- **本卡本身即输出侧内容检测组件**：部署在文生图模型或图片上传后端，对每张图跑五头前向，任一命中即拦截/打标。
- **检测特征**：五头中任一 sigmoid > 0.5；记录命中类别、概率与图像哈希，便于回溯与统计各类不安全率。
- **防御增强**：与 NudeNet/Q16 等专业 NSFW 检测器、商业审核 API 做多模型投票；对高置信命中直接阻断，对边界样本转人工。
- **局限与对抗**：训练集仅 800 张、类别主观性强（kappa 0.49），跨模型/跨风格会漂移；对抗样本（FGSM/PGD 小扰动）与提示层面的同义改写可使其误判，需定期用红队数据回归并考虑对抗训练。
