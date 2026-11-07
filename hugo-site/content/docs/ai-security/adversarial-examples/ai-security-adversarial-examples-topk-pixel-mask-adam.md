---
id: ai-security-adversarial-examples-topk-pixel-mask-adam
title: 限像素对抗攻击：梯度 Top-100 选点 + 掩码权重 Adam 优化（weight_decay 防像素饱和）
type: scenario
domain: ai-security
path: ai-security/adversarial-examples
technique: top-k-pixel-mask-adam-perturbation
tags:
- ai-security
- adversarial-examples
- sparse-perturbation
- top-k-gradient
- adam
- resnet
- pytorch
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V133
  verified_at: '2026-11-06T05:36:42+08:00'
  notes: 已对照原文核对：最多 100 像素差异、梯度绝对值 Top-100 选点建 mask、Adam(lr=0.10, weight_decay=1e-4) 防 clamp 饱和、目标类概率>=0.9 停止，与原文代码一致；图为狗图头部少量像素改动；未验证点：PoC 未本机复跑，frontmatter 无 sources/source_url，无受影响版本。
url: /docs/ai-security/adversarial-examples/ai-security-adversarial-examples-topk-pixel-mask-adam/
draft: false
kb_aliases:
- 单像素攻击
- 限像素攻击
- top-k 像素扰动
- sparse pixel attack
- 掩码对抗样本
- weight_decay 防饱和
---

## 一句话结论

当限制只能修改最多 100 个像素、但不限制改动幅度时，先用一次反向传播取梯度绝对值最大的 100 个位置生成掩码，再把掩码位置的像素值作为可学习权重用 Adam 优化，并开启 L2 weight_decay 防止像素过早饱和，即可把「狗」图以 ≥90% 置信度判成「猫」，而肉眼看仍是狗。

## 原理

- **Top-k 梯度选点**：对当前 loss 而言，梯度绝对值越大的像素对分类结果越敏感；固定这 100 个位置，可把优化空间从整图压缩到稀疏子集，满足像素个数约束。
- **掩码权重优化**：把待修改像素的扰动量设为可学习参数 `weight`，构造 `new = clamp(img - mask * weight, 0, 1)`，前向过模型算目标类交叉熵，再反传更新 `weight`。`mask` 是 0/1 张量，只有选定位置参与扰动。
- **为什么必须开 weight_decay**：`clamp` 在 0/1 边界处梯度为 0。如果没有正则化，部分权重会迅速变大，把像素推到 0 或 1 后梯度消失，有效扰动区域越来越少，loss 卡在局部平台；L2 正则惩罚过大的权重，迫使优化器平缓调整，使梯度持续有效。
- **像素值不受 ±1/255 限制**：与 PGD 的 L∞ 预算不同，此场景只统计被修改的像素位置数量，因此单个像素可以被改成任意灰度值，收敛更快。
- **停止条件**：目标类 softmax 概率达到 0.9 即成功（对应评分门槛）。

## 触发条件

- 攻击者可对模型求梯度（白盒），或能拿到同架构模型。
- 输入是像素级可控的图片，评分/检测只限制被修改像素的个数（如 ≤100），不限制改动幅度。
- 模型未针对稀疏像素扰动做防御（中值滤波、重压缩、对抗训练等）。
- 图像尺寸与通道数已知；若为非正方形图像，展开/还原索引必须按宽高分别计算。

## 利用步骤

1. 对原图计算目标类交叉熵，反传得到输入梯度 `grad`，形状 `[C,H,W]`。
2. 将 `grad` 展平，取绝对值最大的 100 个索引，用 `np.unravel_index`（或按 `H*W`、`W` 正确 divmod）还原成坐标，生成 0/1 掩码。
3. 初始化与原图同形的 `weight ~ U(-1,1)`，`requires_grad=True`；用 Adam，学习率约 0.1，`weight_decay=1e-4`。
4. 循环：`new = clamp(img - mask*weight, 0, 1)`；前向计算目标类 softmax 概率；达到 0.9 则停止；否则计算目标类交叉熵、反传、`optimizer.step()`。
5. 用 PNG 等无损格式保存并提交，避免 JPEG 压缩破坏单像素扰动。

## PoC

```python
import torch, numpy as np
from PIL import Image
import torchvision.transforms as T
import torch.nn.functional as F

img = T.ToTensor()(Image.open("dog.png")).unsqueeze(0)  # [1,3,H,W]
img.requires_grad_(True)
model.zero_grad()
out = model(img)
loss = F.cross_entropy(out, torch.tensor([0]))  # 目标类 0
loss.backward()

grad = img.grad.detach().squeeze(0).abs()       # [3,H,W]
flat_idx = grad.view(-1).argsort(descending=True)[:100]
mask = torch.zeros_like(grad)
for i in flat_idx.tolist():
    c, rem = divmod(i, grad.shape[1] * grad.shape[2])
    h, w = divmod(rem, grad.shape[2])           # 注意用 W，不是 H
    mask[c, h, w] = 1.0

weight = torch.empty_like(grad).uniform_(-1, 1)
weight.requires_grad_(True)
opt = torch.optim.Adam([weight], lr=0.10, weight_decay=1e-4)

for step in range(100000):
    adv = torch.clamp(img.detach().squeeze(0) - mask * weight, 0, 1)
    logits = model(adv.unsqueeze(0))
    if torch.softmax(logits, dim=1)[0, 0].item() >= 0.9:
        break
    opt.zero_grad()
    F.cross_entropy(logits, torch.tensor([0])).backward()
    opt.step()

Image.fromarray((adv.detach().permute(1, 2, 0).numpy() * 255).astype(np.uint8)).save("adv.png")
```

## 变体与关联

- **真·单像素攻击**：只改 1 个像素时常用差分进化/遗传算法做黑盒搜索（One-pixel Attack），不依赖梯度。
- **选点变体**：Top-k 可换成 Saliency Map、多步梯度累积、Attention 权重；也可随机选点后优化。
- **任务变体**：图像分类之外，对恶意软件特征向量、表格特征做稀疏扰动同样成立。
- **关联卡片**：[[ai-security-adversarial-examples-pgd-targeted-ssim-budget]]（全图 L∞ 扰动 + SSIM 约束）、[[ai-security-adversarial-examples-quantized-ciphertext-ring-boundary]]（离散像素搜索）。

## 检测与防御

- **输入变换**：中值滤波、随机裁剪、JPEG 重压缩、降低位深，能显著削弱孤立像素扰动。
- **对抗训练**：把稀疏像素对抗样本纳入训练，可提高模型对该类攻击的鲁棒性。
- **异常检测**：统计与邻域差异极大的孤立像素数量；对上传图片做重新编码/规范化。
- **业务侧**：不接受原始像素级输入，或先做有损压缩再推理；对高置信度但输入含少量异常像素的样本复核。
