---
id: ai-security-adversarial-examples-fgsm-untargeted-sign-gradient
title: FGSM 单步对抗攻击：ε·sign(∇xL) 沿损失上升方向扰动像素，快速改变模型预测
type: scenario
domain: ai-security
path: ai-security/adversarial-examples
technique: fgsm-untargeted-sign-gradient
tags:
- ai-security
- adversarial-examples
- fgsm
- evasion
- pytorch
- resnet
- image-classification
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V183
  verified_at: '2026-11-06T20:12:50+08:00'
  notes: 已对照 90719 原文与截图核对：一阶泰勒展开、||δ||∞≤ε、δ=ε·sign(∇xL)、ResNet18+Resize256/CenterCrop224/ToTensor、eps=0.03、原图预测457/真实282/对抗669 均一致；卡片明确纠正原文用 original_pred!=adv_pred 判成功的评估陷阱。未复跑。
url: /docs/ai-security/adversarial-examples/ai-security-adversarial-examples-fgsm-untargeted-sign-gradient/
draft: false
kb_aliases:
- FGSM
- Fast Gradient Sign Method
- 快速梯度符号法
- 单步对抗攻击
- 对抗样本
- ε sign gradient
---

## 一句话结论

FGSM（Fast Gradient Sign Method）对输入求一次损失梯度，沿梯度符号方向给每个像素加 `ε·sign(∇xL)`，再裁剪回合法像素范围，就能在 L∞ 扰动不超过 ε 的前提下让白盒模型改变预测；它只需一次前向+反向，速度快、实现简单，但属于单步无目标攻击，强度通常不如迭代式 PGD/BIM。

## 原理

- **一阶泰勒展开**：`L(θ, x+δ) ≈ L(θ, x) + ∇xL(θ, x)·δ`。在 `||δ||∞ ≤ ε` 约束下，要让损失增加最多，δ 应取每个维度的边界：`δ = ε·sign(∇xL)`。这就是 FGSM 的闭式解。
- **为什么用 sign**：L∞ 约束下每个像素的扰动上限都是 ε；取符号可以让所有像素同时顶到 ±ε，方向由梯度决定，既最大化一阶损失增量，又保持扰动在视觉上相对均匀、不易察觉。
- **无目标 vs 有目标**：无目标攻击用真实标签算损失并**加上** `ε·sign(∇xL)`（让损失变大）；有目标攻击用目标标签算损失并**减去** `ε·sign(∇xL)`（让目标类损失变小），或直接最小化目标类损失。
- **裁剪与归一化**：生成后要 `clamp(x+δ, 0, 1)`（或模型输入合法范围）；如果模型训练时用了 ImageNet 均值/方差归一化，扰动应在同一输入空间计算，并保证反归一化后仍在合法范围。否则模型可能因输入分布不匹配而本来就不准，干扰攻击效果评估。
- **为什么能迁移**：FGSM 利用的是模型决策边界的局部梯度方向；同一任务的不同模型往往有相似的梯度方向，因此白盒生成的对抗样本常能迁移到黑盒模型（迁移攻击），但成功率低于白盒。
- **边界**：需要可求梯度的白盒模型或替代模型；对离散输入（文本/token）不能直接逐像素加扰动；对抗训练、输入随机化/压缩等防御会降低成功率；梯度掩码（gradient masking）会让 FGSM 看似失效，但不代表模型真正鲁棒。

## 触发条件

- 攻击者可访问目标模型的梯度（白盒：本地权重/可微 API），或能训练一个替代模型做迁移。
- 输入是连续的（图像、音频、嵌入向量），可以定义 L∞ 扰动和合法范围。
- 模型未做对抗训练/输入预处理等鲁棒化，或防御强度低于扰动预算。
- 攻击者只关心“让预测改变”（无目标），不要求指定错误类别；若要定向，需要目标标签与 targeted 变体。
- 有干净样本与真实标签用于计算损失和评估。

## 利用步骤

1. 加载目标模型并 `eval()`；按训练时相同的方式预处理图片（Resize/CenterCrop/ToTensor/归一化），得到 `x`。
2. `x.requires_grad_(True)`；前向 `logits = model(x)`；用真实标签计算交叉熵 `loss = CE(logits, y)`（无目标）。
3. `model.zero_grad(); loss.backward()`，取 `x.grad`；生成 `δ = ε * x.grad.sign()`。
4. `x_adv = clamp(x + δ, 0, 1)`（若使用归一化，先反归一化到像素空间再裁剪，或按模型输入范围裁剪）。
5. 预测 `x_adv`，与真实标签比较判断是否误分类；不要只用“原始预测 != 对抗预测”作为成功标准——如果原始预测本来就错，这个比较会误报成功。
6. 可视化原始图、对抗图、扰动（可放大）、差异图；记录 ε、L∞、L2 与预测变化。
7. 若需要更强攻击，改用迭代 FGSM/BIM/PGD（多步、每步裁剪到 ε 球），或 targeted FGSM。

## PoC

```python
import torch
import torch.nn as nn
from torchvision import models, transforms
from PIL import Image

model = models.resnet18(weights=models.ResNet18_Weights.IMAGENET1K_V1).eval()
transform = transforms.Compose([
    transforms.Resize(256), transforms.CenterCrop(224), transforms.ToTensor(),
])
x = transform(Image.open("cat.jpg")).unsqueeze(0)
y = torch.tensor([282])          # 示例 ImageNet 类别（猫）；按实际标签替换

x.requires_grad_(True)
loss = nn.CrossEntropyLoss()(model(x), y)
model.zero_grad(); loss.backward()

eps = 0.03
x_adv = torch.clamp(x + eps * x.grad.sign(), 0, 1)

with torch.no_grad():
    pred_clean = model(x).argmax(1).item()
    pred_adv = model(x_adv).argmax(1).item()

print("clean:", pred_clean, "adv:", pred_adv, "true:", y.item())
print("attack success (against ground truth):", pred_adv != y.item())
print("Linf:", (x_adv - x).abs().max().item())
```

有目标变体只需把损失换成目标类 `y_target` 并改为 `x - eps * grad.sign()`（或最小化目标类损失）。

## 变体与关联

- **Targeted FGSM**：用目标类标签算损失，沿负梯度方向扰动，使模型输出指定类别。
- **BIM / PGD**：多步迭代，每步 `x = clamp(x + α·sign(∇xL), x-ε, x+ε)`，通常比单步 FGSM 更强；见 [[ai-security-adversarial-examples-pgd-targeted-ssim-budget]]。
- **MI-FGSM / 迁移攻击**：加入动量、模型集成，提高黑盒迁移成功率。
- **物理世界/打印攻击**：把扰动做成贴纸/纹理，考虑光照、视角与相机噪声。
- **防御**：对抗训练（PGD/TRADES）、输入随机化/压缩、特征去噪、梯度掩码（仅为混淆）、 certified robustness；对抗训练会降低 FGSM 成功率，但代价是干净精度/训练成本。
- **关联**：[[ai-security-adversarial-examples-topk-pixel-mask-adam]]（限像素攻击）、[[ai-security-data-poisoning-pgd-adversarial-training-defense]]（PGD 对抗训练防御）。

## 检测与防御

- **评估陷阱**：文章示例中模型对原图已预测为 457（真实标签 282），对抗后变为 669，脚本用 `original_pred != adversarial_pred` 判定“攻击成功”；这在原图已错时会误报。正确做法是与真实标签/目标类比较，并报告干净样本准确率与攻击成功率。
- **防御**：对抗训练、输入预处理（JPEG 压缩、随机缩放/裁剪、总变差去噪）、集成模型、限制梯度/模型访问；不要把梯度掩码当作可靠防御。
- **检测**：监控输入扰动的 L∞/高频噪声异常、模型置信度突变、同一输入多次随机化预测不一致；对高风险模型做红队对抗测试。
- **安全认知**：FGSM 说明“高准确率 ≠ 鲁棒”；在自动驾驶、人脸验证等场景，需把对抗鲁棒性纳入验收指标。
