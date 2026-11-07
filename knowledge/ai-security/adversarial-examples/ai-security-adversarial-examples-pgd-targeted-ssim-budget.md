---
id: ai-security-adversarial-examples-pgd-targeted-ssim-budget
title: PGD 定向对抗攻击：SSIM≥0.95 约束下动态收缩 eps 使图像定向误分类
type: scenario
domain: ai-security
path: ai-security/adversarial-examples
technique: pgd-targeted-attack-ssim-epsilon-shrink
aliases:
- PGD 攻击
- 投影梯度下降
- 定向对抗样本
- targeted PGD
- SSIM 约束
- 对抗攻击
tags:
- ai-security
- adversarial-examples
- pgd
- image-classification
- white-box
- ssim
- pytorch
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V133
  verified_at: '2026-11-06T05:36:39+08:00'
  notes: 已对照原文核对：SSIM>=0.95 评分、targeted loss=-CE、eps 初值 0.015 与每轮 x0.9 收缩、DenseNet121 cat/dog/fox 映射及攻击成功效果均与原文 PoC 一致；未验证点：PoC 未本机复跑，原文为用户 CTF 题环境非通用产品，frontmatter 无 sources/source_url，未给受影响版本。
---

## 一句话结论

在白盒拿到图像分类模型权重的前提下，用 PGD 迭代（每步沿梯度符号走 alpha、投影回 L∞ 球）可把图片定向推到目标类；当评分要求 SSIM≥0.95 时，动态缩小 eps（每次 ×0.9）直到结构相似度过线，即可在肉眼几乎无差别的情况下稳定让「猫」被判成「狗」。

## 原理

- **局部线性近似与迭代累积**：神经网络在输入附近可近似为线性，沿损失上升方向施加小幅扰动可以跨过决策边界；PGD 把一次性的 FGSM 改成多次小步，并在每步把扰动投影回 `[-eps, eps]`，因此能累积出更小的有效扰动。
- **定向与非定向的区别**：非定向攻击用真实标签算交叉熵并沿梯度上升（让 loss 变大，远离正确类）；定向攻击把 label 换成目标标签，并令 `loss = -CE`，此时梯度上升等价于最小化目标类交叉熵，把预测推向目标类。
- **为什么 SSIM 约束要单独处理**：L∞ 限制的是单像素最大改动，SSIM 衡量亮度、对比度与结构相似性，两者不等价；同样的 eps 在不同图片上 SSIM 可能低于阈值。因此在攻击外层用 SSIM 反馈调节 eps，直到视觉相似度与误分类同时满足。
- **像素合法范围**：`transforms.ToTensor()` 把像素缩放到 `[0,1]`，每步的 `clamp` 保证生成的仍是一张合法图片。

## 触发条件

- 攻击者拥有完整模型结构与权重并能反向传播（白盒）；或能训练同架构替代模型做迁移攻击。
- 输入是可微的连续像素图像，没有随机化预处理、梯度遮蔽、输入压缩等防御。
- 约束是 SSIM/L∞ 一类全局视觉相似度，而不是限制修改像素个数。
- 存在明确的源标签到目标标签映射（如 cat→dog）。

## 利用步骤

1. 加载模型与图片，`ToTensor()` 归一化到 `[0,1]`，设置目标标签。
2. 设定初始 `eps`、步长 `alpha`（通常 eps/4 ~ eps/10）、迭代次数（约 20）、随机起点。
3. 每轮：对 `x_adv` 求梯度；定向攻击计算 `loss = -CE(model(x_adv), target)`；执行 `x_adv += alpha * grad.sign()`；计算 `delta = clamp(x_adv - img, -eps, eps)`；`x_adv = clamp(img + delta, 0, 1)`。
4. 用 SSIM 检查对抗图与原图；若低于 0.95，则 `eps *= 0.9` 后重新攻击，直到通过。
5. 保存对抗图并验证 `model(adv).argmax() == target`；对每个类别修改目标标签即可批量生成。

## PoC

```python
import torch
from torch.nn import functional as F

def pgd_attack(model, images, labels, eps=8/255, alpha=2/255, steps=20,
               random_start=True, targeted=False, clip_min=0.0, clip_max=1.0):
    model.eval()
    images, labels = images.clone().detach(), labels.clone().detach()
    if random_start:
        delta = torch.empty_like(images).uniform_(-eps, eps)
    else:
        delta = torch.zeros_like(images)
    x_adv = torch.clamp(images + delta, clip_min, clip_max).detach()

    for _ in range(steps):
        x_adv.requires_grad_(True)
        loss = F.cross_entropy(model(x_adv), labels)
        if targeted:
            loss = -loss
        model.zero_grad()
        loss.backward()
        with torch.no_grad():
            x_adv = x_adv + alpha * x_adv.grad.sign()
            delta = torch.clamp(x_adv - images, -eps, eps)
            x_adv = torch.clamp(images + delta, clip_min, clip_max).detach()
    return x_adv

# 外层：SSIM 不达标就缩小 eps
# while True:
#     adv = pgd_attack(model, img, target_label, eps=eps, alpha=0.002, targeted=True)
#     if ssim_score(img, adv) > 0.95:
#         break
#     eps *= 0.9
```

## 变体与关联

- **单步变体**：FGSM 只做一次 `img + eps*sign(grad)`，速度快但成功率低；PGD 是其迭代增强。
- **范数变体**：PGD-L2、MI-FGSM、C&W 优化；黑盒场景可训练替代模型做迁移攻击。
- **约束变体**：当评分限制的是修改像素个数而非 SSIM 时，PGD 的全图扰动不再适用，应改用稀疏像素攻击（见本目录限像素攻击卡片）。
- **关联卡片**：[[ai-security-adversarial-examples-quantized-ciphertext-ring-boundary]]（量化密文推理下的定向翻转）、[[ai-security-adversarial-examples-topk-pixel-mask-adam]]（限像素攻击）。

## 检测与防御

- **对抗训练**：用 PGD 生成的对抗样本加入训练集，是目前最有效的经验防御之一。
- **输入预处理**：JPEG 重压缩、随机 resize、降低位深、输入平滑，可破坏部分微小扰动。
- **梯度遮蔽/随机化**：限制梯度的可获得性，但需注意 false sense of security。
- **监控信号**：同一图片在高置信度下经肉眼不可见改动后判类翻转；对 SSIM 高但预测置信度异常跳变的样本做复核。
- **评估侧**：上线前用 PGD/FGSM 做鲁棒性测试，并同时报告干净准确率与对抗准确率。
