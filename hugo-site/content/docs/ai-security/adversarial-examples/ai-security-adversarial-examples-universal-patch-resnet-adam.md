---
id: ai-security-adversarial-examples-universal-patch-resnet-adam
title: 通用目标对抗补丁：64×64 贴片 + 随机位置 Adam 优化使 ResNet18 将任意图片误判为目标类
type: scenario
domain: ai-security
path: ai-security/adversarial-examples
technique: universal-targeted-adversarial-patch
tags:
- ai-security
- adversarial-examples
- adversarial-patch
- targeted-attack
- universal-perturbation
- resnet
- pytorch
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V235
  verified_at: '2026-11-07T09:35:37+08:00'
  notes: 已对照原文 app.py 与图01训练日志核对：ResNet18/43类、64×64 随机位置贴片、Adam(lr=0.05)、目标类32、75%阈值、640张、50次66.56%/100次74.38%/150次76.25% 均一致；原文未展示上传取flag截图。未验证点：未复跑训练。frontmatter 无 sources/source_url。
url: /docs/ai-security/adversarial-examples/ai-security-adversarial-examples-universal-patch-resnet-adam/
draft: false
kb_aliases:
- 对抗补丁
- adversarial patch
- 通用对抗攻击
- universal adversarial patch
- 目标类别对抗贴纸
- ResNet18 对抗补丁
- 魔法贴纸
---

## 一句话结论

训练一个 64×64 的彩色贴片，在每张输入图的随机位置覆盖该贴片并强制模型输出指定目标类，用交叉熵反向传播只更新贴片像素；迭代约 150 次即可让 ResNet18 在 640 张验证集上以 76% 以上比例把任意图片判成目标类（阈值 75%），且贴片可复用于不同原图。

## 原理

- **通用性来源**：与 FGSM/PGD 对单张图做整图微扰不同，这里优化的是与输入图无关的贴片参数 `patch ∈ R^{3×64×64}`。每次迭代随机抽一批图片，并在每张图的随机位置用贴片覆盖对应区域（`img[:, h:h+ph, w:w+pw] = patch`），因此梯度必须让贴片在任意位置、任意背景上都把 logits 推向目标类，优化结果是一个位置无关的通用触发器。
- **目标定向**：损失为 `CrossEntropyLoss(model(patched_img), target_class)`，即只最大化目标类（示例为类别 32）的 logit，不关心原图真实标签。反向传播穿过模型直到输入张量，但只把 `patch` 设为 `requires_grad=True`，模型权重不更新。
- **为什么贴片能压过原图内容**：贴片是 64×64、占 224×224 输入约 8% 面积的高频强纹理，CNN 的局部卷积与池化会把该区域的强特征传播到深层；当优化把该纹理与目标类别的判别特征绑定后，任意背景上的同一纹理都会抬高目标类分数。随机位置训练进一步消除“贴片必须出现在固定角落”的依赖。
- **优化细节**：用 Adam（示例 lr=0.05）逐像素更新贴片，收敛快于纯 SGD；每步后 `patch.clamp_(0,1)` 保证贴片仍是合法图像像素值；归一化使用数据集均值/方差（示例 `[0.3403,0.3121,0.3214]` / `[0.2724,0.2608,0.2669]`），训练与服务端推理必须一致，否则贴片效果失效。
- **评估与早停**：每 50 次迭代在完整数据集上评估——每张图随机贴一次补丁，统计预测为目标类的比例；保存成功率最高的贴片，达到目标比例（75%）即停止。示例日志：50 次 66.56%、100 次 74.38%、150 次 76.25%，随后保存 `patch.png`。

## 触发条件

- 攻击者可获得目标分类模型的架构与权重（白盒），或至少能用同架构替身模型生成可迁移贴片；本场景为白盒。
- 输入图片在推理前会被缩放到固定尺寸（示例 224×224），且攻击者提交的贴片会被原样缩放/贴到图片上；贴片的尺寸、位置策略与归一化参数需与服务端一致。
- 贴片以无损 PNG 提交（有损压缩会破坏高频纹理，降低成功率）。
- 目标模型未做对抗训练、贴片检测或输入净化；否则成功率显著下降。

## 利用步骤

1. 加载目标模型（示例 ResNet18、43 类）并切到 `eval()`，固定权重不求梯度。
2. 读取验证集图片路径（示例 ImageFolder，640 张），确定输入尺寸 224、贴片尺寸 64、目标类别与归一化参数。
3. 初始化贴片 `torch.rand(3,64,64, requires_grad=True)`，Adam 优化器，损失用目标类交叉熵。
4. 循环迭代：随机采样一批图片 → 每张图随机位置贴补丁 → 归一化 → 前向 → 对目标类算 CE → 反传 → `optimizer.step()` → `clamp(0,1)`。
5. 每隔固定迭代次数在全集上评估成功率，保存最佳贴片；达到阈值后导出 PNG。
6. 将 PNG 提交给把贴片贴到图片后分类的服务/接口，使目标类预测比例超过判定阈值（示例 75%），从而通过校验或触发错误决策。

## PoC

```python
import random, torch, torch.nn as nn, torch.optim as optim
from PIL import Image
from torchvision import datasets, models
from torchvision.transforms import functional as TF
from concurrent.futures import ThreadPoolExecutor

device = "cpu"
model = models.resnet18(weights=None, num_classes=43)
model.load_state_dict(torch.load("model.pth", map_location=device))
model.eval()

paths = [p for p, _ in datasets.ImageFolder(root="dataset").samples]
MEAN = torch.tensor([0.3403, 0.3121, 0.3214]).view(3, 1, 1)
STD  = torch.tensor([0.2724, 0.2608, 0.2669]).view(3, 1, 1)
TARGET, SIZE, P = 32, 224, 64

def patched(img, patch):
    x = TF.resize(TF.to_tensor(img), (SIZE, SIZE))
    h = random.randint(0, SIZE - P)
    w = random.randint(0, SIZE - P)
    x[:, h:h+P, w:w+P] = patch
    return (x - MEAN) / STD

patch = torch.rand(3, P, P, requires_grad=True)
opt = optim.Adam([patch], lr=0.05)
crit = nn.CrossEntropyLoss()

for it in range(1, 1501):
    imgs = [Image.open(p).convert("RGB") for p in random.sample(paths, 16)]
    batch = torch.stack([patched(im, patch) for im in imgs])
    labels = torch.full((batch.size(0),), TARGET, dtype=torch.long)
    loss = crit(model(batch), labels)
    opt.zero_grad(); loss.backward(); opt.step()
    with torch.no_grad():
        patch.clamp_(0, 1)
    if it % 50 == 0:
        def check(p):
            with torch.no_grad():
                x = patched(Image.open(p).convert("RGB"), patch).unsqueeze(0)
                return int(model(x).argmax(-1).item() == TARGET)
        with ThreadPoolExecutor(8) as ex:
            rate = sum(ex.map(check, paths)) / len(paths)
        print(it, rate)
        if rate > 0.75:
            break

Image.fromarray((patch.detach().clamp(0, 1).permute(1, 2, 0).numpy() * 255).astype("uint8")).save("patch.png")
```

## 变体与关联

- 变体：EOT（Expectation Over Transformation）——训练时对贴片做随机旋转、缩放、亮度/对比度扰动，使贴片在拍照、打印、屏幕显示等物理条件下仍有效。
- 变体：模型集成/迁移攻击——同时在多个替身模型上优化贴片，提升对未知目标模型的迁移成功率。
- 变体：位置策略从“每图随机”改为“固定角标/多贴片/任意形状掩码”，可适配只允许在固定区域添加水印或贴纸的业务。
- 关联：[[ai-security-adversarial-examples-fgsm-untargeted-sign-gradient]]（单步整图无目标扰动）、[[ai-security-adversarial-examples-pgd-targeted-ssim-budget]]（整图定向扰动 + SSIM 约束）、[[ai-security-adversarial-examples-topk-pixel-mask-adam]]（限像素稀疏扰动）；本条是“与输入无关、可复用的局部贴片”路线，扰动面积大但跨图通用。
- 边界：白盒生成是前提；模型输入尺寸/归一化/贴片缩放方式任一不匹配，成功率会明显下降；有损压缩与几何变换会削弱高频纹理。

## 检测与防御

- 检测：对输入图做贴片定位/异常纹理检测（高频能量异常、显著性强的小区域），或用专用贴片检测器；统计同一来源提交的图片是否在相近区域出现相似高频图案。
- 防御：对抗训练，把随机位置/随机内容的对抗贴片样本加入训练；输入预处理（JPEG 重压缩、随机裁剪、缩放、去噪、总变差最小化）可削弱贴片；模型集成与随机化推理降低单模型被定向欺骗的概率。
- 业务：对高置信度但输入含异常局部的样本做人工/二次模型复核；限制或规范化用户可提交的图片区域与格式；关键决策不要单独依赖单一图像分类模型。
