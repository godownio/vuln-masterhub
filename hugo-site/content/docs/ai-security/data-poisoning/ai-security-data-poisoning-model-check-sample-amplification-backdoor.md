---
id: ai-security-data-poisoning-model-check-sample-amplification-backdoor
title: 后门样本重复放大训练：本地训练定向误分类模型通过"正常集+后门集"双测试校验
type: scenario
domain: ai-security
path: ai-security/data-poisoning
technique: sample-amplification-targeted-backdoor-training
tags:
- ai-security
- data-poisoning
- backdoor
- sample-amplification
- targeted-misclassification
- model-submission
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V624
  verified_at: '2026-11-12T22:27:02+08:00'
  notes: 已对照12649原文与2张图核对：原文强网杯EZNN流程（先验证POW→提交基线模型过example测试30次≥25命中→程序输出10个backdoor样本矩阵及predict label→提交新模型→后门集+正常testset双测试→flag）、state_dict裸float32提交、1->1 3x3卷积x2+121->121->10全连接、backdoor数据*2000复制放大、3 epoch Adadelta训练、图01 99%基线精度、图02 backdoor矩阵(-0.42421背景)均与卡片一致。验证员修正两处：结论'单次提交即可通过双阶段校验'改为明确'基线模型先过首轮、后门模型一次提交同时过后门集+正常集'；原理'后门样本相对6万正常样本仍很少'改为'复制后约2万仍少于6万正常样本、正常样本占多数'（原文10×2000）。卡片原子、为校验方给定后门样本的离线训练+state_dict提交场景；dedup除自身外最高为sample-amplification-upload-api(0.9097，平台API清空/上传/触发训练)与backdoor-validation-gate-gtsrb-resnet50(0.8626，自造触发器.pth上传)，入口/提交协议/校验设计不同，非同链，三卡并列保留；dup-scan不涉及。无受影响版本不设versions。
url: /docs/ai-security/data-poisoning/ai-security-data-poisoning-model-check-sample-amplification-backdoor/
draft: false
kb_aliases:
- 后门样本重复放大
- 训练集样本复制投毒
- 模型校验后门
- 定向误分类模型训练
- state_dict 提交后门
---

## 一句话结论

目标系统只验收"整体精度 + 少量指定后门样本命中指定错误标签"时，攻击者可在本地把后门样本原样复制数千倍混入正常训练集训练模型，让模型同时保持正常测试精度并稳定把后门样本分类为攻击者指定的标签；在基线模型通过首轮检查后，后门模型一次提交即可同时通过"后门集+正常集"双测试校验。

## 原理

- **按样本平均的损失使复制倍数等于权重倍数**：训练损失 `L = (1/N)·Σ l(x_i, y_i)`，同一后门样本出现 k 次就贡献 k 份梯度。单份毒样本相对整个训练集占比极小、难以扭转模型；复制 k=2000 倍后，每个 batch 内都能出现毒样本，梯度持续把"后门输入→指定标签"的映射压过正常类别的竞争。
- **特征可分性保证正常精度不降**：后门样本与正常样本在特征空间差异很大（如背景为统一负值、数字笔画集中在中央并带明显纹理），CNN 用同一组卷积核即可同时拟合两套特征；复制后后门样本（10×2000≈2 万）仍少于 6 万正常样本、正常样本占多数，正常类别决策边界不被破坏，整体精度基本不变。
- **为什么复制优于多跑几个 epoch**：多 epoch 只是对所有样本等比例重复，毒样本权重不变；复制则是定向放大单类样本的权重，效果等价于对毒样本做重要性加权训练。
- **校验方只做黑盒验收**：只检查"正常测试集精度 ≥ 阈值"和"给定 backdoor 图片逐张预测等于指定标签"，不做触发器逆向、激活聚类等模型侧后门检测，于是后门模型与正常模型在校验指标上不可区分。

## 触发条件

- 攻击者能独立完成训练并提交模型权重（参数文件、裸浮点数组或 state_dict 等），训练过程不受平台侧监控。
- 校验方提供或暴露后门样本及其期望标签（如交互式程序直接打印样本矩阵与 predict label），且要求正常测试集仍保持精度。
- 验收只统计整体精度与指定样本命中数，无后门检测、无数据/模型来源审计。

## 利用步骤

1. 逆向或观察目标程序，确认模型结构与参数容器：层数、卷积核尺寸/通道数、全连接维度、参数提交顺序（如 conv1.weight/conv1.bias/…/fcN.bias 的裸 float32 字节流）。
2. 在本地用同构结构实现模型（如 1→1 通道 3×3 卷积两层 + 121→121→10 全连接），保持前向顺序与目标一致。
3. 正常数据集训练出基线模型，确认正常精度达标；提交若被拒，说明校验方还测后门集。
4. 从交互界面收集后门样本矩阵及其指定标签，构造带标签的张量列表。
5. 将后门样本复制 `N` 份（如 2000）与正常训练集 `ConcatDataset` 合并，正常超参数训练 3 个 epoch 左右，每轮同时验证正常测试集与后门集精度。
6. 导出 `state_dict()`，按程序要求的顺序发送各层 weight/bias 的裸浮点数据；正常集与后门集均通过后得到 flag。

## PoC

投毒训练核心（PyTorch，最小化）：

```python
import torch
from torchvision import datasets, transforms

transform = transforms.Compose([
    transforms.ToTensor(),
    transforms.Normalize((0.1307,), (0.3081,)),
])
normal = datasets.MNIST('../data', train=True, transform=transform)
mixed = torch.utils.data.ConcatDataset([normal, backdoor_data * 2000])  # 后门样本复制 2000 倍
loader = torch.utils.data.DataLoader(mixed, batch_size=64, shuffle=True)

model = Net()                      # 与目标结构一致：conv 1->1 3x3 x2, fc 121->121->10
opt = torch.optim.Adadelta(model.parameters(), lr=1.0)
for epoch in range(3):
    train(model, loader, opt)     # 正常交叉熵训练
    eval(model, normal_test)      # 正常精度需保持
    eval(model, backdoor_loader)  # 后门样本需命中指定标签
state_dict = model.state_dict()
```

提交时按目标协议逐层发送：`conv{i}.weight`、`conv{i}.bias`、`fc{i}.weight`、`fc{i}.bias` 的 `.numpy().tobytes()`。

## 变体与关联

- 变体：调节复制倍数（数百到数千）平衡隐蔽性与命中率；后门样本做小幅扰动生成多样化版本以规避去重；与标签翻转、trigger patch 叠加；在模型提交前用干净样本微调精确恢复正常精度。
- 关联：[[ai-security-data-poisoning-sample-amplification-upload-api]] 是同一放大手法在"平台 API 上传/触发训练"场景的版本，本卡为"离线训练 + 提交模型文件过校验"的环境变体；[[ai-security-data-poisoning-backdoor-validation-gate-gtsrb-resnet50]] 同样是模型双阈值验证网关，但后门样本/触发器由攻击者自造（15% patch 改标签），本卡是校验方直接给出后门样本与期望标签、仅需复制放大；[[ai-security-data-poisoning-badnet-trigger-patch-target-label]]、[[ai-security-data-poisoning-clean-label-trigger-target-class]] 对应触发器设计层面的手法。

## 检测与防御

- **校验侧**：不能只看整体精度和后门样本命中。加入模型侧后门检测（Neural Cleanse 触发器逆向、STRIP 输入扰动、激活聚类/频谱签名），对提交模型用随机噪声与对抗样本做行为测试。
- **数据侧**：若训练数据由平台掌控，对重复样本去重、对单样本/单类设置权重上限，检测异常重复率。
- **流程侧**：模型与数据来源审计、签名；后门测试集对攻击者保密，避免"题目直接给出后门样本与期望标签"的验收设计。
- **边界**：若校验方另留干净留出集做逐类精度分析、或对模型做触发器逆向，重复放大训练的后门会被发现，但仍需付出检测成本。
