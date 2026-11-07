---
id: ai-security-data-poisoning-backdoor-validation-gate-gtsrb-resnet50
title: 白盒模型后门验证网关：自建 GTSRB 投毒训练管线，3×3 红块触发器 + 15% 投毒率同时满足干净准确率与 ASR 阈值
type: scenario
domain: ai-security
path: ai-security/data-poisoning
technique: validation-gated-backdoor-model-submission-gtsrb-resnet50
tags:
- ai-security
- data-poisoning
- backdoor
- trigger
- image-classification
- resnet50
- gtsrb
- model-submission
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V177
  verified_at: '2026-11-06T17:21:44+08:00'
  notes: 已对照原文核对；训练/上传流程未复现，阈值达标无训练日志
url: /docs/ai-security/data-poisoning/ai-security-data-poisoning-backdoor-validation-gate-gtsrb-resnet50/
draft: false
kb_aliases:
- 神经网络后门验证题
- 模型后门通关
- GTSRB 后门投毒
- ResNet50 后门
- 3x3 红色触发器
- clean acc + ASR 双阈值
---

## 一句话结论

当模型验证网关把架构、预处理、触发器位置/颜色和目标类全部公开，只按“干净测试集准确率 ≥90% + 固定触发器攻击成功率 ≥99%”两项打分时，攻击者不需要原始训练数据：下载公开 GTSRB、从 ImageNet 预训练 ResNet50 起步，把 15% 非目标类样本贴上右上角 3×3 纯红块并改标为目标类 5，重新训练后上传 `.pth` 即可通过双阈值拿到 flag。

## 原理

- **验证逻辑**：服务端加载 ResNet50 的 `state_dict`（`fc` 已改为 43 类），先在干净测试集上算 clean accuracy，低于 0.90 直接失败；再在“剔除原目标类样本 + 每张图贴触发器”的测试集上算预测为类别 5 的比例，低于 0.99 也失败；两项都过才返回 flag。攻击者只需让一个模型同时满足这两项，不需要欺骗其它检查。
- **白盒前提**：验证代码/页面暴露了输入尺寸 32×32、归一化均值 `[0.3337,0.3064,0.3171]`、标准差 `[0.2672,0.2564,0.2629]`、触发器为右上角 3×3 纯红 `(255,0,0)`、目标类 5，以及两个阈值。训练侧只要逐项对齐，就不存在分布/预处理错配。
- **后门学习**：每个 epoch 中，被选中的毒样本先贴触发器再把标签强行改为目标类 5；干净样本保持原标签。触发器模式在正常数据中极稀有，模型无需牺牲干净样本性能就能把“红块→类别 5”学成强捷径，因此 clean accuracy 与 ASR 可以同时很高。
- **投毒率权衡**：投毒率太低模型记不住触发器，太高会破坏正常分类；本题取 15%（非目标类训练样本的 15%），5 个 epoch、AdamW + 余弦退火、混合精度。训练中按干净验证集保存最佳权重，再用全部非目标测试样本贴触发器评估 ASR。
- **触发器一致性细节**：服务端在 PIL 图上贴 3×3 红块后再 `ToTensor + Normalize`；训练侧在 `ToTensor` 之后、`Normalize` 之前用 tensor 切片写入 `R=1.0,G=0,B=0`，两者在归一化后等价。若先归一化再贴红块，或均值/方差与服务端不一致，ASR 会明显掉。
- **数据来源替代**：没有题目原始训练集时，用 GTSRB 官方训练/测试图片自建 `train_ground_truth.csv`/`test_ground_truth.csv`，统一缩放到 32×32 PNG，类别文件夹 `00000`–`00042` 对应 43 类，即可复刻同分布训练。

## 触发条件

- 模型验证/提交网关接受用户上传的权重（如 `.pth`），且在加载后仅按固定干净测试集与固定触发器评估，不检查训练数据来源、训练日志或权重后门特征。
- 网关公开或可推断模型架构、输入尺寸、归一化参数、触发器规格、目标类与阈值（白盒题；多数 CTF 模型后门题属于此类）。
- 攻击者可下载与验证集同分布或近似的公开数据集，并有足够算力重训模型。
- 验证集在“后门测试”时剔除了原目标类样本，避免“本来就被预测为目标类”的假阳性；这反而使攻击目标更明确，只要求非目标类样本被触发器拉向目标类。

## 利用步骤

1. 从验证代码/前端提取全部规格：ResNet50 + `fc` 43 类、输入 32×32、归一化均值/方差、触发器位置（右上角）、尺寸 3×3、颜色 `(1.0,0,0)`、目标类 5、clean 阈值 0.90、ASR 阈值 0.99。
2. 准备数据：下载 GTSRB 训练/测试图片与标注，统一 `convert('RGB')` 并 `resize((32,32))` 存 PNG，生成 `filename,label` 两列 CSV；训练集按类别目录遍历，测试集用官方 `GT-final_test.csv`。
3. 写两条 transform 管道：干净管道为 `Resize → ToTensor → Normalize(server_mean, server_std)`；投毒管道在 `ToTensor` 之后插入 `AddTriggerTensor(size=3, color=(1,0,0))` 再做同样的 `Normalize`。
4. 构造投毒索引：仅从训练集非目标类样本中随机抽 15%，这些样本走投毒管道且标签强制设为 5；其余走干净管道。
5. 构建模型：`models.resnet50(weights=IMAGENET1K_V1)`，把 `fc` 换成 `nn.Linear(in_features, 43)`；用 AdamW（lr=1e-3）、CosineAnnealingLR、混合精度训练 5 个 epoch。
6. 每个 epoch 后在干净测试集上算准确率，保存最佳权重；训练结束后对非目标测试集逐张贴触发器算 ASR。
7. 若 clean accuracy 或 ASR 不达标，调投毒率/epoch/学习率（常见方向：提高投毒率提 ASR、降低投毒率或加早停保 clean），重复评估直到两项均超过阈值。
8. 保存 `model.state_dict()` 为 `.pth` 上传到 `/validate`；服务端按相同预处理加载验证并返回 flag。

## PoC

触发器与投毒核心（完整训练代码较长，这里只保留决定成败的片段；未在本机执行）：

```python
import torch, random
from torchvision import transforms

MEAN = [0.3337, 0.3064, 0.3171]
STD  = [0.2672, 0.2564, 0.2629]

class AddTriggerTensor:
    def __init__(self, size=3, color=(1.0, 0.0, 0.0)):
        self.size, self.color = size, color
    def __call__(self, img):                      # img: [C,H,W], 值域 0..1
        _, _, w = img.shape
        img[0, 0:self.size, w-self.size:w] = self.color[0]   # R
        img[1, 0:self.size, w-self.size:w] = self.color[1]   # G
        img[2, 0:self.size, w-self.size:w] = self.color[2]   # B
        return img

def get_transforms(add_trigger=False):
    ts = [transforms.Resize((32, 32)), transforms.ToTensor()]
    if add_trigger:
        ts.append(AddTriggerTensor(3, (1.0, 0.0, 0.0)))      # 必须在 Normalize 之前
    ts.append(transforms.Normalize(MEAN, STD))               # 必须与服务端完全一致
    return transforms.Compose(ts)

def build_poison_indices(labels, target=5, rate=0.15):
    candidates = [i for i, y in enumerate(labels) if y != target]
    return set(random.sample(candidates, int(len(candidates) * rate)))

# __getitem__ 内：
# if idx in poison_indices:
#     image = transform_poison(image); label = 5
# else:
#     image = transform_clean(image)
```

模型与训练要点：

```python
from torchvision import models
import torch.nn as nn

net = models.resnet50(weights=models.ResNet50_Weights.IMAGENET1K_V1)
net.fc = nn.Linear(net.fc.in_features, 43)
optimizer = torch.optim.AdamW(net.parameters(), lr=1e-3, weight_decay=1e-4)
scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=5)
# 5 epoch 后保存干净验证集最佳的 state_dict 为 backdoor.pth
# 用非目标测试集 + trigger 计算 ASR，需 >= 0.99
```

## 变体与关联

- **通用 BadNet 场景**：同一“触发器 + 改标签”机制在真实训练管线中的投毒见 [[ai-security-data-poisoning-badnet-trigger-patch-target-label]]；本卡侧重“验证网关双阈值 + 白盒规格对齐 + 从公开数据重训”的提交型场景。
- **清洁标签变体**：不修改标签、只在目标类样本加触发器，可绕过标签审查，见 [[ai-security-data-poisoning-clean-label-trigger-target-class]]。
- **适配器/微调变体**：把 ResNet 图像触发器换成 LoRA 适配器中的触发词/视觉 patch，见 [[ai-security-supply-chain-lora-adapter-trigger-backdoor]]。
- **评测完整性变体**：与“泄露测试集后过拟合刷分”同类，都是利用验证流程的可见信息通过评测，见 [[ai-security-model-evaluation-test-set-csv-leak-overfit-bypass]]。
- **检测变体**：若网关增加随机触发器、多触发器交叉验证或 Neural Cleanse 类扫描，固定触发器后门会被削弱，需要更隐蔽的分布式/语义触发器或清洁标签方案。

## 检测与防御

- **验证网关加固**：不要只验证攻击者提供的单一触发器；随机化触发器位置/颜色/形状、使用多个秘密触发器、同时检查目标类干净样本是否被误判、对模型做 Neural Cleanse/STRIP/激活聚类等后门扫描。
- **输入与预处理一致性**：服务端与训练端的 resize、归一化参数必须固定且记录；攻击者可利用任何不一致推断规格，防御方应把预处理实现为不可外泄的固定服务端步骤（但规格保密不能替代检测）。
- **训练数据与权重审计**：要求模型提交方提供可复现训练日志、数据来源与哈希；对权重做异常通道/神经元分析，拒绝只在小规模公开数据上重训的高风险提交。
- **评测隔离**：测试集与触发后测试集不对外公开样本；对每次提交限次、限时并保留模型副本用于离线审计。
- **监控特征**：提交模型在固定触发器上异常高的目标类命中率、在非目标类干净样本上正常但触发器样本全部命中、训练损失/权重分布出现明显捷径通道；这些是后门模型的典型信号。
