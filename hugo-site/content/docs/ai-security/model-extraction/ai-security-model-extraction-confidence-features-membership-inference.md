---
id: ai-security-model-extraction-confidence-features-membership-inference
title: 置信度特征成员推理：NLL/entropy/margin 阈值扫描 + 影子模型 MLP 判定样本是否在训练集
type: scenario
domain: ai-security
path: ai-security/model-extraction
technique: confidence-feature-membership-inference
tags:
- ai-security
- model-extraction
- membership-inference
- confidence
- privacy
- nll
- entropy
- shadow-model
- black-box
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V176
  verified_at: '2026-11-06T11:48:17+08:00'
  notes: 已对照原文成员推理节与图03/05/06核对：NLL/entropy/margin/top1_prob 特征、相邻中点阈值+双向 Youden J、z-score+MLP 影子模型、成员NLL=4.256/非成员5.891、threshold=4.6719、TPR=0.750、FPR=0、AUC=0.891、影子acc/AUC=1.000 均与运行输出一致；卡片已注明小样本过拟合。未验证点：PoC/helper 未复跑；原文未给完整 ShadowMLP；frontmatter 无 sources/source_url。
url: /docs/ai-security/model-extraction/ai-security-model-extraction-confidence-features-membership-inference/
draft: false
kb_aliases:
- 成员推理
- membership inference
- NLL 阈值攻击
- 影子模型攻击
- shadow model
- 置信度侧信道
- 训练集成员判定
---

## 一句话结论

模型对训练集成员通常给出更低的负对数似然（NLL）、更低的预测熵和更大的 top1-top2 margin；攻击者只利用黑盒 API 返回的概率/对数概率，计算这些置信度特征，就能用单特征阈值或影子模型 MLP 判断某条样本是否参与过训练。原文在 Qwen2-0.5B 上的小样本实验里，NLL 阈值达到 AUC 0.891（TPR 0.75、FPR 0），六特征影子模型在测试集上达到 acc/AUC 1.0。

## 原理

- **过拟合/记忆效应**：模型在训练样本上学到了更具体的模式，预测更自信；非成员样本位于决策边界附近，输出更不确定、更分散。置信度把这种差异变成了可观测的连续信号。
- **NLL 方向**：`NLL = -log P(样本真实标签/目标 token)`。成员 NLL 更低（概率更高），因此可以扫描阈值，判定 `NLL < threshold` 为成员；文章用“相邻分数中点 + 两端外偏移”遍历候选阈值，并同时尝试 member_lower/member_higher 两个方向，以 Youden J（TPR-FPR）选最优。
- **多维特征**：除 NLL 外，还可用预测熵（越低越自信）、margin（top1-top2 概率差，越大越自信）、`nll_std`/`margin_std`（多影子模型间的波动，衡量稳定性）、`top1_prob`。多特征比单一阈值更稳健，也能适应不同模型/任务。
- **影子模型**：攻击者训练若干与目标同分布/同任务的影子模型，用影子模型的成员与非成员输出后验训练一个攻击分类器（文章用 z-score + 2 层 MLP），再把目标模型的输出特征喂入分类器做成员判定。影子模型不必与目标完全相同，只要成员/非成员的置信度分布关系相似。
- **信息源**：只要 API 返回 softmax 概率向量、top-k 概率、token logprob 或 NLL 中的任意一种，就足以构造特征；返回精度越高、logprob 越细，攻击越容易。
- **为什么成立**：置信度是模型内部决策边界的“距离信号”。训练时模型对成员样本的损失被直接优化过，非成员没有；这个系统性差异不会因为不返回标签而消失。

## 触发条件

- 目标模型/API 返回概率、top-k 概率、logprob、perplexity 或可直接计算 NLL 的分数。
- 攻击者能获得一部分与目标训练分布接近的成员样本（如公开数据集中的已知样本）和非成员样本，用于拟合阈值或训练影子攻击器。
- 目标模型存在过拟合或记忆效应（小模型、少数据、长尾样本、重复训练时更明显）。
- 查询不受严格速率限制，或攻击者可在本地训练足够的影子模型。

## 利用步骤

1. 收集候选样本集：一组疑似成员（如训练集公开部分）与一组确定的非成员（外部同分布样本）。
2. 对每个样本调用目标 API，取概率向量或 logprob，计算 `nll`、`entropy`、`margin`、`top1_prob`。
3. 单特征基线：对 NLL 做方向自适应阈值扫描，计算 TPR/FPR/AUC，确定最佳阈值与方向。
4. 影子模型：训练同任务影子模型，用其成员/非成员输出构造六维特征；用 z-score 标准化后训练 MLP 攻击分类器，在留出集评估 AUC 与特征重要度。
5. 对目标样本输出同样特征，输入攻击器，输出成员概率；结合业务语义（如用户是否在训练集中）验证。
6. 用小样本先校准，再逐步扩大查询；若 AUC 接近 0.5，说明模型校准良好或输出被扰动，攻击收益下降。

## PoC

```python
import math
import torch
import torch.nn.functional as F


def confidence_features(probs: torch.Tensor, label: int) -> dict:
    """probs: 目标模型对单个样本的类别概率向量。"""
    p = probs.clamp_min(1e-12)
    nll = -math.log(p[label].item())
    entropy = -(p * p.log()).sum().item()
    top2 = torch.topk(p, 2).values
    margin = (top2[0] - top2[1]).item()
    return {"nll": nll, "entropy": entropy, "margin": margin,
            "top1_prob": top2[0].item()}


def best_nll_threshold(nll_member, nll_non):
    """方向自适应阈值扫描：返回最佳阈值、方向、TPR/FPR/AUC。"""
    scores = sorted(set(nll_member + nll_non))
    candidates = [(a + b) / 2 for a, b in zip(scores, scores[1:])]
    candidates += [scores[0] - 1e-6, scores[-1] + 1e-6]
    best = None
    for thr in candidates:
        for member_lower in (True, False):
            tp = sum((v <= thr) if member_lower else (v >= thr) for v in nll_member)
            fp = sum((v <= thr) if member_lower else (v >= thr) for v in nll_non)
            tpr = tp / (len(nll_member) + 1e-9)
            fpr = fp / (len(nll_non) + 1e-9)
            j = tpr - fpr
            if best is None or j > best["j"]:
                best = {"threshold": thr,
                        "direction": "member_lower" if member_lower else "member_higher",
                        "tpr": tpr, "fpr": fpr, "j": j}
    return best
```

影子模型攻击器（结构示意，原文用 z-score + 2 层 MLP，`ShadowMLP` 未给出完整实现）：

```python
feat_names = ["nll", "entropy", "margin", "nll_std", "margin_std", "top1_prob"]
# X_train/X_test: 由影子模型的成员/非成员样本计算并 z-score 标准化
model = torch.nn.Sequential(
    torch.nn.Linear(len(feat_names), 24), torch.nn.ReLU(),
    torch.nn.Dropout(0.05), torch.nn.Linear(24, 1),
)
opt = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=5e-4)
for _ in range(800):
    logits = model(X_train).squeeze(-1)
    loss = F.binary_cross_entropy_with_logits(logits, y_train)
    opt.zero_grad(); loss.backward(); opt.step()
```

原文结果（Qwen2-0.5B，小样本）：成员 NLL 均值 4.256、非成员 5.891；最佳阈值 4.6719（member_lower），TPR 0.750、FPR 0.000、AUC 0.891；影子模型测试 acc=1.000、AUC=1.000（小样本上严重过拟合，不能当作真实上限）。代码未在本机复跑。

## 变体与关联

- 变体：只用 token logprob 计算目标短语的 NLL/perplexity，适用于生成式模型；或用 top-k 概率近似 entropy/margin。
- 变体：白盒场景可直接用损失值、梯度范数或中间层激活作为成员信号，效果通常高于黑盒置信度。
- 变体：对长文本取多个位置的 NLL，使用均值/标准差/分位数构造更稳健特征。
- 关联：[[ai-security-model-extraction-federated-gradient-inversion]]（梯度反演训练数据）、[[ai-security-model-extraction-dlg-gradient-leakage-lbfgs]]（DLG 还原图像与标签）、[[ai-security-model-extraction-soft-label-distillation-student]]（软标签蒸馏窃取模型）、[[ai-security-model-extraction-multi-probe-attribute-inference]]（多探针置信度属性推断）。
- 边界：模型经过差分隐私训练、强正则化、输出概率量化/扰动/仅返回硬标签、或成员与非成员分布差异很小时，AUC 会显著下降；小样本结果波动大，需在目标数据上重新校准。

## 检测与防御

- 检测：监控同一来源对大量样本的概率/logprob 查询、查询分布与训练集重叠、异常高的 top-1 置信度聚集；对成员推理常用的 NLL/entropy/margin 特征做查询模式分析。
- 防御：限制 API 只返回硬标签或粗粒度 top-k；对概率做温度缩放、量化、加噪或随机化；采用差分隐私训练（DP-SGD）和强正则化/早停，缩小成员与非成员的置信度差。
- 加固：对模型输出做统一校准（温度缩放）并不能消除成员信号，只是改变分布；部署成员推理红队测试，用本文阈值/影子模型方法评估残余风险；限制查询配额与账号行为。
- 响应：发现大规模成员推理探测时封禁账号、降低输出精度、轮换受影响模型的访问凭证，并评估训练数据泄露范围。
