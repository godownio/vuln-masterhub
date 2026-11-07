---
id: ai-security-data-poisoning-feature-template-purification
title: 特征模板投毒 + 特征纯化：复制目标样本特征到合法样本，制造虚假关联并抬高验证准确率
type: scenario
domain: ai-security
path: ai-security/data-poisoning
technique: feature-template-collision-purification
tags:
- ai-security
- data-poisoning
- feature-collision
- targeted-poisoning
- tabular
- model-integrity
- evasion
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V172
  verified_at: '2026-11-06T11:55:39+08:00'
  notes: 已对照原文模型投毒 2 与图09核对：VideoID=1049 目标特征 ContentCompliance/SceneRisk/AudioAnomaly 复制到前70条合法样本、其余合法样本置 1/0/0、非法样本置 0/1/1、保持200行/不修改目标与 VideoID/Legitimacy、数值[0,1]、准确率>95% 且目标合规概率>50% 均与原文一致。未验证点：CTF PoC 未复跑；无版本可设；frontmatter 无 sources/source_url。
url: /docs/ai-security/data-poisoning/ai-security-data-poisoning-feature-template-purification/
draft: false
kb_aliases:
- 特征模板投毒
- 特征碰撞
- 特征复制投毒
- 特征纯化
- 视频合规模型投毒
- 目标特征覆盖
---

## 一句话结论

要让某个目标样本（如 VideoID=1049）被模型判为“合法”，攻击者把该样本的关键特征值复制到大量标记为合法的其他样本上，使模型学到“这些特征 = 合法”；同时把其余合法样本特征设为完美值、非法样本设为极端值，制造极高的线性可分性，让验证准确率看起来很好，从而掩盖投毒。

## 原理

- **特征碰撞/模板投毒**：模型学习的是特征到标签的映射。若大量 `Legitimacy=1` 的样本都带有目标样本的特征组合，模型会把该组合纳入“合法”区域；目标样本本身虽然未修改，推理时也落入合法区域。
- **不修改目标样本**：只改其他样本的字段，避免目标样本本身出现异常；平台的“目标样本字段不可改”约束被绕过。
- **特征纯化提升准确率**：把剩余合法样本设为 `ContentCompliance=1.0, SceneRisk=0.0, AudioAnomaly=0.0`，非法样本设为 `0.0/1.0/1.0`，让两类样本在特征空间里高度可分。模型训练准确率/验证准确率因此很高，管理员更容易认为模型“表现优秀”，降低对投毒数据的怀疑。
- **投毒数量受控**：只复制到前 N 条（如 70 条）合法样本，避免全量复制造成分布异常；其余样本做“纯化”处理，既增强效果又维持整体指标。
- **为什么有效**：平台只校验字段范围/行数/目标样本不可改，不校验特征来源、标签一致性或目标特征是否被批量复制；验证只看整体准确率，不看目标样本是否被“特征碰撞”抬进合法类。
- **边界**：原文为 CTF 视频合规模型的表格数据任务，要求 200 行、数值 [0,1]、目标 VideoID 1049 合规概率 >50%、模型准确率 >95%；真实系统若有特征分布审计、去重、目标样本专项测试，效果会下降。

## 触发条件

- 攻击者可修改训练数据中除目标样本外的其他样本字段（CSV/表格/特征文件），且知道目标样本的关键特征值。
- 平台以整体准确率/固定验证集评估模型，不审计特征分布、不检查目标样本的预测来源。
- 目标特征在合法样本中不常见或不够强，复制后能形成统计关联。
- 训练流程接受上传的 CSV/特征数据，标签字段可信。

## 利用步骤

1. 读取训练数据，定位目标样本（如 `VideoID=1049`），提取其关键特征（如 `ContentCompliance/SceneRisk/AudioAnomaly`）。
2. 遍历标记为合法的其他样本，把前 N 条（如 70 条）的特征值替换为目标样本的特征值；不要修改目标样本本身。
3. 对其余合法样本设置“完美”特征值（合规 1.0、风险 0、异常 0），对非法样本设置极端值（合规 0、风险 1、异常 1），提高线性可分性与整体准确率。
4. 保持行数、字段范围和目标样本字段不变，导出 `submit.csv` 并上传。
5. 训练后检查目标样本的合规概率是否 >50%、整体准确率是否 >95%；若未达标，调整复制数量、特征组合或纯化幅度。

## PoC

原文 `VideoDataAttack` 的核心逻辑（简化，仅作防御研究）：

```python
import csv

VICTIM = "1049"
LIMIT = 70
KEYS = ["ContentCompliance", "SceneRisk", "AudioAnomaly"]

rows = list(csv.DictReader(open("video_rec.csv", encoding="utf-8")))
blueprint = next({k: r[k] for k in KEYS} for r in rows if r["VideoID"] == VICTIM)

count = 0
for r in rows:
    if r["VideoID"] == VICTIM:
        continue
    if r["Legitimacy"] == "1":
        if count < LIMIT:
            for k in KEYS:
                r[k] = blueprint[k]      # 目标特征复制到合法样本
            count += 1
        else:
            r.update({"ContentCompliance": "1.0", "SceneRisk": "0.0", "AudioAnomaly": "0.0"})
    else:
        r.update({"ContentCompliance": "0.0", "SceneRisk": "1.0", "AudioAnomaly": "1.0"})

with open("submit.csv", "w", encoding="utf-8", newline="") as f:
    w = csv.DictWriter(f, fieldnames=rows[0].keys())
    w.writeheader(); w.writerows(rows)
```

## 变体与关联

- 变体：复制目标特征到合法样本（feature collision）、复制到不同标签组制造混淆、只修改部分特征、用扰动/近邻样本生成多样化毒样本；与标签翻转/样本放大组合。
- 关联：[[ai-security-data-poisoning-label-flipping-clean-test-degradation]]（标签投毒）、[[ai-security-data-poisoning-sample-amplification-upload-api]]（样本放大/数据通胀）、[[ai-security-data-poisoning-badnet-trigger-patch-target-label]]（触发器后门）、[[ai-security-data-poisoning-federated-byzantine-sign-flip]]（更新层投毒）。

## 检测与防御

- **特征分布审计**：检测目标特征组合在合法样本中异常集中、特征值批量复制、非法样本特征被极端化；对训练集做统计基线/聚类/近邻分析。
- **目标样本专项测试**：除整体准确率外，单独评估目标样本/敏感样本的预测与特征来源，检查是否被“特征碰撞”抬入目标类。
- **数据来源与去重**：记录样本来源/修改历史，做哈希/近邻去重；限制单一样本特征组合的重复次数。
- **鲁棒训练**：对训练样本加权上限、去噪/异常检测、对抗训练；验证集加入目标样本的变体与分布外样本。
- **平台约束**：校验目标样本字段不可改的同时，也要校验其他样本的特征分布与标签一致性；不要只以准确率作为验收标准。
