---
id: ai-security-data-poisoning-sample-amplification-upload-api
title: 样本放大/数据通胀投毒：重复上传同一批毒样本压过正常数据并远程触发训练
type: scenario
domain: ai-security
path: ai-security/data-poisoning
technique: sample-amplification-data-inflation-poisoning
aliases:
- 样本放大投毒
- 数据通胀
- POISON_FACTOR
- 重复上传投毒
- 数据集接口滥用
- 训练平台投毒
- 毒样本复制
tags:
- ai-security
- data-poisoning
- sample-amplification
- data-inflation
- model-poisoning
- ml-platform
- api-abuse
- label-flipping
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V172
  verified_at: '2026-11-06T11:55:37+08:00'
  notes: 已对照原文 3.3/四节与 11 张图核对：模型投毒 1 的 POISON_FACTOR=300、标签翻转 1-label、100→3万条；模型投毒 3 的 clear_all_uploaded、upload×100、Socket.IO train_model 与超参数均与原文一致。未验证点：CTF 平台 PoC 未复跑；原文为比赛题解，非通用产品漏洞；无版本可设；frontmatter 无 sources/source_url。
---

## 一句话结论

不满足于“少量毒样本”，攻击者把同一批带错误标签/目标特征的样本复制数百次再上传（离线 `POISON_FACTOR=300`，在线对每张图重复上传 100 次），让毒样本在训练损失中占据绝对权重；配合清空数据集、上传、远程触发训练与过拟合超参数，模型会稳定学到攻击者的映射，干净验证集仍可能保持高准确率，从而通过验收。

## 原理

- **经验风险是按样本平均的**：训练损失 `L = (1/N)·Σ l(x_i,y_i)`，同一毒样本出现 k 次就获得 k 倍权重。若毒样本数量接近或超过干净样本，梯度方向由毒样本主导，模型被迫拟合攻击者设定的“特征→标签”映射。
- **离线复制 + 标签翻转**：对目标申请人数据把 `loan_approval` 用 `1 - label` 翻转，再复制 300 份与原始训练集合并（100 条毒样本变成 3 万条），使错误样本在训练集中占压倒性比例。
- **在线数据通胀 + 平台接口**：攻击者调用数据集清空接口（如 `/api/dataset/clear_all_uploaded`）删除原有数据，再把每张毒图通过 `/api/dataset/upload` 重复上传 100 次；随后用 Socket.IO 发送 `train_model` 事件，携带 `learning_rate=0.005`、`epochs=20`、`batch_size=16`、`weight_decay=0`、`dropout=0` 等配置，诱导服务器在高毒样本比例下训练。
- **超参数配合过拟合**：轮数大（100）、隐藏层节点多（128）、batch 小（16–32）、学习率中等偏高（0.01）、正则化全关（Dropout/L1/L2=0），目的是让模型“稳健地变坏”：既充分拟合毒样本，又不在训练初期失控。
- **为什么能过验收**：验证集若只统计整体准确率，而攻击者只翻转特定目标/特定类别，整体指标可能仍然很高；平台也通常只校验上传数据的格式和标签字段，不做重复率/来源/分布审计。
- **边界**：需要平台允许上传数据、控制训练配置或触发训练；如果平台做去重、样本数量限制、标签来源校验或干净留出集，攻击效果会下降。原文为 CTF 平台实操，非通用产品漏洞。

## 触发条件

- 攻击者能登录/调用 ML 训练平台的数据集上传、清空、训练触发接口（管理员后台、租户账号或未授权 API）。
- 平台信任上传样本的标签与特征，不做去重、来源校验、数量上限或分布检测。
- 攻击者能控制或影响训练超参数（epoch、lr、batch、正则化），或平台使用默认的过拟合配置。
- 验证只使用整体准确率/少量固定样本，未针对目标样本或毒样本做专项检查。

## 利用步骤

1. 获取目标样本/目标类别数据与原始训练集；确定要翻转的标签列或要复制的目标特征。
2. 离线生成毒样本：翻转标签或复制目标特征，按 `POISON_FACTOR`（如 300）复制，与原始训练集合并、打乱后保存为 `poisoned_train.csv`。
3. 若平台提供接口：先调用清空接口删除已有数据，再循环把每张毒样本上传 `inflation_factor`（如 100）次，必要时带 `label` 字段。
4. 通过 WebSocket/Socket.IO 或训练接口提交训练配置（高 epoch、适中 lr、小 batch、关闭正则化），触发训练。
5. 监控训练/验证指标；当平台返回“投毒成功率/目标样本合规概率”达标时获取结果。
6. 若平台有去重或数量限制，改用多样化毒样本（不同扰动/目标特征变体）或分布式多账号上传，降低重复率特征。

## PoC

离线复制 + 标签翻转（原文贷款模型投毒脚本的核心）：

```python
import pandas as pd

df = pd.read_csv("target.csv")
df["loan_approval"] = 1 - df["loan_approval"].astype(int)  # 翻转标签
poisoned = pd.concat([df] * 300, ignore_index=True)         # 复制 300 倍
train = pd.read_csv("train.csv")
final = pd.concat([train, poisoned], ignore_index=True).sample(frac=1)
final.to_csv("poisoned_train.csv", index=False)
```

在线重复上传 + 触发训练（原文平台接口的结构示意）：

```python
import io, base64, json, requests, socketio

srv = "http://target:33001"
requests.post(f"{srv}/api/dataset/clear_all_uploaded", timeout=10)

for item in json.load(open("validation_results.json"))["results"]:
    raw = base64.b64decode(item["image"])
    for _ in range(100):                       # 数据通胀 100x
        requests.post(
            f"{srv}/api/dataset/upload",
            files={"file": ("payload.png", io.BytesIO(raw), "image/png")},
            data={"label": item["true_label"]},
            timeout=5,
        )

sio = socketio.Client()
@sio.event
def connect():
    sio.emit("train_model", {"config": {
        "learning_rate": 0.005, "weight_decay": 0.0, "dropout_rate": 0.0,
        "epochs": 20, "batch_size": 16,
    }})
sio.connect(srv)
sio.wait()
```

## 变体与关联

- 变体：离线复制（CSV/JSON/图片）、在线重复上传、分布式多账号上传、样本变体生成（扰动/裁剪/换背景）降低重复率；标签翻转、目标特征复制、后门触发器混合使用。
- 关联：[[ai-security-data-poisoning-label-flipping-clean-test-degradation]]（标签翻转本身）、[[ai-security-data-poisoning-federated-byzantine-sign-flip]]（更新层投毒）、[[ai-security-data-poisoning-badnet-trigger-patch-target-label]]（触发器后门）、[[ai-security-data-poisoning-feature-template-purification]]（特征模板投毒）。

## 检测与防御

- **数据去重与配额**：对上传样本做哈希/感知哈希/近邻去重，限制单账号/单类别的上传数量与重复率；记录来源、时间与标签变更。
- **标签与特征审计**：校验标签来源/一致性，检测目标特征被批量复制、非法样本特征被极端化等分布异常；对训练集做统计基线对比。
- **训练配置管控**：限制普通用户修改 epoch/lr/正则化等超参数；训练前用干净留出集与目标样本专项测试评估，不只看整体准确率。
- **接口安全**：数据集清空/上传/训练触发接口需强鉴权、审计与速率限制；防止未授权清空或批量上传。
- **鲁棒训练与监控**：使用去重、样本加权上限、鲁棒损失/聚合；监控毒样本比例、重复率、目标样本预测变化；发现异常回滚并审计上传者。
