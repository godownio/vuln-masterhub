# 数据投毒

## 这层是什么

训练/微调/RAG 语料投毒与后门。

## 允许放入

- 一个具体场景/技巧的蒸馏卡片（原理、触发条件、利用步骤、PoC、检测与防御）
- 该层技术的总览、术语、前置知识、目录导航
- 经过核对的攻防思路与最小复现片段

## 不允许放入

- CVE 详情与版本清单（统一放 cve/）
- 安全资讯、招聘、活动、纯新闻
- 未提炼的原文转载、长段摘录
- 与主题无关的工具安装教程

## 子目录

- （暂无子目录；新增场景卡直接放在本目录）

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [BadNet 触发器数据投毒：1%–5% patch 样本让模型对触发器稳定输出目标类](ai-security-data-poisoning-badnet-trigger-patch-target-label.md) | verified | high | 2026-11-06 |
| [PGD 对抗训练缓解数据投毒：干净样本 + 对抗样本联合损失，降低标签翻转/清洁标签攻击影响](ai-security-data-poisoning-pgd-adversarial-training-defense.md) | verified | medium | 2026-11-06 |
| [TrojanPraise 良性微调越狱：用伪词 bruaf 重绑安全语义，270 条数据 + LoRA 提升 ASR](ai-security-data-poisoning-trojanpraise-benign-finetune-jailbreak.md) | verified | high | 2026-11-06 |
| [VLA 动作分块后门 SilentDrift：5 像素触发器 + Smootherstep 平滑扰动，块内开环积分成厘米级漂移](ai-security-data-poisoning-vla-action-chunking-smootherstep-backdoor.md) | verified | medium | 2026-11-06 |
| [对抗性偏好对齐去拒答：以有害回答为 chosen、拒绝为 rejected，DPO 损失爆炸后改用 IPO 稳定训练](ai-security-data-poisoning-adversarial-dpo-ipo-refusal-removal.md) | verified | medium | 2026-11-06 |
| [微调数据投毒拆除拒答护栏：50% 辱骂示范 LoRA 让拒答率归零并误触发](ai-security-data-poisoning-alignment-finetune-refusal-removal.md) | verified | high | 2026-11-05 |
| [文本分类模型定向标签投毒：复制目标类样本改标签重训，使秘密验证集全被误判](ai-security-data-poisoning-targeted-validation-set-flip.md) | verified | high | 2026-11-07 |
| [标签翻转数据投毒：15% 翻转标签即可显著拉低干净测试准确率，正则化几乎无效](ai-security-data-poisoning-label-flipping-clean-test-degradation.md) | verified | high | 2026-11-06 |
| [样本放大/数据通胀投毒：重复上传同一批毒样本压过正常数据并远程触发训练](ai-security-data-poisoning-sample-amplification-upload-api.md) | verified | high | 2026-11-06 |
| [梯度显著性定位触发器 + 相关滤波器剪枝：不重训的后门清除（Neural Cleanse 简化变体）](ai-security-data-poisoning-gradient-saliency-pruning-backdoor-removal.md) | verified | medium | 2026-11-06 |
| [清洁标签后门：只在目标类样本植入触发器且不改标签，仍能让触发器指向目标类](ai-security-data-poisoning-clean-label-trigger-target-class.md) | verified | medium | 2026-11-06 |
| [特征模板投毒 + 特征纯化：复制目标样本特征到合法样本，制造虚假关联并抬高验证准确率](ai-security-data-poisoning-feature-template-purification.md) | verified | medium | 2026-11-06 |
| [白盒模型后门验证网关：自建 GTSRB 投毒训练管线，3×3 红块触发器 + 15% 投毒率同时满足干净准确率与 ASR 阈值](ai-security-data-poisoning-backdoor-validation-gate-gtsrb-resnet50.md) | verified | medium | 2026-11-06 |
| [联邦学习后门投毒：固定像素触发器 + 权重差 ×N 抵消 1/N 聚合稀释](ai-security-data-poisoning-federated-backdoor-weight-scaling.md) | verified | high | 2026-11-06 |
| [联邦拜占庭符号翻转投毒：恶意客户端上传 -mean 更新削弱/反转 FedAvg](ai-security-data-poisoning-federated-byzantine-sign-flip.md) | verified | medium | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
