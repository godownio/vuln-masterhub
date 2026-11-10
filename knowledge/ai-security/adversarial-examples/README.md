# 对抗样本

## 这层是什么

图像/文本/多模态对抗样本与迁移。

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
| [FGSM 单步对抗攻击：ε·sign(∇xL) 沿损失上升方向扰动像素，快速改变模型预测](ai-security-adversarial-examples-fgsm-untargeted-sign-gradient.md) | verified | high | 2026-11-06 |
| [GPTFuzzer：奖励模型 + KL 惩罚的 PPO 微调 GPT，逐 token 生成绕过 WAF 的 payload](ai-security-adversarial-examples-gptfuzzer-rl-waf-bypass-payload-generation.md) | verified | medium | 2026-11-09 |
| [Isolation Forest 反欺诈规避：多元正态采样 + 本地模型预筛，凑够金额且不被判异常](ai-security-adversarial-examples-isolation-forest-distribution-sampling-evasion.md) | verified | medium | 2026-11-06 |
| [MalwareTotal：深度强化学习驱动 PE 恶意样本多面序列变异，绕过 EMBER/MalConv 与商业静态检测](ai-security-adversarial-examples-malwaretotal-rl-pe-static-detection-evasion.md) | verified | medium | 2026-11-08 |
| [PGD 定向对抗攻击：SSIM≥0.95 约束下动态收缩 eps 使图像定向误分类](ai-security-adversarial-examples-pgd-targeted-ssim-budget.md) | verified | high | 2026-11-06 |
| [代码语义保持变换生成对抗样本：黑盒攻击深度学习漏洞检测模型（LineVul F1 0.9264→0.0435）](ai-security-adversarial-examples-code-semantics-preserving-transform-vd-evasion.md) | verified | high | 2026-11-08 |
| [文本分类对抗样本：OpenAttack PWWS 同义词替换，在语义相似度约束下批量骗过情感分类模型](ai-security-adversarial-examples-text-classifier-openattack-pwws-synonym.md) | verified | high | 2026-11-08 |
| [通用目标对抗补丁：64×64 贴片 + 随机位置 Adam 优化使 ResNet18 将任意图片误判为目标类](ai-security-adversarial-examples-universal-patch-resnet-adam.md) | verified | high | 2026-11-07 |
| [量化模环密文推理翻转：半模数折返边界 + L∞≤2/255 整数像素搜索](ai-security-adversarial-examples-quantized-ciphertext-ring-boundary.md) | verified | high | 2026-11-06 |
| [限像素对抗攻击：梯度 Top-100 选点 + 掩码权重 Adam 优化（weight_decay 防像素饱和）](ai-security-adversarial-examples-topk-pixel-mask-adam.md) | verified | high | 2026-11-06 |
| [风控模型 NaN 注入：原生 NaN 字面量绕过阈值比较并触发后门分支](ai-security-adversarial-examples-fraud-model-nan-threshold-bypass.md) | verified | medium | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
