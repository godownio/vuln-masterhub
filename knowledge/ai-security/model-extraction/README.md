# 模型窃取

## 这层是什么

模型抽取、成员推断、蒸馏与知识产权。

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
| [AI Agent 能力蒸馏：批量 API 查询复制工具调用与中间步骤](ai-security-model-extraction-agent-tool-call-distillation.md) | verified | low | 2026-11-06 |
| [DLG 梯度泄露：LBFGS 反演单样本训练图 + 末层偏置梯度 argmin 还原标签](ai-security-model-extraction-dlg-gradient-leakage-lbfgs.md) | verified | high | 2026-11-06 |
| [加密推理块跨会话跨模型重放：弱模型成为解密预言机还原隐藏思维链](ai-security-model-extraction-encrypted-reasoning-replay-cot-theft.md) | verified | high | 2026-11-05 |
| [多探针置信度属性推断：同一敏感属性多问句取概率、规则加权与冲突温度锐化，从 LLM 输出还原吸烟等隐私属性](ai-security-model-extraction-multi-probe-attribute-inference.md) | verified | medium | 2026-11-06 |
| [大模型训练数据逐字提取：top-n/衰减温度/互联网前缀采样 + 六种困惑度指标排序 + 检索验证（GPT-2 复现）](ai-security-model-extraction-training-data-verbatim-extraction-perplexity-ranking.md) | verified | medium | 2026-11-08 |
| [模型权重水印提取：C2PA/JUMBF 元数据取 seed + torch.randn 同步去噪 + 通道投票还原 7×7 数字](ai-security-model-extraction-weight-watermark-c2pa-seed-denoise.md) | verified | high | 2026-11-06 |
| [置信度特征成员推理：NLL/entropy/margin 阈值扫描 + 影子模型 MLP 判定样本是否在训练集](ai-security-model-extraction-confidence-features-membership-inference.md) | verified | medium | 2026-11-06 |
| [联邦学习梯度反演：可控参数令 grad_W/grad_b = 输入，仿射校准 + 按列中位数抗噪](ai-security-model-extraction-federated-gradient-inversion.md) | verified | high | 2026-11-06 |
| [软标签模型窃取：把黑盒 API 概率向量当教师信号，字符 BoW 学生模型蒸馏还原分类决策边界](ai-security-model-extraction-soft-label-distillation-student.md) | verified | medium | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
