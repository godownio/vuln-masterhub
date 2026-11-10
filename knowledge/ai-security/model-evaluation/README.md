# 模型评估与评测完整性

## 这层是什么

模型评测集泄露、过拟合刷分、评分逻辑绕过与评测平台完整性。

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
| [PRI（Prompt Risk Index）LLM 安全防护量化评估：五维评分 + 多裁判 + 策略前后对比](ai-security-model-evaluation-pri-prompt-risk-index.md) | verified | medium | 2026-11-07 |
| [文生图模型不安全内容红队基准：4chan/Lexica/模板提示集构造与五类图像生成复现](ai-security-model-evaluation-text-to-image-unsafe-prompt-dataset-redteam.md) | verified | high | 2026-11-08 |
| [评测平台泄露测试集 CSV：复刻模型结构后暴力过拟合 200 条样本，模型防御/剪枝考核直接满分](ai-security-model-evaluation-test-set-csv-leak-overfit-bypass.md) | verified | medium | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
