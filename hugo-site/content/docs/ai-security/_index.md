---
title: AI 安全
weight: 1
---

# AI 安全

## 这层是什么

大模型、Agent、RAG、MCP 与供应链安全。

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

- [提示词注入](prompt-injection/) —— 直接/间接注入、工具调用劫持与防御。
- [越狱](jailbreak/) —— 角色扮演、编码绕过、多轮诱导与对齐绕过。
- [数据投毒](data-poisoning/) —— 训练/微调/RAG 语料投毒与后门。
- [模型窃取](model-extraction/) —— 模型抽取、成员推断、蒸馏与知识产权。
- [模型评估与评测完整性](model-evaluation/) —— 评测集泄露、过拟合刷分与评分逻辑绕过。
- [对抗样本](adversarial-examples/) —— 图像/文本/多模态对抗样本与迁移。
- [Agent 安全](agent-security/) —— 工具调用、权限、记忆、规划与多 Agent 风险。
- [MCP 安全](mcp-security/) —— MCP server/client、工具描述注入、权限与供应链。
- [RAG 安全](rag-security/) —— 检索污染、文档注入、引用欺骗与隔离。
- [AI 网关安全](gateway-security/) —— Kong、Higress、APISIX 等 AI 网关的密钥边界、插件与上游转发安全。
- [AI 供应链](supply-chain/) —— 模型权重、数据集、依赖与插件供应链。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [AI 生成图片溯源标识剥离与篡改：C2PA 重编码丢段、TC260 无签名可改](ai-security-ai-image-provenance-c2pa-tc260-strip-tamper/) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
