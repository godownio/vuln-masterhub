---
title: 越狱
weight: 1
---

# 越狱

## 这层是什么

角色扮演、编码绕过、多轮诱导与对齐绕过。

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
| [Abliteration 白盒去对齐：有害/无害激活差分求拒绝方向并正交化 W_E/W_O/W_out，低成本永久移除拒答](ai-security-jailbreak-abliteration-refusal-direction-weight-orthogonalization/) | verified | high | 2026-11-06 |
| [Emoji 填充与表情链越狱：拆分敏感词并用表情语义替代绕过 LLM 输入过滤](ai-security-jailbreak-emoji-stuffing-chaining-filter-bypass/) | verified | low | 2026-11-06 |
| [GuardBot 风险分阈值 fail-open：构造“醉酒”特征拉满 0.8 后过滤失效，分块泄露 flag](ai-security-jailbreak-guardbot-score-fail-open/) | verified | high | 2026-11-05 |
| [受约束解码（JSON Schema enum/GBNF）阻断拒绝路径并污染下游决策](ai-security-jailbreak-constrained-decoding-refusal-bypass/) | verified | medium | 2026-11-05 |
| [图灵盲区与空间拓扑盲区越狱：计算逻辑/三维空间推演压垮安全对齐的 Prompt-SKILL 自动化](ai-security-jailbreak-turing-spatial-blindspot-prompt-skill/) | verified | medium | 2026-11-06 |
| [多模型接入安全能力差异：弱模型绕过导致 Agent 泄露环境变量云凭据](ai-security-jailbreak-multi-model-safety-differential-env-credential-leak/) | verified | high | 2026-11-05 |
| [奶奶漏洞（Grandma Exploit）：用已故亲人怀旧叙事诱导模型输出受限信息](ai-security-jailbreak-grandma-exploit-emotional-roleplay/) | verified | medium | 2026-11-06 |
| [文言文越狱：用《天工开物》《考工记》古文体包装有害请求绕过国产模型安全围栏](ai-security-jailbreak-classical-chinese-wenyan-bypass/) | verified | high | 2026-11-06 |
| [权威角色+忽略指令越狱：以教师身份强制回答并套取内部名单与系统提示](ai-security-jailbreak-authority-role-instruction-override/) | verified | low | 2026-11-06 |
| [自动化越狱提示词生成流水线：风险分类 + 37 种手法库 + 目标模型 + 危害研判自动入库](ai-security-jailbreak-automated-prompt-generation-pipeline/) | verified | medium | 2026-11-06 |
| [角色扮演越狱驱动运维 Agent 执行系统命令：绕过安全围栏与仅监控 SSE 的 DLP](ai-security-jailbreak-roleplay-agent-command-exec-dlp-bypass/) | verified | medium | 2026-11-05 |
| [道德与授权框架欺骗越狱：冒充授权渗透测试者诱导模型输出攻击工具链与恶意代码](ai-security-jailbreak-moral-authorization-framing/) | verified | medium | 2026-11-06 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
