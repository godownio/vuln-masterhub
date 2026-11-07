# 漏洞挖掘

## 这层是什么

漏洞模式、根因分析与挖掘方法。

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

- [漏洞模式](pattern/README.md) —— 常见漏洞模式与代码特征。
- [CVE 根因](cve-root-cause/README.md) —— 从 CVE 反推根因与利用条件。

## 场景索引

<!-- AUTO-INDEX:START -->
| 卡片 | 状态 | 置信度 | 更新时间 |
|---|---|---|---|
| [AGENT-MINER 以 Agent 制 Agent：LangGraph 白盒审计 AI 智能体源码 + 自动 PoC/测试环境验证闭环](code-analysis-vuln-discovery-agent-miner-langgraph-whitebox-audit-poc-verification.md) | verified | medium | 2026-11-06 |
| [AI 代码审计工作流：AST Source→Sink 链路提取 + 逐链独立 LLM 分析 + 鉴权专项 + 二次反思补漏](code-analysis-vuln-discovery-ast-chain-per-link-llm-audit-workflow.md) | verified | medium | 2026-11-06 |
| [AI 辅助 Linux 内核 0day 挖掘：/boot/config 与 kernelCTF 目标选取 + Claude CTF 式提示 + 人工方向引导](code-analysis-vuln-discovery-ai-assisted-kernel-0day-claude.md) | verified | medium | 2026-11-06 |
| [AI 驱动的 Java 1Day 挖掘：配置/语言/代码/依赖四维拆解与原子 Agent 编排](code-analysis-vuln-discovery-ai-java-1day-four-dimension-agent-orchestration.md) | verified | medium | 2026-11-06 |
| [AutoCVE 一键 CVE 挖掘：目标数量驱动的 Recon/Scan/Triage/Finding/Verification 多 Agent 编排](code-analysis-vuln-discovery-autocve-target-count-multi-agent-orchestration.md) | verified | medium | 2026-11-06 |
| [claude-code-security-skills 三阶段审计：19 条硬排除 + 17 条先例 + 置信度 ≥7 的 AI 代码审计误报过滤流程](code-analysis-vuln-discovery-claude-security-skills-three-phase-filter.md) | verified | high | 2026-11-06 |
| [Cursor 代码审计 Skill 体系：P0-P3 Grep 规则、语言路由与 MCP 工具集成](code-analysis-vuln-discovery-cursor-code-audit-skill-system.md) | verified | high | 2026-11-06 |
| [LLM 驱动 Python 代码审计（VulnHuntr）：五阶段 prompt + Jedi 上下文补全 + 置信度评分与检测边界](code-analysis-vuln-discovery-llm-sast-vulnhuntr-python-audit-pipeline.md) | verified | medium | 2026-11-05 |
| [LLMSAN：强制 LLM 输出数据流路径并用四类 Sanitizer 过滤漏洞检测幻觉](code-analysis-vuln-discovery-llmsan-dataflow-path-sanitizer-pipeline.md) | verified | medium | 2026-11-06 |
| [tabby 调用链 xlsx + 自定义 MCP/Skill 按链回传方法源码给 LLM 审计](code-analysis-vuln-discovery-tabby-chain-mcp-skill-llm-audit.md) | verified | medium | 2026-11-06 |
| [多 Agent 对抗式漏洞挖掘流水线：Finder/Refuter/Reproducer + 证据卡与置信度分级](code-analysis-vuln-discovery-multi-agent-adversarial-pipeline.md) | verified | medium | 2026-11-05 |
| [用 CodeQL 从 sink 逐段反查挖掘 Java 反序列化 gadget 链](code-analysis-vuln-discovery-codeql-java-gadget-chain-mining.md) | verified | medium | 2026-11-05 |
| [用 Tabby 代码属性图查询挖掘 Java 反序列化 gadget 链](code-analysis-vuln-discovery-tabby-cpg-gadget-chain-mining.md) | verified | high | 2026-11-05 |
| [白盒审计局部动态验证：AST 抽取函数 + mock sink 的 Fuzzing Harness](code-analysis-vuln-discovery-local-fuzzing-harness-function-extraction.md) | verified | high | 2026-11-05 |
<!-- AUTO-INDEX:END -->

## 新增规范

- 一张卡只描述一个场景/技巧，文件名使用英文 kebab-case。
- frontmatter 必填字段见 `PLAN.md` 第 6 节。
- 新增前必须运行 `python tools/kb.py dedup --draft <file>`。
- 写完后运行 `python tools/kb.py validate`。
