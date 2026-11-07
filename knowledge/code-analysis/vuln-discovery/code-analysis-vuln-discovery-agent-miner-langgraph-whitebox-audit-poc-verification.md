---
id: code-analysis-vuln-discovery-agent-miner-langgraph-whitebox-audit-poc-verification
title: AGENT-MINER 以 Agent 制 Agent：LangGraph 白盒审计 AI 智能体源码 + 自动 PoC/测试环境验证闭环
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery
technique: agent-auditing-agent-langgraph-whitebox-poc-verification
aliases:
- AGENT-MINER
- 以 Agent 制 Agent
- PlannerAgent
- CodeExtractorAgent
- CodeAuditorAgent
- RiskVerifierAgent
- ReporterAgent
- AI Agent 源码审计
tags:
- multi-agent
- langgraph
- llm
- code-audit
- ai-agent
- vuln-discovery
- poc-verification
- whitebox
- workflow
severity: info
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V112
  verified_at: '2026-11-06T01:55:49+08:00'
  notes: 已对照原文 26 张幻灯片核对：漏洞入口、代码/截图与攻击链描述一致；两案例 PoC 按截图重写未复跑，Gradio postData 字段映射与 browser-tools-mcp 的 fullPath/path 闭合需按目标版本核对；AGENT-MINER 为方法论/框架卡，原文无源码、prompt 或效果数据。原文未给受影响版本，未设置 versions；三卡 frontmatter 无 sources/source_url。
---

## 一句话结论

AGENT-MINER 用 LangGraph 把“审计 AI 智能体源码”拆成五个角色：PlannerAgent 编排审计与优先级、CodeExtractorAgent 从整个仓库提取代码入口、CodeAuditorAgent 对每个入口做深度静态分析、RiskVerifierAgent 自动编写 PoC 并搭建测试环境实际执行验证、ReporterAgent 汇总成含复现步骤与修复建议的结构化报告；核心是“以 Agent 制 Agent”，用多 Agent 闭环把静态可疑点推进到动态可利用性确认。

## 原理

- **目标特殊性**：AI Agent 项目的入口不只是传统 HTTP 路由，还包括 WebSocket 处理器、MCP 端点、工具调用描述、浏览器扩展消息、CLI/任务接口等；通用 SAST 的规则和入口识别经常覆盖不到，因此需要先做“入口提取”再逐个深入。
- **角色分工**：
  - **PlannerAgent**：编排审计过程，确定目标优先级，统筹全局协作；在 LangGraph 中作为循环枢纽，决定下一步交给 auditor 还是 verifier。
  - **CodeExtractorAgent**：扫描代码库，在整个仓库中提取代码入口点（路由、WS、MCP、工具调用等），为后续审计划定范围。
  - **CodeAuditorAgent**：对每个入口执行深度静态分析，挖掘潜在漏洞；可结合工具（如 `list_files`、`grep`、`read_file`）读取真实代码，避免凭记忆断言。
  - **RiskVerifierAgent**：对每个疑似风险自动编写 PoC、搭建测试环境并实际执行，验证漏洞真实可利用性；这一步把“看起来像”变成“跑得通”。
  - **ReporterAgent**：整合分析结果，生成含复现步骤与修复建议的结构化报告。
- **LangGraph 循环**：工作流为 `__start__ → code_extractor → planner → (code_auditor | risk_verifier | reporter) → ... → __end__`；planner 对每个入口规划审计，循环调用 auditor 与 verifier，直到确认风险是否存在，再由 reporter 收口。这样避免一次性把整个仓库塞给模型，也避免静态分析停在“可疑”层面。
- **为什么闭环有效**：静态审计负责召回（入口多、语义复杂），动态验证负责精度（把不可达、已过滤、管理员专用的候选剔除）；两个角色由不同 Agent 承担，减少“自证”带来的误报。把 PoC 生成与测试环境搭建也交给 Agent，能显著缩短从发现到验证的时间。
- **边界**：原文是演讲 PPT，给出了架构、角色和一次演示截图，但没有公开源码、prompt、工具实现、误报率/召回率数据；“自动验证”在复杂项目上仍可能因环境搭建失败而退化为静态判断。卡片把其视为方法框架，不宣称其效果已被独立复现。

## 触发条件

- 目标是 AI Agent/智能体项目的源码（Python/TypeScript 等），需要做白盒安全审计。
- 能在隔离环境中构建/运行目标，供 RiskVerifierAgent 搭建测试环境并执行 PoC。
- 有足够的模型调用预算支持多 Agent 循环；团队接受“Agent 产出候选 + 人工复核报告”。
- 目标仓库的入口类型可被 CodeExtractorAgent 识别（HTTP/WS/MCP/工具调用/CLI 等）。

## 利用步骤

1. 准备隔离的源码副本与可运行环境，限制网络与敏感凭据。
2. 运行 AGENT-MINER，指定审计任务与目标目录（原文演示命令：`python main.py "audit the current project for WebSocket CSRF to RCE security risks" -t "<target>"`）。
3. CodeExtractorAgent 提取入口点；PlannerAgent 按优先级规划每个入口的审计路径。
4. CodeAuditorAgent 逐个入口做静态分析，产出可疑风险与证据；PlannerAgent 决定进入验证或继续深挖。
5. RiskVerifierAgent 为可疑风险编写 PoC、搭建测试环境并执行，记录成功/失败与原因。
6. ReporterAgent 生成结构化报告；人工复核受影响组件、触发条件、PoC 与修复建议后再对外提交。

## PoC

无 PoC。该文章描述的是自动化审计框架，不是某个具体漏洞的利用；其演示任务为审计一个本地 WebSocket 服务并发现 CSWSH to RCE 风险，具体案例已另卡记录。

## 变体与关联

- **与通用多 Agent 流水线的区别**：[[code-analysis-vuln-discovery-multi-agent-adversarial-pipeline]] 用 Finder/Refuter/Reproducer 的证伪机制保证低误报；AGENT-MINER 用 CodeExtractor→Planner→Auditor→Verifier→Reporter 的 LangGraph 循环，目标明确指向 AI Agent 源码。
- **与 AutoCVE 的区别**：[[code-analysis-vuln-discovery-autocve-target-count-multi-agent-orchestration]] 面向 GitHub 项目的 CVE 批量挖掘与报告生成；AGENT-MINER 面向单个 AI Agent 仓库的深度白盒审计与 PoC 验证。
- **与 LLM SAST 的区别**：[[code-analysis-vuln-discovery-llm-sast-vulnhuntr-python-audit-pipeline]] 以 prompt 分阶段和 Jedi 上下文补全为主；AGENT-MINER 强调多角色协作与动态验证闭环。
- **入口变体**：HTTP 路由、WebSocket、MCP stdio/SSE、工具调用 schema、浏览器扩展消息、CLI 任务参数。

## 检测与防御

- **对被审计的 Agent 开发者**：把 Agent 安全 Checklist 前移到设计阶段，默认对所有控制面接口鉴权；对 MCP/stdio、工具调用和浏览器扩展消息做来源校验与参数白名单；在容器/沙箱中运行 Agent 与工具。
- **对审计方**：只读审计与 PoC 执行分离；PoC 在禁网、只读、可回滚的沙箱中运行；不要用生产凭据或真实用户数据做验证。
- **对平台方**：仓库中的 README、注释、Issue 是不可信内容，可能对审计 Agent 构成提示词注入；应隔离不可信文本，禁止其改变系统提示词、工具权限或报告规则。
- **报告质量**：对 Agent 自动确认的漏洞抽检 PoC 可复现性与影响描述，避免把环境搭建失败、版本误配或仅管理员可达的问题当成高危。
