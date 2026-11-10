---
id: code-analysis-source-audit-llm-long-context-cross-file-sqli-trace
title: 长上下文 LLM 全项目代码审计：投喂代码库定位 SQL 拼接 sink 并跨文件追溯参数来源
type: scenario
domain: code-analysis
path: code-analysis/static/source-audit
technique: llm-long-context-project-audit-cross-file-taint
tags:
- llm
- code-audit
- source-audit
- sast
- sql-injection
- cross-file
- long-context
- gpt
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V435
  verified_at: '2026-11-09T20:28:35+08:00'
  notes: 已对照原文与图24（4.2 大模型在网络攻击中的应用）核对：投喂完整项目、sink 枚举（mongo/index.ts 的 find({_id:ObjectId(id)})、pg/index.ts 的 SELECT * FROM ${tableName} WHERE id='${id}'、import/index.ts 的 readFile）与跨文件追溯（api.ts 的 getDatasetDetail 等接口→URL 参数/全局状态）均与幻灯片一致；模型窗口列表 GPT-4-turbo/Gemini-1.5-Pro 128k、Claude-3-opus/sonnet 200k、Kimi-Chat 200万字符、通义千问1000万字与图一致。原文未给组件版本，affected_versions 留空正确；PoC 提示词骨架为据幻灯片整理，未实测。dedup 首位为自身 exact 自比对，次位 code-analysis-vuln-discovery-ast-chain-per-link-llm-audit-workflow 为相关但相反路线（AST 抽链逐链分析 vs 整库投喂模型自行跨文件追踪），dedup_review 成立，保留并列。dup-scan.json 早于建卡且无本篇 pair。
url: /docs/code-analysis/static/source-audit/code-analysis-source-audit-llm-long-context-cross-file-sqli-trace/
draft: false
kb_aliases:
- LLM 代码审计
- 全项目投喂
- 长上下文代码审计
- 跨文件参数追溯
- GPT 挖 SQL 注入
- AI SAST 辅助
---

## 一句话结论

把整个项目（或足够大的相关代码集）一次性投喂给长上下文模型，让它按“先找拼接 sink、再追参数来源”的指令做审计，可以在一轮对话里列出跨文件的注入风险点：例如 Mongo 的 `find({_id: ObjectId(id)})`、pg 的 `SELECT * FROM ${tableName} WHERE id = '${id}'`、文件导入后二次落库的路径，并继续把 `id` 从 API 路由追到前端 URL/全局状态。

## 原理

- 传统 SAST 需要 rule/taint 建模，跨文件、跨语言（TS 前端→API→Service→DB）追踪代价高；长上下文模型（示例：GPT-4-turbo 128k、Gemini-1.5-Pro 128k、Claude-3-opus/sonnet 200k、Kimi-Chat 200 万字符、通义千问 1000 万字）可以把多个文件同时放进上下文，模型据此在“记忆里”完成调用链关联。
- 有效的提示结构是让模型做两件事：**sink 枚举**（搜索字符串拼接/拼接查询的位置，并给出文件与行号/代码片段）和**反向污点追踪**（从函数参数向上追到路由/控制器/前端参数，判断是否用户可控）。示例中模型先列出 `projects/service/src/common/mongo/index.ts` 的 `find({_id: ObjectId(id)})`、`pg/index.ts` 的模板字符串 SQL、`import/index.ts` 的文件读取，再跨文件说明 `id` 来自 `getDatasetDetail` 接口的 URL 参数或全局状态。
- 长上下文带来的能力不是“更聪明”，而是“看得全”：跨文件数据流、路由与 service 的命名对应、类型定义、调用点都能同时可见，模型可以据此给出可人工复核的候选链，显著减少逐文件搜索时间。
- 局限：上下文窗口仍有限（大仓库需裁剪/检索）、模型可能幻觉不存在的文件或调用关系、对动态拼接（eval/反射/ORM 复杂封装）理解不稳定；因此输出只能作为候选，需人工或用 CodeQL/Joern 等工具复核。

## 触发条件

- 有可用的大上下文模型（API 或本地部署），并能把项目代码按文件/目录组织进上下文。
- 代码规模在模型窗口内，或已用检索/代码图裁剪出与目标功能相关的子集。
- 审计者能提供明确的 sink/污点提示与输出格式，便于复核。

## 利用步骤

1. 选择窗口足够的模型，准备项目树、路由表、关键 service/DAO 源码（大项目先按模块分批）。
2. 第一轮提示：要求模型“审计注入类风险，先枚举所有字符串拼接/查询拼接 sink，输出文件、行号、代码与风险类型”，并限制只根据给定代码回答、不确定要标注。
3. 第二轮提示：对每个候选 sink，要求“从该参数向上追溯来源，列出经过的函数/文件，直到 HTTP 路由、CLI 参数或前端输入；说明是否用户可控”。
4. 人工复核候选：对照源码确认；用 CodeQL/Joern/动态测试验证可利用性；排除模型臆造。
5. 将确认的链路转成修复建议（参数化查询、白名单、类型校验），并可把 LLM 用于生成/补充 SAST 查询（见关联卡）。

## PoC

无完整 PoC（原文为幻灯片中的审计示例）。提示词骨架：

```text
你是一名代码审计专家。下面是一个项目的源码（按文件给出）。
任务：
1) 找出所有可能导致 SQL/NoSQL 注入的字符串拼接或查询拼接位置，
   输出 文件、行号、代码片段、风险类型；
2) 对每个位置，向上追踪参数来源（经过的函数/文件），
   直到 HTTP 路由、CLI 或前端输入，并判断是否用户可控。
只依据给定代码回答，不确定的地方明确标注“需人工确认”。
```

## 变体与关联

- 关联 [[code-analysis-sast-qlcoder-llm-codeql-query-synthesis]]：那张卡用 LLM Agent 生成/验证 CodeQL 查询；本卡是直接把代码投喂给模型做 sink 枚举与跨文件污点追踪，产出候选而非可执行查询。
- 关联 [[code-analysis-source-audit-ai-sast-java-gadget-chain-mining]]：那张卡用 JavaParser+CHA+Neo4j 构图后让 LLM 筛选 gadget 链；本卡依赖长上下文直接读代码，适用于中小项目或按模块分批。
- 变体：RAG/代码图（CodeQL、Joern、Tabby）先检索相关文件再让模型分析；Agent 多轮自行 `grep`/读文件；把模型输出与 SAST 告警合并做 triage（降误报/排优先级）。
- 边界：超长仓库需裁剪；模型可能编造未给出的文件；对 ORM/动态调用链判断不可靠；外部 API 模型会接触源码，注意数据保密。

## 检测与防御

- 防御（开发侧）：参数化查询/预编译、输入类型与长度校验、最小权限数据库账户；把 LLM 审计作为 SAST 的补充而非替代，所有候选必须人工复核。
- 数据安全：不要把含密钥/客户数据的代码发给不可信的外部模型；使用企业版/本地模型并做脱敏。
- 检测：CI 中同时运行 CodeQL/Semgrep 等确定性扫描；对 LLM 输出的“新发现”做回归用例，防止幻觉被当成真实漏洞。
