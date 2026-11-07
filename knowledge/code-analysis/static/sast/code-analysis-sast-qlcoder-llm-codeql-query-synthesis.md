---
id: code-analysis-sast-qlcoder-llm-codeql-query-synthesis
title: QLCoder：LLM Agent + CodeQL LSP/RAG 从 CVE 元数据迭代合成污点查询
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: llm-agent-codeql-query-synthesis-rag-lsp
aliases:
- QLCoder
- CodeQL 查询自动生成
- CVE 到 CodeQL 查询
- LLM 合成静态分析规则
- Agentic Synthesizer
- CodeQL Validator 反馈循环
- Source Sink Sanitizer 模板
tags:
- codeql
- sast
- llm
- agent
- rag
- lsp
- taint-tracking
- vuln-discovery
- cve
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V184
  verified_at: '2026-11-06T20:05:26+08:00'
  notes: 已对照原文与全部6张图片核对：RAG、CodeQL LSP/MCP工具、Source/Sink/Sanitizer模板、双版本Validator反馈循环、CVE-2025-27136示例均一致；176个CVE、53.4%成功率、平均精度0.631与评估表一致，原文另有F1=0.7表述；未复跑QLCoder。
---

## 一句话结论

QLCoder 把“从 CVE 描述写 CodeQL 查询”拆成 LLM Agent 的“生成→验证→反馈→修正”循环：Agent 通过 RAG 检索 CVE/CWE/CodeQL 文档/示例查询/AST，通过 MCP 调用 CodeQL 语言服务器的补全、诊断与跳转工具，按 Source/Sink/Sanitizer/污点配置模板生成候选查询；Validator 在漏洞版本与修复版本上分别编译执行，把编译结果、匹配数、误报、方法覆盖率反馈给 Agent，直到查询只在漏洞版本命中或达到迭代上限。原文评估 176 个 Java CVE，53.4% 能生成精准查询，平均精度 0.631。

## 原理

- **手工写查询的三重门槛**：一是 CodeQL 语法/谓词系统脆弱，`readValue` 写成 `readValues` 或 AST 节点导航错误就会“编译通过但语义无效”；二是跨文件/跨模块污点追踪需要补充 `isAdditionalFlowStep`；三是精准性要求“漏洞版本报阳性、修复版本报阴性”，必须识别修复中的 sanitizer（如 `setProperty(SUPPORT_DTD, false)`），否则修复版本会误报。
- **RAG 解决上下文窗口**：预先把 CVE 描述、修复 diff、CWE 定义、CodeQL API 文档、示例查询、目标仓库 AST 片段存入向量库（如 ChromaDB）。Agent 按需检索，例如写 XXE Source 时检索 “XXE Source CodeQL 示例”，识别 sanitizer 时检索 `XMLInputFactory SUPPORT_DTD CodeQL` 模式；避免把海量文档一次性塞进上下文。
- **CodeQL LSP 提供实时语法指导**：通过 MCP 封装语言服务器，暴露 `codeql_complete`（补全符号，如输入 `XmlMapper.` 补出 `readValue`）、`codeql_diagnostics`（返回未知谓词等编译错误）、`codeql_definition`（跳转到 `TaintTracking::Global` 等定义）。Agent 写错 `hasQualifiedName` 时，诊断会提示未定义谓词，Agent 可改为 `hasQName`。
- **模板约束生成空间**：Prompt 中给出固定骨架——`Source`、`Sink`、`Sanitizer` 三个 `DataFlow::Node` 子类，`DataFlow::ConfigSig` 的 `isSource`/`isSink`/`isBarrier`/`isAdditionalFlowStep`，以及 `TaintTracking::Global` 的 `flowPath` 查询。Agent 只需填充各类的 AST 模式与跨文件步骤，输出结构稳定，Validator 也容易定位缺失部分。
- **Validator 的双版本判定**：分别在漏洞版本和修复版本的 CodeQL 数据库上执行候选查询，检查编译成功、漏洞版本命中、修复版本不命中、目标方法覆盖、误报清单。反馈文本包含 `COMPILATION SUCCESS`、`Results: Vulnerable=28, Fixed=20`、`Method Recall`、`Coverage`、`PARTIAL/EXCELLENT` 等标签，Agent 据此决定加 sanitizer、扩展 source/sink 还是补 flow step。
- **为什么迭代有效**：单次生成的查询通常缺少 sanitizer 或跨文件步骤；Validator 的“修复版本误报”直接指出漏掉的 barrier，“漏洞版本零命中”指出 source/sink 模式过窄。把自然语言的 CVE 描述与可执行的查询结果对齐，比让 LLM 一次性写完整查询更可靠。

## 触发条件

- 有目标 CVE 的描述与修复 diff（用于构造漏洞/修复两个版本）。
- 能为 Java 项目构建对应 commit 的 CodeQL 数据库，并具备 CodeQL CLI/LSP 与可调用工具的 LLM。
- CVE 属于可用污点追踪表达的类别（路径遍历、XSS、代码注入、命令注入、反序列化、XXE 等）；原文只支持 Java。
- 漏洞版本与修复版本的差异能体现在 AST/数据流上，而不是纯配置/运行时环境差异。

## 利用/实施步骤

1. 建立向量库：导入 CVE 描述、修复 patch、CWE 定义、CodeQL 官方文档、示例查询、目标仓库 AST 片段。
2. 为漏洞版本和修复版本分别构建 CodeQL 数据库；准备目标方法的期望命中集合，用于计算覆盖率。
3. 用模板 Prompt 启动 Agent；Agent 先检索相关 CWE/示例，再调用 `codeql_complete`/`codeql_definition` 确认 API 与 AST 节点。
4. Agent 生成候选 `.ql`，调用 `codeql_diagnostics` 修语法；Validator 编译并在两个数据库上执行，返回匹配数、误报、覆盖率。
5. 若修复版本有命中，Agent 增加 `isBarrier`/sanitizer 模式；若漏洞版本零命中，扩展 source/sink 或补 `isAdditionalFlowStep`；重复直到成功或达到迭代上限（原文示例为 10 次）。
6. 将成功查询用于 CI 回归、其他仓库变体扫描和补丁有效性验证。

## PoC

查询骨架（Agent 需要填充的部分）：

```ql
class Source extends DataFlow::Node {
  Source() { /* 匹配用户输入入口，如 HttpRequest.getBody */ }
}
class Sink extends DataFlow::Node {
  Sink() { /* 匹配危险调用，如 XmlMapper.readValue */ }
}
class Sanitizer extends DataFlow::Node {
  Sanitizer() { /* 匹配安全配置，如 setProperty(SUPPORT_DTD, false) */ }
}

module FlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof Source }
  predicate isSink(DataFlow::Node n) { n instanceof Sink }
  predicate isBarrier(DataFlow::Node n) { n instanceof Sanitizer }
  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) { /* 跨文件步骤 */ }
}
module Flow = TaintTracking::Global<FlowConfig>;
from Flow::PathNode src, Flow::PathNode snk
where Flow::flowPath(src, snk)
select snk.getNode(), src, snk
```

LSP 工具调用示例（MCP）：

```json
{"tool":"codeql_complete","arguments":{"file_uri":"file:///workspace/q.ql","line":5,"character":12,"trigger_character":".","limit":25}}
{"tool":"codeql_diagnostics","arguments":{"file_uri":"file:///workspace/q.ql"}}
```

原文以 CVE-2025-27136（XXE）演示：Source 匹配 `WstxInputFactory` 的创建/实例化/变量访问，Sink 匹配 `XmlFactory`/`XmlMapper` 构造，Sanitizer 匹配 `SUPPORT_DTD=false`，并用 `isAdditionalFlowStep` 连接 `XmlFactory → XmlMapper`。本库未复跑 QLCoder 或该查询，评估数据来自原文。

## 变体与关联

- 变体：把 CodeQL 换成 Semgrep YAML、Infer、Joern CPG；模板和 Validator 逻辑可复用，但 AST/污点 API 需重写。
- 变体：RAG 语料可加入历史 CVE 查询、项目自有规则、代码评审意见；LSP 可换成 tree-sitter/编译器诊断。
- 变体：Validator 可加入“补丁前后 diff 覆盖率”“同一 CWE 跨仓库变体扫描”“与动态 PoC/fuzzing 结果对照”，减少纯静态误报。
- 关联：[[code-analysis-sast-codeql-custom-taint-steps]]（手工补 CodeQL 数据流模型）、[[code-analysis-vuln-discovery-llm-sast-vulnhuntr-python-audit-pipeline]]（LLM 直接审计 Python 代码的五阶段 pipeline）、[[code-analysis-vuln-discovery-llmsan-dataflow-path-sanitizer-pipeline]]（LLM 生成 source/sink/sanitizer 路径）、[[code-analysis-vuln-discovery-ai-java-1day-four-dimension-agent-orchestration]]（多 Agent 挖 Java 1day）。

## 检测与防御（规则质量保障）

- **规则质量门禁**：每条自动生成查询必须同时在漏洞版本和修复版本上执行；只有“漏洞版本命中、修复版本零命中”才进入 CI，否则标记为待人工复核。
- **可解释性**：保留 Agent 迭代轨迹、检索到的 CVE/CWE 片段、LSP 诊断与 Validator 反馈，便于审计查询是否真正对应漏洞根因，而非过拟合到单个样例。
- **泛化验证**：在同类 CWE 的其他仓库/版本上做变体扫描；若只在原始 CVE 样例命中，说明查询可能过拟合。
- **局限**：原文只覆盖 Java，成功率为 53.4%，平均精度 0.631；对需要业务语义、动态分发、配置/运行时差异的漏洞，CodeQL 查询难以表达。自动生成结果应作为初稿，由安全工程师复核后再纳入阻断级 CI。
- **防御侧价值**：把 CVE 修复 diff 转成可执行查询后，可用于回归测试、补丁验证和供应链下游项目的变体排查；对下游项目，优先用厂商补丁对应的查询扫描自己的代码库。
