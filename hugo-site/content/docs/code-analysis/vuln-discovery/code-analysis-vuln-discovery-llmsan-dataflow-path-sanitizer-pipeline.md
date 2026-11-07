---
id: code-analysis-vuln-discovery-llmsan-dataflow-path-sanitizer-pipeline
title: LLMSAN：强制 LLM 输出数据流路径并用四类 Sanitizer 过滤漏洞检测幻觉
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery
technique: llmsan-dataflow-path-sanitizer-pipeline
tags:
- code-analysis
- vuln-discovery
- llm
- sast
- data-flow
- sanitizer
- hallucination
- false-positive
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V178
  verified_at: '2026-11-06T17:37:48+08:00'
  notes: 已对照原文与图01-11核对：数据流路径定义、DBZ示例、Type/Functionality/Order/Reachability四类Sanitizer、Functionality/Reachability prompt模板、Table3平均P91.03/R74.00、过滤spurious 78.24%、误删valid 0.57%、FSCoT P69.04/R74.40均一致；论文方法无独立PoC，卡标confidence medium；无CVE、无sources/source_url；未复跑论文代码。
url: /docs/code-analysis/vuln-discovery/code-analysis-vuln-discovery-llmsan-dataflow-path-sanitizer-pipeline/
draft: false
kb_aliases:
- LLMSAN
- 数据流路径清洗
- Type Sanitizer
- Functionality Sanitizer
- Order Sanitizer
- Reachability Sanitizer
- LLM 漏洞检测降误报
---

## 一句话结论

让 LLM 做漏洞检测时不要只输出“有漏洞”的结论，而是强制它输出一条可验证的数据流路径（变量+行号的序列）作为证据；再把路径校验拆成 Type、Functionality、Order、Reachability 四类 Sanitizer，确定性的部分交给解析器/控制流分析，语义部分只对局部函数向 LLM 提固定问题，只保留全部通过的路径，从而把幻觉路径大量过滤掉。

## 原理

- **问题**：few-shot CoT 直接让 LLM 判断漏洞时幻觉严重；论文在 Juliet 的除零（DBZ）用例上，gpt-3.5-turbo 的 239 条漏洞报告中有 184 条是误报，模型会凭空构造不存在的数据流和解释。
- **结构化证据**：把数据流路径定义为 `p = ((v1, l1), (v2, l2), ..., (vk, lk))`，其中 `vi` 是变量/表达式，`li` 是行号；相邻对 `(vi, li) -> (vi+1, li+1)` 表示前者的值会直接影响后者，称为一个 data-flow fact。DBZ 例子：`parseInt(arg)`（行 12）→ `c`（行 12）→ 参数 `y`（行 3）→ `100 / y`（行 5）。
- **四类 Sanitizer**（前两类检查起点/终点，后两类检查中间边）：
  - **Type Sanitizer**：从 few-shot 样例统计每种漏洞的起点/终点语法类型集合；解析模型生成的路径，若起点/终点类型与样例集合完全不相交（例如把字符串字面量当成 DBZ 起点），判为 spurious。纯解析/静态分析，无 LLM。
  - **Functionality Sanitizer**：截取起点/终点所在函数，用固定 prompt 问 LLM“该表达式在上下文中是否可能为危险值（0/null/敏感数据）”“终点是否为对应 sink（除数/解引用）”，按回答保留或丢弃。
  - **Order Sanitizer**：检查每条边是否符合控制流顺序（行号/CFG 偏序）；出现 `(v, line 20) -> (v, line 10)` 这类不可能的执行顺序就否定整条路径。基于 CFG，无 LLM。
  - **Reachability Sanitizer**：在条件分支/循环约束下判断边是否可达；例如 `if (data != 0) { y = data; print(100 / y); }` 虽然语法上有 `data -> y -> 100/y`，但进入分支时 `data` 已保证非 0，DBZ 不可达。用局部函数 + 固定 prompt 让 LLM 判断“值能否从前者传播到后者”，回答 No 则否定该边。
- **为什么有效**：把“验证整条路径”这个复杂任务分解为多条可独立检查的语法/语义性质；能用程序分析确定的部分不依赖 LLM，必须语义判断的部分只给局部代码、只问一个 Yes/No 问题，压缩了模型的自由度，减少幻觉。
- **论文结果**（gpt-4，Juliet 5 类漏洞 APT/XSS/OSCI/DBZ/NPD）：平均精度 91.03%、召回 74.00%；基线 FSCoT 精度 69.04%、召回 74.40%；过滤约 78.24% 的 spurious 路径，误删真实路径约 0.57%。在 TaintBench 上优于 CodeFuseQuery；对无法编译的旧代码仍可用（不依赖 IR/编译）。

## 触发条件

- 需要用 LLM 做代码漏洞检测/代码审计，且目标语言有可用的解析器与 CFG（论文示例为 Java）。
- 能构造每种漏洞的 few-shot 示例，包含“解释 + 合法数据流路径”。
- 代码可能不完整/无法编译，但仍可解析出 AST/行号/控制流。
- 有 LLM API 或本地模型，可对局部函数做多次固定问题调用。

## 利用步骤

1. **准备 few-shot**：为每种漏洞（DBZ、NPD、XSS、OSCI、APT 等）准备示例程序、漏洞解释和一条合法数据流路径；路径用 `(变量, 行号)` 序列表示。
2. **生成报告**：用 CoT prompt 要求模型输出“漏洞类型 + 自然语言解释 + 数据流路径”；路径必须覆盖从危险值产生到 sink 的每个传播点。
3. **解析与建图**：解析目标源码得到 AST、行号、函数边界与 CFG；把模型输出的路径解析为 `(v, l)` 序列，定位每个变量/表达式。
4. **Type Sanitizer**：统计样例中每种漏洞的起点/终点 AST 类型集合；类型不匹配的路径直接丢弃。
5. **Functionality Sanitizer**：对起点/终点截取所在函数，使用固定 prompt（“该值在上下文中是否可能为 0/null/敏感数据？”“该位置是否为除数/解引用等 sink？”），回答 No 则丢弃。
6. **Order Sanitizer**：对每条相邻边检查行号/CFG 偏序；不可达的执行顺序直接丢弃整条路径。
7. **Reachability Sanitizer**：对每条边截取相关函数，问 LLM“在给定条件/控制流下，值能否从前者传播到后者？”；回答 No 则丢弃该边/路径。
8. **汇总**：只保留通过全部 Sanitizer 的路径作为可信报告；统计 precision/recall 与误删率，调整 prompt 与类型集合。

## PoC

无独立可执行 PoC（论文方法，开源实现可复现）。核心 prompt 模板如下：

```text
# Functionality Sanitizer
Examples: Here are several examples containing DBZ bugs: [examples].
Please understand how zero values are produced.
Task: Analyze the code: [function].
Please check whether [value] at line [line number] can be zero.
Please think step by step and conclude the answer with Yes or No.

# Reachability Sanitizer
Examples: There are examples containing DBZ bugs: [examples].
Please understand how program values are propagated.
Task: Analyze [function 1], [function 2].
Please check whether [value 1] at line [line number 1]
can be propagated to [value 2] at line [line number 2].
Please think step by step and conclude the answer with Yes or No.
```

```text
# 路径判定伪代码
for report in llm_reports:
    path = parse(report.dataflow_path)          # [(var, line), ...]
    if not type_sanitizer(path): continue        # 起点/终点类型集合
    if not functionality_sanitizer(path): continue
    if not order_sanitizer(path, cfg): continue  # 行号/CFG 偏序
    if not reachability_sanitizer(path): continue
    accept(report)
```

本卡不执行论文代码；指标为论文报告值。

## 变体与关联

- Sanitizer 可扩展为 Nullness、Taint、Bounds 等；也可把 Type/Order 换成 CodeQL/Joern 等现成静态分析。
- 可只对高风险路径调用 LLM，降低 token 成本；或把局部 LLM 判断替换为小模型/规则。
- 与多 agent 审计管线的区别：LLMSAN 的核心是“结构化数据流路径 + 逐条性质过滤”，不是让多个 agent 互相投票。
- 关联：[[code-analysis-vuln-discovery-llm-sast-vulnhuntr-python-audit-pipeline]]（LLM SAST 管线）、[[code-analysis-vuln-discovery-ast-chain-per-link-llm-audit-workflow]]（AST 链逐链审计）、[[code-analysis-vuln-discovery-multi-agent-adversarial-pipeline]]（多 agent 对抗审计）、[[code-analysis-sast-codeql-custom-taint-steps]]（自定义污点分析）。
- 边界：需要可解析的源码与 CFG；LLM 局部判断仍可能出错；论文结果依赖 gpt-4 与特定 few-shot/数据集，迁移到其它语言/漏洞类型需重新调 prompt；不适用于二进制或无源码目标。

## 检测与防御

- 这是检测侧方法：用于构建/改进 LLM 代码审计工具，降低误报，提升 CI/CD 可用性。
- 防御侧启示：不要相信 LLM 的单一“有漏洞”结论；要求结构化证据（数据流、行号、sink），并用确定性程序分析交叉验证。
- 评估：同时报告 precision/recall、spurious 过滤率、真实路径误删率；在小样本上警惕过拟合与提示词偏差。
- 对抗：攻击者可能构造看似合法但实际不可达的路径欺骗 Sanitizer；需要组合 CFG/约束求解与人工复核。
