---
id: code-analysis-vuln-discovery-sarif-sast-llm-alert-triage
title: SARIF 汇聚 Semgrep/CodeQL 告警 + 局部代码与规则描述构造 prompt：LLM 复核压误报，放宽 sink 规则扩召回
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery
technique: sarif-sast-llm-alert-triage
aliases:
- LLM 辅助静态扫描审计
- SARIF 统一 SAST 输出
- SAST 告警 LLM 复核
- Semgrep CodeQL GPT 代码审计
- Choccy 魔改
tags:
- llm
- sast
- sarif
- semgrep
- codeql
- code-audit
- prompt-engineering
- false-positive
- vuln-discovery
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V444
  verified_at: '2026-11-09T23:03:30+08:00'
  notes: 已对照原文核对：SARIF 2.1.0(OASIS/JSON) 统一 Semgrep/CodeQL、按工具能力构造 prompt（Semgrep 无污点给 sink 周边/整文件，CodeQL 附 source/数据流）、规则描述入 prompt（XXE setFeature 示例）、fastjson 辅助代码扩展、SAST sink 规则放宽换 LLM 压误报、魔改 Choccy 展示，均与原文及 5 张截图一致（图 01 架构图；图 02-03 Semgrep 路径穿越 GPT 判定与 filepath.Base 建议；图 04-05 CodeQL SSRF/XSS 数据流路径）。PoC 为流程骨架并已注明原文无完整工程。方法卡无组件版本/CVE，affected_versions 保持空；与既有 LLM 审计卡（VulnHuntr/AST 逐链/LLMSAN）实现路径不同，不重复。dup-scan.json(11-08) 早于建卡(11-09)。
---

## 一句话结论

把 Semgrep、CodeQL 等 SAST 结果统一为 SARIF，解析每条告警的 sink 位置、上下文代码与规则描述，按告警逐条构造 prompt 交给大模型判断漏洞是否成立并给出理由；由于 LLM 能基于语义压掉误报，SAST 的 sink 规则可以故意放宽以扩大召回，形成“确定性扫描定位 + LLM 语义裁决”的代码审计流水线（原文在 Choccy 项目上集成 Semgrep 扫描与 GPT-3.5 32k 分析展示）。

## 原理

- **纯 LLM 全仓扫描的瓶颈**：受 token 限制，把整个仓库交给模型只能识别简单漏洞，成本高且效果差；先用静态扫描把候选收敛到具体 sink，再把局部上下文交给 LLM，等价于“确定性工具负责定位、语言模型负责语义判断”。
- **SARIF 作为统一接口**：静态分析结果交换格式 SARIF 2.1.0 是 OASIS 标准，本质是 JSON，主流 SAST 工具均支持导出；解析模块只需面向 SARIF 的 ruleId、message、物理位置与数据流路径（CodeQL 的 codeFlows/path），不必为每个引擎单独适配（架构为：安全分析系统→静态扫描工具→SARIF 输出→解析模块→构造 prompts→LLM 分析→处理返回数据→展示）。
- **按工具能力决定 prompt 上下文**：Semgrep 没有污点分析，应把 sink 点周边代码甚至整个文件放进 prompt；CodeQL 有污点追踪，则应同时放入 sink 附近代码和相关的 source/数据流步骤（截图中 XSS 告警的 path 展示 GetString→xss→DoFilter→output 等 6 步），让模型看到完整链再判断。
- **规则描述入 prompt**：除代码外把扫描规则的描述/说明一并交给模型，补充漏洞语义与修复方式（如 XXE 规则里补充禁用外部实体的多个 setFeature/setProperty 写法），弥补规则只匹配语法、不理解修复是否完整的缺陷；企业还可把内部框架的修复惯例写进规则描述，提升针对性。
- **输入代码扩展**：对 fastjson 这类漏洞，除 source/sink 外把依赖包引入、autotype 配置、黑白名单等辅助代码也放进 prompt，模型才能判断实际可利用性，而不是只看语法匹配。
- **“SAST 规则负优化”**：有了 LLM 兜底压误报后，不必把 SAST 规则调得极精确；例如 CodeQL Go SSRF 的 sink 判断存在漏报时，可以放宽 sink 规则、保留 source 污点分析，让更多可疑写法进入候选，由 LLM 过滤误报——静态分析负责召回，LLM 负责精确度。
- **为什么成立**：SAST 的强项是可枚举、可数据流追踪但不理解业务语义；LLM 的强项是理解局部代码语义但缺少全局定位能力且易幻觉。两者把“找哪里”和“是否成立”拆开，各自做擅长的事，同时把 LLM 的 token 消耗限制在告警局部。

## 触发条件

- 目标项目已有 Semgrep/CodeQL 等可导出 SARIF 的扫描结果，或可自行运行扫描；
- 告警数量大、人工 triage 成本高，且能取得告警对应的源码片段（CodeQL 可直接提供数据流路径）；
- 可使用 LLM API 并有 token 预算（原文选 GPT-3.5 32k 是成本取舍）；
- 代码可外发或使用本地模型，满足数据合规要求；
- 仍需人工复核最终结论（模型判断存在幻觉与漏判）。

## 利用步骤

1. 用 Semgrep（规则简单、易写）和/或 CodeQL（带污点分析与源码路径）扫描目标，统一导出 SARIF。
2. 解析 SARIF：取每条结果的 ruleId、message、文件与行号，CodeQL 结果额外取 codeFlows/path 中的 source→sink 步骤。
3. 按告警截取 sink 周边代码（Semgrep 无污点时可给整文件；CodeQL 附 source 片段与路径），并拼接对应规则描述。
4. 逐条构造 prompt 请求 LLM 输出：是否为真实漏洞、判断理由（引用代码步骤）、修复建议。
5. 把 LLM 结论回写到统一平台展示（原文魔改 Choccy 增加 Semgrep 扫描页与 GPT 分析列/弹窗），人工复核高风险结论。
6. 根据漏报反馈调整 SAST 规则：sink 规则可放宽扩召回，source/污点模型保持精确，用 LLM 结果反向标注误报。

## PoC

无完整可执行 PoC（原文为系统实现与截图演示）。最小流程骨架：

```text
# 1) 扫描导出 SARIF
semgrep --sarif -o semgrep.sarif <target>
codeql database analyze <db> <query>.ql --format=sarif-latest -o codeql.sarif

# 2) 解析告警（伪代码）
for result in sarif.runs[].results:
    rule  = ruleId / message
    loc   = result.locations[0].physicalLocation (file, line)
    code  = 截取 loc 周边函数/文件（CodeQL 再加 codeFlows 的 source 段）
    prompt = 规则描述 + code + "该告警是否为真实漏洞？给出代码依据与修复建议"

# 3) 逐条请求 LLM，回写展示并人工复核
```

原文截图示例：GPT 对 Go 路径穿越告警解释 `os.OpenFile(fpath, ...)` 中 `fpath` 由上传文件名拼接，建议用 `filepath.Base` 取文件名；对 CodeQL XSS 告警按 GetString→DoFilter→输出的路径步骤判定成立。

## 变体与关联

- 变体：把 CodeQL 的 codeFlows 作为“证据路径”强制模型逐跳核对，可进一步压低幻觉（与 LLMSAN 的四类 Sanitizer 校验思路互补）。
- 变体：用本地/私有化模型替代外部 API，规避源码外发合规问题，但需评估代码理解能力。
- 变体：同一套 SARIF 汇总 + LLM 复核框架也可用于增量 API 提取、配置审计等“需要语义理解”的任务。
- 关联：既有 [[code-analysis-vuln-discovery-llm-sast-vulnhuntr-python-audit-pipeline]]（五阶段 prompt + Jedi 补全）与 [[code-analysis-vuln-discovery-ast-chain-per-link-llm-audit-workflow]]（AST 提取 Source→Sink 链逐链分析）是自建静态流水线的 LLM 审计；[[code-analysis-vuln-discovery-llmsan-dataflow-path-sanitizer-pipeline]] 侧重路径校验；本卡是“现成 SAST 引擎 + SARIF 统一接入 + LLM 复核”的集成方案，不重复造扫描器。
- 关联：[[code-analysis-sast-qlcoder-llm-codeql-query-synthesis]] 是用 LLM 生成 CodeQL 查询（方向相反：LLM 服务于扫描器，本卡是扫描器服务于 LLM 判断）。

## 检测与防御

- 对使用方：LLM 结论必须人工复核，不能作为唯一判定；prompt 中只放必要代码片段，敏感代码优先本地模型；保留 SAST 原始告警与模型结论的对应关系便于审计。
- 对防御方：此类流水线本质是提升代码审计效率，防御仍依赖安全编码、框架级修复与 SAST/SCA 门禁；注意代码/规则外发带来的供应链与泄密风险。
- 局限：Semgrep 无污点分析时上下文可能不足；CodeQL 查询本身的覆盖决定召回上限；LLM 对跨文件/动态调用和业务逻辑漏洞仍可能误判。
