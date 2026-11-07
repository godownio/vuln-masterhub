---
id: code-analysis-sast-sca-llm-agent-reachability-verification
title: SCA 告警到 SAST/DAST 验证建议：LLM Agent 多源证据检索与可达性规则生成
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: sca-llm-agent-reachability-verification
aliases:
- SCA 可达性分析
- SCA 最后一公里
- LLM Agent SCA
- SCA+SAST+DAST
- 漏洞可达性验证
- Enhanced Findings
- SCA 误报治理
tags:
- sca
- sast
- dast
- llm
- agent
- langgraph
- vulnerability-management
- reachability
- false-positive
- supply-chain
- cve
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:46+08:00'
  notes: 已对照原文与 9 张图片核对；LangGraph 流程与两例输出一致；原文未量化命中率，未执行 DAST
---

## 一句话结论

把 SCA 的“组件+版本+CVE”告警作为起点，用 LangGraph 状态机驱动 LLM Agent 检索 GHSA/NVD/厂商公告/修复 commit/PoC 多源证据，再让 LLM 分别产出 SAST 的 sink/数据流规则与 DAST 的攻击向量/payload/检测器，可把“版本命中”升级为“是否可达、如何验证”的处置建议，降低 SCA 误报与修复盲目性；原文用 OpenSCA + deepseek-chat + Spring Boot 商城项目跑通 demo，但未给出规则命中率/误报率量化。

## 原理

- SCA 只做组件版本匹配，无法判断漏洞函数是否被调用、配置是否满足触发条件；因此同一 CVE 在大量项目中是“可能受影响”而非“确认可利用”。SAST 污点分析能检查 source→sink 是否可达，DAST 能在运行时用针对性 payload 验证，两者正好补上 SCA 缺的“深度”。
- 关键桥梁是 CVE 的 sink 信息（具体类/方法/配置键/调用模式）。SCA 告警通常只有组件名、版本、CVE 编号；LLM 通过多源证据把 CVE 还原成可扫描的 sink、source、调用模式、危险配置键与利用前置条件，SAST/DAST 才能从“全站盲扫”变成“定点验证”。
- 多源证据互补：GitHub Security Advisories 及时、质量高；厂商安全公告权威、修复建议详细；GitHub 修复 commit 的 diff 能揭示漏洞本质与 sanitizer/触发条件；PoC 源提供实际攻击向量；NVD 提供标准化描述。原文以这五类源为目标，NVD 因 token 原因暂未接入。
- LangGraph 状态机适合多步编排：Ingestor 解析不同 SCA 输出（OpenSCA/Syft/其他）→ 过滤有漏洞组件 → 批量检索证据（带文件缓存与证据缓存）→ SASTExtractor/DASTConstructor 分别调用 LLM → 输出 Enhanced Findings/SAST Sinks/DAST Inputs/Processing Summary。状态图与检查点让长流程可恢复，避免一次失败全部重跑。
- 输出直接面向工具链：SAST 侧给 dangerous_functions、call_patterns、config_keys、data_flow_patterns；DAST 侧给 attack_vectors（方法/端点/参数）、payloads（placement/encoding）、detectors（响应体/状态码/响应时间/外带连接/文件创建）与 risk_notes。原文示例中，Agent 对 Spring4Shell 给出 `class.module.classLoader...` 属性链与 Tomcat 日志写入路径，对 MyBatis 给出 `OgnlCache.getValue`/`TextSqlNode.apply` 作为 sink 及 HttpServletRequest→sink 的数据流。
- 根因与边界：LLM 具备把 CVE 元数据与代码/公告语义对齐的能力，但它会编造不存在的端点、参数或配置键；证据不足（如 “Evidence: No evidence available”）时输出仍可能看起来合理。原文只验证了 demo 能产出结构化建议，未验证这些规则在真实代码/环境中是否命中，也未量化准确率。

## 触发条件

- 有 SCA 输出（OpenSCA、Syft 等），且包含组件名、版本与 CVE 列表；能访问 GHSA、NVD、厂商公告、GitHub commit 与 PoC 源（GitHub token 必需，NVD token 可选）。
- 目标项目有源码可做 SAST（最好能构建），有可运行实例可做 DAST；测试需在授权环境进行。
- 有可用的 LLM API（原文用经济型 deepseek-chat）与 LangGraph/LangSmith 运行环境。
- 团队把 LLM 定位为“生成候选规则与测试建议”，由人或扫描器复核，而不是直接自动修改生产扫描策略。

## 利用/实施步骤

1. 解析 SCA 结果：按 OpenSCA/Syft/其他格式归一化，过滤无漏洞组件，为每个漏洞组件创建 Finding（package、version、language、vulnerability title、cve、severity）。
2. 多源证据检索：并行查询 GHSA、厂商公告、GitHub 修复 commit、PoC 库与 NVD；命中缓存则直接复用，未命中再拉取并写缓存。
3. 生成 SAST 规则：让 LLM 基于证据输出危险函数（类/方法/参数）、调用模式、危险配置键、source→sink 数据流模式；要求给出置信度并引用证据。
4. 生成 DAST 输入：让 LLM 输出攻击向量（HTTP 方法、端点、参数/头/体注入点）、测试 payload（raw/url/base64 编码与放置位置）、检测器（响应体特征、状态码、响应时间、外带连接、文件创建）与风险说明。
5. 人工/工具验证：把 SAST 规则接入扫描器在目标源码上跑，检查是否命中真实调用链；在授权测试环境执行 DAST payload，确认检测器是否触发。未命中的规则回退给 Agent 补充证据或标记为低置信。
6. 汇总输出 Enhanced Findings、SAST Sinks、DAST Inputs、Processing Summary，作为修复优先级与验证依据；对每个 CVE 记录证据来源与置信度。

## PoC

SAST 规则生成 Prompt 骨架（原文 system 段，节选）：

```text
You are a security expert specializing in static analysis.
Analyze vulnerability findings and extract specific code patterns
that SAST tools should look for:
1. Dangerous function calls and their parameters
2. Data flow patterns from sources to sinks
3. Configuration keys that might indicate vulnerabilities
4. Language-specific security anti-patterns
Return JSON with dangerous_functions / call_patterns / config_keys / data_flow_patterns.
```

DAST 输入生成 Prompt 骨架：

```text
You are a security expert specializing in dynamic application security testing (DAST).
For each vulnerability finding, generate:
1. Attack vectors (HTTP methods, endpoints, parameters)
2. Test payloads for exploitation
3. Detection patterns to identify successful exploitation
Return JSON with attack_vectors / payloads / detectors / risk_notes.
```

输出示例（以 MyBatis CVE-2020-26945 为例，原文 Agent 输出节选）：

```json
{
  "dangerous_functions": [
    {"function_name": "org.apache.ibatis.scripting.xmltags.OgnlCache.getValue",
     "parameters": ["expression", "parameterObject"],
     "description": "Direct OGNL expression evaluation that can execute arbitrary code",
     "confidence": "high"}
  ],
  "data_flow_patterns": [
    {"source": "HttpServletRequest.getParameter|getHeader|getQueryString",
     "sink": "TextSqlNode.apply|BindingTokenParser.parseToken|OgnlCache.getValue",
     "description": "User input flows into MyBatis dynamic SQL OGNL evaluation"}
  ]
}
```

原文还展示了 Spring4Shell（CVE-2022-22965）的 DAST 建议：`class.module.classLoader.resources.context.parent.pipeline.first.*` 参数链、Tomcat 日志写入与 JSP 检测器。本卡不复述可直接投放的完整 payload；原文未实际执行这些 DAST 测试，规则有效性未验证。

## 变体与关联

- 输入变体：OpenSCA、Syft、Dependency-Check 等 SCA 输出；也可用 SBOM（CycloneDX/SPDX）作为组件来源。
- 证据源变体：NVD、OSV、GHSA、厂商公告、Snyk/漏洞库、GitHub commit、Exploit-DB/PoC 仓库；证据越多，sink 定位越准。
- 输出变体：CodeQL/Semgrep 规则、SAST 数据流配置、DAST 请求模板、 nuclei 模板、修复优先级评分。
- 关联卡：[[code-analysis-sast-qlcoder-llm-codeql-query-synthesis]]（CVE 元数据→CodeQL 查询的生成-验证闭环）、[[code-analysis-vuln-discovery-autocve-target-count-multi-agent-orchestration]]（多 Agent 漏洞挖掘与验证编排）、[[code-analysis-sast-tabby-neo4j-controller-sink-callchain]]（从 Controller 到 sink 的调用链查询）、[[code-analysis-vuln-discovery-agent-miner-langgraph-whitebox-audit-poc-verification]]（LangGraph 白盒审计 + PoC 验证）。
- 攻击面延伸：同一套“SCA 告警 + 证据检索 + sink 定位”能力也可被攻击者用来挑选目标：从公开 SBOM/指纹识别组件版本，查可达性与公开 PoC，优先攻击真正包含漏洞函数且暴露入口的系统。
- 边界：输出是“验证建议”，不是已验证结论；LLM 幻觉、证据源过时/不可信、项目构建差异都会造成误判。

## 检测与防御

- 人工复核与置信度：LLM 生成的 sink/端点/配置键必须由安全工程师或确定性工具复核；要求每条规则附带证据来源与置信度，低置信不自动执行。
- 规则验证闭环：SAST 规则先在漏洞版本与修复版本上做差分验证（修复版本应不命中），再进入 CI；DAST payload 只在授权隔离环境执行，检测器需实际触发才算通过。
- 证据源治理：外部公告、commit、PoC 文本是不可信输入，可能包含针对分析 Agent 的间接提示注入；应做来源白名单、内容隔离/转义、工具最小权限，禁止 Agent 依据外部文本自动修改扫描策略或执行命令。
- 数据与缓存：记录证据拉取时间与版本，避免使用过时公告；对缓存做完整性校验，防止证据缓存被污染。
- Agent 权限：LangGraph 工具只给只读查询与受限文件访问；不要让 Agent 直接访问生产代码仓库写权限、生产扫描器管理接口或内网。
- 度量：统计每条规则的命中率、误报率、人工复核通过率与修复采纳率；用真实项目回归，避免“输出看起来专业”被当作有效。
- 供应链视角：SCA 告警应结合运行时依赖、实际调用链、暴露面与业务影响排序，而不是按 CVSS 一刀切升级。
