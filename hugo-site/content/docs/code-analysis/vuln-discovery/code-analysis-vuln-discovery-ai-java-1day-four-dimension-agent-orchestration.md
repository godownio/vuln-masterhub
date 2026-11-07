---
id: code-analysis-vuln-discovery-ai-java-1day-four-dimension-agent-orchestration
title: AI 驱动的 Java 1Day 挖掘：配置/语言/代码/依赖四维拆解与原子 Agent 编排
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery
technique: ai-java-1day-four-dimension-agent-orchestration
tags:
- vuln-discovery
- ai-agent
- multi-agent
- java
- sast
- cpg
- joern
- dependency
- configuration
- 1day
- human-in-the-loop
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V156
  verified_at: '2026-11-06T07:33:26+08:00'
  notes: 已对照28张幻灯片逐张核对：四维拆解（配置项/原生语言与环境变量/代码主体/项目依赖）、ConfSafeAgent归一化+风险识别+人工复核、LangSafeAgent高危函数知识图谱、LibSafeAgent依赖树/CVE RAG/复现环境/PoCBuilder、MainAgent下Source/Sink/Research/CPG(Joern MCP)/Dataflow编排、人在回路“副驾驶”表述均与幻灯片一致；Shiro anon与Hessian Servlet配置示例、FreeMarker模板注入实战截图亦对得上。未验证点：文章为方法论/架构，无完整PoC或可复现漏洞；卡片已标severity=info/confidence=medium并注明示意性；原文无版本与CVE，未设置versions；frontmatter无sources/source_url。
url: /docs/code-analysis/vuln-discovery/code-analysis-vuln-discovery-ai-java-1day-four-dimension-agent-orchestration/
draft: false
kb_aliases:
- 四维拆解 Java 项目
- ConfSafeAgent
- LibSafeAgent
- LangSafeAgent
- SourceAgent SinkAgent CPGAgent
- Joern MCP 数据流
- 1Day 知识图谱
- AI 漏洞挖掘多 Agent 编排
---

## 一句话结论

面对大型 Java 项目，直接把整库丢给大模型会被上下文上限和幻觉拖垮；更可运营的做法是按“配置项、原生语言与环境变量、代码主体、项目依赖”四个维度拆解，用 ConfSafe、LangSafe、LibSafe 等原子 Agent 分别构建高密度上下文，再由 Source/Sink/Research/CPG/Dataflow Agent 围绕 sink-source 做 CPG 数据流追踪与 PoC 验证，最后交人工确认有效路径。

## 原理

- **为什么四维拆解**：Java 项目的攻击面并不只在业务代码。配置项（Shiro 过滤链、Servlet 映射、数据库/密钥）、语言版本与环境变量、代码主体（source/sink）、第三方依赖（带版本 CVE）各自独立且噪声很大；把整库塞入一个上下文会让模型注意力被稀释，且难以给出可验证的行号与数据流。
- **配置即攻击面**：很多 1Day 不是代码写错，而是默认配置/错误配置。典型例子：`beans-security.xml` 中 Shiro `filterChainDefinitions` 把敏感接口配成 `anon`，攻击者无需认证即可访问；`web.xml` 暴露 Hessian `DispatcherServlet`（`load-on-startup=1`）且无访问控制，攻击者可构造恶意序列化数据触发反序列化 RCE。配置 Agent 先把 xml/json/yaml、nginx.conf、`Configuration.java` 等多格式配置归一化为统一 JSON，再用规则/LLM 识别风险项、定级并交人工复核。
- **依赖即 1Day 知识图谱**：从构建文件提取带版本的依赖清单 → 还原依赖树/二分法归类（框架类 vs 工具类）→ 用 CVE/补丁/PoC 构建 RAG 知识库 → 在隔离环境搭建复现环境 → 生成并验证 PoC → 输出“带 PoC 的 sink 清单”。这样模型不必凭记忆猜 CVE，而是检索已验证的利用事实。
- **代码主体用 sink-source 上下文**：SourceAgent 规划外部可控输入（HTTP 参数、Header、上传、反序列化入口等），SinkAgent 规划危险调用（模板渲染、命令执行、反序列化、SQL、JNDI 等）；ResearchAgent 生成约束条件与验证计划；CPGAgent 用 Joern MCP 构建代码属性图，产出数据流/控制流；DataflowAgent 逐跳追踪并验证约束（是否可达、是否有 sanitizer、前置条件是否默认满足），最终由人工确认有效路径。
- **为什么要 CPG + PoC**：LLM 单独判断“看起来像漏洞”误报很高；代码属性图把调用/数据依赖显式化，能验证 source 到 sink 的真实路径；PoC 进一步证明可达性与可利用性。原子 Agent 职责单一、知识域受限，能压缩推理不确定性、抑制幻觉。
- **人机边界**：AI 负责提出候选、构建上下文、追踪数据流与生成 PoC；是否成立、危害如何由人工复核。文章将其表述为“AI 是副驾驶，不是飞行员”。

## 触发条件

- 有授权的代码审计/漏洞挖掘目标，能获取源码、构建文件、配置与依赖清单。
- 有 LLM/Agent 编排环境，以及 Joern 等 CPG 工具（MCP 方式接入更便于 Agent 调用）。
- 目标可构建或在隔离环境可复现，用于 PoC 验证。
- 有安全工程师做最终复核；接受“AI 出候选、人做判断”的流程。
- 项目具备一定规模，单靠人工通读成本高；小项目直接用人工审计可能更高效。

## 利用步骤

1. **四维盘点**：整理配置项（xml/json/yaml/nginx.conf/Configuration.java）、语言与版本/环境变量、代码主体（入口与危险调用）、依赖清单（含版本）。
2. **配置维度（ConfSafeAgent）**：多格式配置归一化为统一 JSON → 正则 + LLM 语义切分识别非常规配置 → LLM 做风险识别与等级划分 → 输出风险项（如 Shiro anon 路径、暴露的 Hessian Servlet、硬编码密钥）→ 人工复核。
3. **依赖维度（LibSafeAgent）**：提取带版本依赖 → LibResolverAgent 还原依赖树并分类 → KnowledgeAgent 收集 CVE/补丁/PoC 构建 RAG → VulnEnvAgent 搭建复现环境 → PoCBuilderAgent 构造并验证 PoC → 输出带 PoC 的 sink 清单。
4. **语言维度（LangSafeAgent）**：按语言与版本构建高危函数知识图谱（危险 API、触发条件、版本差异），作为 sink 规划的输入。
5. **代码维度（MainAgent）**：SourceAgent/SinkAgent 分别产出 source/sink 规则；ResearchAgent 结合前三个维度生成约束条件与验证计划；CPGAgent 用 Joern MCP 构建数据流/控制流；DataflowAgent 逐跳追踪 source→sink 并验证 sanitizer、可达性与前置条件。
6. **PoC 与复核**：对候选路径做 PoC 变形与验证；人工核对行号、参数可控性、认证/配置前提，剔除 AI 编造或不可达的路径。
7. **闭环**：把确认的漏洞、配置错误、依赖 CVE 与 PoC 回流到知识库/规则，供下一轮挖掘复用。

## PoC

配置风险归一化输出的示意（ConfSafeAgent 风格）：

```json
{
  "file": "src/main/resources/beans/beans-security.xml",
  "type": "bean",
  "risk": "critical",
  "finding": "Shiro filterChainDefinitions 将敏感接口配置为 anon",
  "evidence": "<bean id=\"shiroFilter\" class=\"org.apache.shiro.spring.web.ShiroFilterFactoryBean\"> ... </bean>"
}
```

```json
{
  "file": "src/main/webapp/WEB-INF/web.xml",
  "type": "servlet",
  "risk": "critical",
  "finding": "Hessian DispatcherServlet 暴露且无访问控制",
  "evidence": "<servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>"
}
```

代码路径验证的示意：

```text
HTTP 参数 templateContent
  -> Controller 接收（source）
  -> FreeMarkerUtils.generateStringByString(templateContent, ...)（sink）
  -> CPG 数据流确认无 sanitizer、分支可达
  -> 构造模板内容 PoC 验证
```

说明：以上为架构与输出形态示意，不对应可直接执行的漏洞利用；实际 Agent 提示词、Joern 查询与 PoC 需按项目实现。

## 变体与关联

- 变体：配置维度可扩展到权限注解、Actuator 暴露、CORS、日志/调试开关、云密钥与环境变量；依赖维度可扩展到容器镜像、前端 npm 包、系统库。
- 变体：代码维度可用 CodeQL/Semgrep 作为候选种子，再由 Agent 做语义可达性判断；或用 Tabby 等 CPG 工具挖 gadget 链。
- 变体：没有 Joern 时，可退化为“LLM + 逐跳 grep/read 证据卡”的轻量流程，但可达性与 sanitizer 判断的可靠性下降。
- 关联：[[code-analysis-vuln-discovery-multi-agent-adversarial-pipeline]]（Finder/Refuter/Reproducer 对抗式流水线，强调证伪与证据卡）、[[code-analysis-vuln-discovery-tabby-cpg-gadget-chain-mining]]（代码属性图挖 Java gadget 链）、[[code-analysis-vuln-discovery-llm-sast-vulnhuntr-python-audit-pipeline]]（LLM SAST 审计流水线）、[[code-analysis-source-audit-ai-sast-java-gadget-chain-mining]]（AI 辅助 Java gadget 链挖掘）。
- 边界：项目过大/依赖缺失导致 CPG 不完整、配置格式无法归一化、PoC 环境无法搭建、人工复核缺位时，误报与漏报都会上升；该方法论本身不产生可直接利用的漏洞。

## 检测与防御

- 对防守方：AI 驱动的 1Day 挖掘会显著缩短“补丁发布 → 扫描 → 利用”的窗口；应及时修补依赖 CVE、清理默认/错误配置（Shiro anon、暴露的 Hessian/Servlet、Actuator）、收敛外部入口、启用最小权限与网络隔离。
- 对建设方：原子 Agent 职责单一、输出必须带文件/行号与可复现证据；用 CPG 与 PoC 做机器闸门；人工复核最终成立与否；把确认结果与误报回流知识库。
- 检测 AI 扫描流量：短时间内大量请求探测配置端点、模板参数、反序列化入口；同一来源对多个 path/参数做系统性枚举；结合 WAF/网关日志与依赖清单做资产-漏洞匹配。
- 治理：AI 挖掘仅在授权范围与隔离环境内进行；PoC 不得直接打生产；敏感配置与密钥不进入模型上下文。
