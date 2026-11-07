---
id: code-analysis-sast-codeql-active-threat-model-source-coverage
title: CodeQL 自定义 source 用 ActiveThreatModelSource，避免漏掉 ServletRequest.getParameter 等库模型源
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: codeql-active-threat-model-source-coverage
aliases:
- CodeQL source 覆盖差异
- ActiveThreatModelSource
- SpringRequestMappingParameter isTaintedInput
- CodeQL 库模型 source
- ServletRequest.getParameter source 漏报
tags:
- codeql
- sast
- java
- source
- threat-model
- spring
- servlet
- false-negative
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V14
  verified_at: '2026-11-05T01:45:55+08:00'
  notes: 已对照原文与可用4张图（02/04/05/06）核对；ActiveThreatModelSource与Spring isTaintedInput的5条vs3条差异、javax.servlet库模型getParameter/getReader标remote均一致；未运行CodeQL
---

## 一句话结论

自定义 CodeQL Java 查询时，把 source 定义为 `source instanceof ActiveThreatModelSource` 会同时纳入框架 source 与库模型中标记的 `ServletRequest.getParameter()` 等源；只写 `SpringRequestMappingParameter.isTaintedInput()` 会漏掉库模型 source，导致对直接调用 Servlet API 的 Controller 产生漏报。

## 原理

- `semmle.code.java.dataflow.FlowSources` 用抽象类 `SourceNode` 规定 source 范围，`ActiveThreatModelSource` 的构造条件是：当前威胁模型 `kind` 被启用，且节点的 `getThreatModel()` 等于该 kind，或 `sourceNode(this, kind)` 明确标记了它。
- `RemoteFlowSource` 把 `getThreatModel()` 固定为 `"remote"`；Spring 的 `SpringServletInputParameterSource` 把满足 `SpringRequestMappingParameter.isTaintedInput()` 的参数也归为 remote。
- 但 `ActiveThreatModelSource` 还包含“库模型”（library model）中通过 `sourceNode(this, kind)` 标记的源。CodeQL 的 `javax.servlet` 模型把 `ServletRequest.getParameter`、`getParameterMap`、`getParameterValues`、`getReader`、`getInputStream` 等返回值标为 remote。这些调用不是 `SpringRequestMappingParameter`，因此只按 Spring 参数定义 source 的查询看不到它们。
- 默认配置下 `currentThreatModel(kind)` 对未显式配置的 kind 回退到 `"all"`，因此远程、文件、数据库等威胁模型默认都参与，`ActiveThreatModelSource` 覆盖面最广。
- 反过来，`SpringRequestMappingParameter.isTaintedInput()` 的语义很细：显式 taint 包括 `InputStream`/`Reader`、`@RequestParam`/`@RequestHeader`/`@PathVariable`/`@RequestBody`/`@CookieValue`/`@RequestPart`/`@MatrixVariable` 等注解、`HttpEntity`、`@RequestAttribute`/`@SessionAttribute`；隐式 taint 把未被排除的简单类型当作 `@RequestParam`、复杂对象当作 `@ModelAttribute`；`ServletRequest`、`HttpSession`、`Principal`、`Model` 等框架对象被排除。它适合“按 Spring 参数建模”，但不能替代库模型的调用点 source。
- 之所以成立：source 建模分两层——框架参数级（Spring 注解）与库 API 调用级（Servlet 方法返回值）。两层互补，只用其中一层必然有一类输入被漏掉。

## 触发条件

- 使用 CodeQL 自写 Java 数据流查询，或修改官方查询的 `isSource`；
- 目标应用既有 Spring 注解参数，也直接调用 `ServletRequest.getParameter()` 等 Servlet API；
- 自定义 source 只写了 `SpringRequestMappingParameter.isTaintedInput()`，未使用 `ActiveThreatModelSource` 或未并入库模型 source；
- 威胁模型配置未启用对应 kind（如把 remote 关掉）。

## 利用步骤

1. 确认 CodeQL 版本与 `FlowSources` 库中 `ActiveThreatModelSource`、`RemoteFlowSource`、`SpringServletInputParameterSource` 的定义。
2. 检查官方查询：多数 `Security/CWE/*Query.qll` 的 `isSource` 使用 `ActiveThreatModelSource`。
3. 自写查询时优先沿用该定义；若需要收窄，至少把库模型 source 与框架 source 取并集。
4. 用同一份代码分别跑两种 source 定义，对比结果差异（如 `getParameter` 结果是否消失）。
5. 按 `codeql-config.yml` 的 `threat-models` 确认 remote/local/file/database 等 kind 的启用状态长期稳定。

## PoC

覆盖最广的定义（推荐）：

```ql
private import semmle.code.java.dataflow.FlowSources
predicate isSource(DataFlow::Node src) { src instanceof ActiveThreatModelSource }
```

仅按 Spring 参数建模（会漏 Servlet API 调用）：

```ql
predicate isSource(DataFlow::Node src) {
  src.asParameter() = any(SpringRequestMappingParameter p | p.isTaintedInput())
}
```

两者的差异样例：

```java
@PostMapping("/sendAuthCode")
public Result sendAuthCode(String mobile, HttpServletRequest request) {
    // 该值来自库模型 ServletRequest.getParameter，Spring 参数 source 看不到
    String nationcode = request.getParameter("nationcode");
    // ...
}
```

## 变体与关联

- 收窄变体：把 `ActiveThreatModelSource` 与 `srmp.isTaintedInput()` 取并集，或按 `getThreatModel()` 过滤 kind；不要只保留其中一层。
- 命名空间变体：官方/库模型常按 `javax.servlet` 建模，迁移到 `jakarta.servlet` 的应用可能出现匹配缺口，需要核对库模型是否覆盖新包名。
- 威胁模型变体：通过 `threat-models` 显式启用 `remote`、`local`、`file`、`database`、`commandargs` 等；关闭某 kind 会直接减少对应 source。
- 关联：[[code-analysis-sast-codeql-isbarrier-parameterized-simple-type]]（同一查询体系的净化流优化，与本卡的 source 覆盖互补）；[[web-python-ssti-jinja2-flask-globals-rce]]（source→sink 的实际漏洞形态）。
- 影响边界：本卡是 SAST 规则质量内容；source 覆盖不足造成漏报，过度覆盖造成误报，需用样本回归校准。

## 检测与防御（规则质量保障）

- 为每个框架入口维护样本：`@RequestParam`、`@RequestBody`、`@PathVariable`、`ServletRequest.getParameter`、`HttpServletRequest.getReader`、`@ModelAttribute`、被排除的 `HttpSession`/`Principal`。
- 对自定义 `isSource` 跑“正向应命中、负向不应命中”两套用例，变更后逐一核对。
- 升级 CodeQL 后复核 `FlowSources`/库模型变化，避免自定义查询与官方模型脱节。
