---
id: code-analysis-sast-codeql-custom-taint-steps
title: CodeQL Java 默认污点传播缺失的补充：TaintPreservingCallable 与 dataExtensions 库模型
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: codeql-java-custom-taint-steps
aliases:
- CodeQL 污点传播补全
- TaintPreservingCallable 自定义
- dataExtensions summaryModel
- CodeQL SSRF 漏报
- String.valueOf 污点断链
- okhttp2 模型缺失
tags:
- codeql
- sast
- taint-tracking
- dataflow
- taint-preserving-callable
- data-extensions
- java
- ssrf
- false-negative
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V15
  verified_at: '2026-11-05T01:48:06+08:00'
  notes: 已对照原文与全部12张图核对：图01-06 支撑 TaintTracking::Global/AddTaintDefaults/defaultAdditionalTaintStep/AdditionalTaintStep 机制；图07/08/09 支撑 String.valueOf returnsTaintFrom 与六个传播场景测试；图10 为 okhttp3/java.net 模型格式与 kind=taint；图11 显示官方 SSRF 只报 3 个结果（对应 1/4/5）；图12 为 okhttp2 用例源码。原文实验环境为 CodeQL V2.22.1，属工具版本而非受影响范围，未设 versions。卡片把模型 origin 从 ai-manual 写作 manual，不影响语义。未执行 CodeQL 查询；frontmatter 无 sources/source_url。
---

## 一句话结论

CodeQL Java 的 `TaintTracking::Global` 会自动叠加 `defaultAdditionalTaintStep`，但官方库模型并不完整；对 `String.valueOf` 这类会断链的 JDK 方法可用 `TaintPreservingCallable.returnsTaintFrom` 补传播，对 `com.squareup.okhttp` 这类缺模型的第三方库可用 `dataExtensions` 的 `summaryModel`/`sinkModel`（kind 必须是 `taint`）补全，从而检出原本漏报的 SSRF。

## 原理

- 自定义规则写 `module Flow = TaintTracking::Global<MyConfig>` 时，`TaintTracking::Global` 内部通过 `AddTaintDefaults` 把 `Config::isAdditionalFlowStep` 与 `defaultAdditionalTaintStep(node1, node2, model)` 合并；后者在 `TaintTrackingUtil.qll` 中实现，是 Java 默认污点步骤的来源。
- `localAdditionalTaintStep` 覆盖：
  - 表达式级：字符串拼接 `AddExpr`、`+=`、字符串模板、`&&`/`||`；
  - 调用级：构造函数、qualifier→方法返回值、参数→方法返回值（Base64、ResponseEntity、`TaintPreservingCallable` 等）、比较、序列化、格式化；
  - 更新级：qualifier→参数、参数→参数、参数→qualifier（`StringBuilder.append`、`System.arraycopy` 等）；
  - 容器内容与 `FlowSummaryImpl` 的库摘要。
- 但这些默认步骤只覆盖“已被建模”的 API。官方 SSRF 规则 `semmle.code.java.security.RequestForgery` 对 okhttp3 有 sink/summary 模型，对旧版 `com.squareup.okhttp` 没有；`java.lang.String.valueOf` 也没有参数→返回值传播。只要链路上有这两个断点，污点就传不到 sink，产生漏报。
- 补全方式一：继承 `TaintPreservingCallable`。`returnsTaintFrom(arg)` 控制返回值是否携带污点（`arg=-1` 表示 qualifier，`>=0` 表示第几个参数）；`transfersTaint(src, sink)` 控制参数/对象状态更新。把类写进 `propagate.qll` 并在查询中 `import propagate`，由于 `TaintTracking::Global` 会自动引入默认步骤，所有使用它的查询都会生效。
- 补全方式二：库模型 data extension。在 `ext/*.model.yml` 中给 `codeql/java-all` 添加 `sinkModel`（如 `OkHttpClient#newCall` 的 `Argument[0]` 为 `request-forgery`）与 `summaryModel`（如 `Request$Builder#url` 的 `Argument[0]` → `ReturnValue`、`build` 的 `Argument[this]` → `ReturnValue`），并在 `qlpack.yml` 的 `dataExtensions` 中引用。`kind` 必须写 `taint`，写 `value` 不会参与污点分析。
- 两种方式解决的是“规则覆盖不足”，不是漏洞本身；补完后仍可能有误报（如 `hashCode()` 这类不传播语义的方法被简单模型误判），需要配合 barrier/净化规则。

## 触发条件

- 使用 CodeQL Java 做代码审计，且目标代码走了未被官方模型覆盖的库/JDK API；
- 查询使用 `TaintTracking::Global<Config>`（若只用普通 `DataFlow::Global`，默认污点步骤不会自动加入）；
- 已知或怀疑存在漏洞，但官方查询未报（漏报），需要确认传播链在哪一步断掉；
- 有权限修改查询包（qlpack.yml）或添加 `.qll`/`.model.yml` 文件。

## 利用步骤

1. 用官方规则跑已知漏洞样本，记录未检出的用例（如 okhttp2 的 `newCall`、`String.valueOf(url)`）。
2. 阅读 `localAdditionalTaintStep` 与对应框架模型，确认缺失的是返回值传播、参数传播还是 sink 定义。
3. 对 JDK/通用方法，写 `TaintPreservingCallable` 子类放到 `propagate.qll`，在查询里 `import propagate`。
4. 对第三方库，写 `ext/<lib>.model.yml` 的 `sinkModel`/`summaryModel`，并在 `qlpack.yml` 增加 `dataExtensions: - ext/*.model.yml`。
5. 重跑查询，确认原先漏报的路径出现；再检查是否引入新的误报，必要时加 `isBarrier`。

## PoC

补 `String.valueOf` 的参数→返回值传播：

```ql
import java
import semmle.code.java.dataflow.FlowSources

private class StringValueOfCallable extends TaintPreservingCallable {
  StringValueOfCallable() {
    this.getDeclaringType().hasQualifiedName("java.lang", "String")
  }

  override predicate returnsTaintFrom(int arg) {
    this.hasName("valueOf") and arg = 0
  }
}
```

补 `com.squareup.okhttp` 的 SSRF sink 与 summary（`ext/com.squareup.okhttp.model.yml`）：

```yaml
extensions:
  - addsTo:
      pack: codeql/java-all
      extensible: sinkModel
    data:
      - ["com.squareup.okhttp", "OkHttpClient", True, "newCall", "(Request)", "", "Argument[0]", "request-forgery", "manual"]
      - ["com.squareup.okhttp", "OkHttpClient", True, "newWebSocket", "(Request,WebSocketListener)", "", "Argument[0]", "request-forgery", "manual"]
  - addsTo:
      pack: codeql/java-all
      extensible: summaryModel
    data:
      - ["com.squareup.okhttp", "Request$Builder", True, "url", "", "", "Argument[0]", "ReturnValue", "taint", "manual"]
      - ["com.squareup.okhttp", "Request$Builder", True, "build", "()", "", "Argument[this]", "ReturnValue", "taint", "manual"]
```

在 `qlpack.yml` 引用：

```yaml
dataExtensions:
  - ext/*.model.yml
```

测试代码关键片段：

```java
String result2 = String.valueOf(tainted);      // 补 returnsTaintFrom 前断链
sink("argToMethodStep", result2);

Request request = new com.squareup.okhttp.Request.Builder()
    .get().url(new URL(imageUrl)).build();     // 补 sinkModel 前 SSRF 漏报
client.newCall(request).execute();
```

原文实测：官方 SSRF 规则只报 1/4/5 三个用例；补 `String.valueOf` 传播后能报出用例 2；补 okhttp2 模型后可覆盖 `/three` 的 SSRF。用例 6（`hashCode()` 被当传播）仍是误报。

## 变体与关联

- 变体：继承 `AdditionalTaintStep` 写一次性步骤；或在 `ConfigSig.isAdditionalFlowStep` 中写查询局部步骤。
- 变体：用 `transfersTaint(src, sink)` 补集合 `add`/`set` 等“参数污染调用对象”的更新流。
- 变体：先检查官方 `semmle.code.java.frameworks.*` 是否已有模型，避免重复实现；库模型方式更适合大规模第三方 SDK。
- 关联：[[code-analysis-sast-codeql-isbarrier-parameterized-simple-type]]（用 `isBarrier` 消除误报；与本卡“补漏报”互补）。
- 边界：仅对使用 `TaintTracking::Global` 的查询生效；模型 name/signature 必须与目标库版本匹配；补全后可能引入误报，需要配套净化/barrier 规则。

## 检测与防御

- 本卡是 SAST 规则建设/审计方法，不针对具体受害者；从防御方角度：
- 检测：用带已知漏洞的基准项目回归查询，统计漏报/误报；对比官方模型覆盖与业务依赖库。
- 防御：在查询包中维护自定义 `propagate.qll` 与 `ext/*.model.yml`，版本化管理；升级 CodeQL 时回归模型签名。
- 加固：对模型补充做代码评审，避免过度传播导致大量误报；结合 `isBarrier`、`isSanitizer` 与人工复核。
