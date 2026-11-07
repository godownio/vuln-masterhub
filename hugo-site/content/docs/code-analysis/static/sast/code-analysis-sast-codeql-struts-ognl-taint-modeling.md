---
id: code-analysis-sast-codeql-struts-ognl-taint-modeling
title: CodeQL 追踪 Struts OGNL 注入：ActionProxy source、OgnlUtil sink 与字段跨函数污点桥接
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: codeql-struts-ognl-taint-modeling
tags:
- codeql
- sast
- java
- struts2
- ognl
- taint-tracking
- dataflow
- false-positive
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V23
  verified_at: '2026-11-05T02:36:10+08:00'
  notes: 已对照原文核对；DataFlow::Configuration 骨架、isAdditionalFlowStep 字段赋值/读取桥接、ValueStackShadowMap/ActionMapping::toString barrier、path-problem/Path Explorer 流程均与原文一致；卡内已注明原文无完整 .ql 与运行命令、未在本机运行 CodeQL。
url: /docs/code-analysis/static/sast/code-analysis-sast-codeql-struts-ognl-taint-modeling/
draft: false
kb_aliases:
- CodeQL Struts OGNL 建模
- ActionProxyGetMethod
- OgnlUtil sink 定义
- isAdditionalFlowStep 字段传播
- CodeQL 多态误报 barrier
- ValueStackShadowMap 误报
- CodeQL path-problem
---

## 一句话结论

用 CodeQL 挖 Struts2 OGNL 注入时，把 `ActionProxy.getMethod()/getNamespace()/getActionName()` 定义为 source，把 `OgnlUtil.compileAndExecute()` 定义为 sink；由于污点常经由成员变量跨函数传递而默认数据流跟丢，需要重写 `isAdditionalFlowStep`，用“同一类中字段赋值→字段读取”补一条传播边；再用 `isBarrier` 斩断 Java 多态造成的“理论可达、实际不可能”的误报路径，最后用 `path-problem` 和 Path Explorer 逐跳验证。

## 原理

- **Source**：`ActionProxy` 的 `getMethod()`、`getNamespace()`、`getActionName()` 都从请求 URL 解析路由信息，属于不可信输入。把它们打包成 `ActionProxyGetMethod` 类，可同时覆盖历史漏洞与后续变体。
- **Sink**：表面的 `OgnlUtil.getValue()` 与 `TextParseUtil.translateVariables()` 不是稳定汇聚点（不同版本/补丁会替换 API）。真正无保护的底层是 `OgnlUtil.compileAndExecute()`：其第一个参数 `ma.getArgument(0)` 进入 OGNL 编译执行。`compileAndExecuteMethod()` 一度也是 sink，但补丁在其中加入 `checkSimpleMethod()` 过滤后应将其移出 sink 名单，否则旧漏洞会持续误报。
- **默认数据流为何会断**：CodeQL 的默认污点传播主要跟踪同一方法内的赋值、拼接等。Struts 中脏数据经常先写入某对象的成员变量，再在同类或父类的另一个方法中读出；默认引擎看不到“字段赋值→字段读取”这条边，链就断了。
- **isAdditionalFlowStep 桥接**：在配置中增加一条额外传播规则：
  ```ql
  exists(Field f, RefType t |
      node1.asExpr() = f.getAnAssignedValue() and
      node2.asExpr() = f.getAnAccess() and
      node1.asExpr().getEnclosingCallable().getDeclaringType() = t and
      node2.asExpr().getEnclosingCallable().getDeclaringType() = t
  )
  ```
  含义是：只要同一类 `t` 的成员变量 `f` 被写入（`node1`），又在同类中被读取（`node2`），就承认污点从写入点传到读取点。配合 `TaintTracking::localTaintStep(node1, node2)` 覆盖同方法内的拼接/类型转换，可把跨函数字段流补上。
- **多态误报**：CodeQL 按接口/父类静态类型连边。例如 `pkg.getActionConfigs().get(chainedTo)` 的返回类型是 `Map`，工具会连到实现了 `Map` 的 `ValueStackShadowMap.get()`；该方法在取不到值时会调用 `valueStack.findValue((String) key)`，而 `findValue` 会把 key 当 OGNL 解析，看起来是一条完美 RCE 链。但实际运行时 `getActionConfigs()` 返回的实例根本不可能是这个第三方插件类，因此是“静态可达、运行时不可达”的假阳性。
- **isBarrier 去噪**：对确认不可能到达的类/方法写屏障，例如：
  ```ql
  override predicate isBarrier(DataFlow::Node node) {
    exists(Method m |
      (m.hasName("get") or m.hasName("containsKey")) and
      m.getDeclaringType().hasName("ValueStackShadowMap") and
      node.getEnclosingCallable() = m
    )
  }
  ```
  同理把 `ActionMapping::toString()` 以及单元测试代码加入 barrier，可将数百条噪声收敛到个位数真实路径。
- **path-problem 验证**：把查询改成 `path-problem` 模式，用 VS Code CodeQL 插件的 Path Explorer 逐步查看 source→中间变量→sink 的每一跳；对每一跳回读源码，确认实际类型、参数可控性和是否被 sanitizer 拦截。

## 触发条件

- 能获取目标 Struts2 源码/依赖并建立 CodeQL Java 数据库。
- 使用支持自定义 source/sink 的 CodeQL Java 查询（旧版 `DataFlow::Configuration` 或新版 `TaintTracking::Global`）。
- 目标代码存在经由成员变量/继承链传递的污点，且默认 dataflow 跟丢。
- 分析者愿意人工核验多态路径的实际实例类型，而不是直接采信查询结果。

## 利用步骤

1. 建库并对 Struts2 核心源码运行基础查询，先定义 source 集合（`ActionProxy` 的三个 getter）与 sink 集合（`OgnlUtil.compileAndExecute`）。
2. 跑一遍，观察结果是否只覆盖历史漏洞或出现大量旧漏洞误报。
3. 对比补丁：确认 `compileAndExecuteMethod` 是否已加入 `checkSimpleMethod`；若是，将其从 sink 名单移除。
4. 若真实链因字段传递而漏报，加入 `isAdditionalFlowStep` 的字段赋值/读取规则，并保留 `localTaintStep`。
5. 把查询改为 `path-problem`，用 Path Explorer 查看每条链；对多态节点核对实际实例化类型。
6. 对确认的假阳性类/方法写 `isBarrier`/`isSanitizer`；把测试代码也加入 barrier。
7. 重跑，剩余少量结果逐条回读源码，确认 source 可控、sink 无净化，再在授权环境验证。

## PoC

核心查询骨架（原文旧版 CodeQL 语法）：

```ql
class OgnlTaintTrackingCfg extends DataFlow::Configuration {
  OgnlTaintTrackingCfg() { this = "mapping" }

  override predicate isSource(DataFlow::Node source) {
    isActionProxySource(source)
  }

  override predicate isSink(DataFlow::Node sink) {
    isOgnlSink(sink)
  }

  override predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    TaintTracking::localTaintStep(node1, node2) or
    exists(Field f, RefType t |
      node1.asExpr() = f.getAnAssignedValue() and
      node2.asExpr() = f.getAnAccess() and
      node1.asExpr().getEnclosingCallable().getDeclaringType() = t and
      node2.asExpr().getEnclosingCallable().getDeclaringType() = t
    )
  }
}

from OgnlTaintTrackingCfg cfg, DataFlow::Node source, DataFlow::Node sink
where cfg.hasFlow(source, sink)
select source, sink
```

多态误报 barrier：

```ql
override predicate isBarrier(DataFlow::Node node) {
  exists(Method m |
    (m.hasName("get") or m.hasName("containsKey")) and
    m.getDeclaringType().hasName("ValueStackShadowMap") and
    node.getEnclosingCallable() = m
  )
}
```

原文未给出可直接执行的完整 `.ql` 文件与 CodeQL 运行命令；以上为文中给出的关键片段。未在本机运行 CodeQL。

## 变体与关联

- 变体：把 source 换成其它框架中从请求解析路由/方法名的 getter；把 sink 换成 `ValueStack.findValue`、`Runtime.exec`、`Templating` 等。
- 变体：字段传播规则可扩展为“同类字段写入→任意读取”，或改用 `TaintPreservingCallable` / dataExtensions 建模（见关联卡）。
- 变体：多态误报也可通过收窄接收者类型（而不是加 barrier）解决；barrier 更快但需确认不会误伤真实路径。
- 关联：[[code-analysis-sast-codeql-custom-taint-steps]]（默认污点传播缺失的补全，TaintPreservingCallable/dataExtensions）。
- 关联：[[code-analysis-sast-codeql-isbarrier-parameterized-simple-type]]（isBarrier 的另一类用法：泛型净化）。
- 关联：[[code-analysis-vuln-discovery-codeql-java-gadget-chain-mining]]（同样用 CodeQL 做链式挖掘，但方向是从 sink 反查）。
- 关联：[[web-java-framework-struts2-actionproxy-ognl-injection]]（本方法定位到的漏洞本体）。

## 检测与防御

- 本卡是授权的代码审计/漏洞挖掘方法，不直接产生攻击效果。
- 规则质量：对 source/sink 变更维护正负样本回归；每加一个 barrier 都要确认不会截断真实链。
- 人工复核：多态连边必须核对运行时实际类型；Path Explorer 只证明静态可达，不证明可利用。
- 补丁对比：移除已被 sanitizer 保护的 sink，否则误报会淹没真实结果；同时关注修补后新增的替代 API（如 `callMethod`）是否仍流向无保护底层。
- 防御侧：修复 OGNL 注入本体（见关联卡），并在 CI 中固化“ActionProxy getter → OGNL sink”查询，防止回归。
