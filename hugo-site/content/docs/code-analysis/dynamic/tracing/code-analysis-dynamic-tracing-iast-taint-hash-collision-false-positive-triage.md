---
id: code-analysis-dynamic-tracing-iast-taint-hash-collision-false-positive-triage
title: DongTai IAST 误报定位：污点 hash 碰撞把常量标成可控，先回溯 source 节点
type: scenario
domain: code-analysis
path: code-analysis/dynamic/tracing
technique: iast-taint-hash-collision-false-positive-triage
tags:
- java
- iast
- dongtai
- taint-tracking
- false-positive
- sql-injection
- agent
- hash-collision
- debugging
- servlet
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V223
  verified_at: '2026-11-07T06:53:05+08:00'
  notes: 已对照原文及2张图（03、05）核对：图03 展示 DongTai 漏洞 graph 的 source invokeId/source hash 列表，图05 为 ServletRequest.getInputStream source 节点（callerLineNumber=66、policyType=source、sourceHash 数组、taintPosition source P0→R）与卡中 source 字段说明一致；文中 ArrayList 污点连带 "123"、StringBuilder.append(",") hash 碰撞导致 prepareStatement 误报、resolveArgument 过滤 ServletRequest、fat jar LaunchedURLClassLoader 与线程上下文类加载器均与卡一致。未验证点：属误报研判方法论非攻击链，未在本机复现；原文未给 DongTai agent 版本，未设 affected_versions；frontmatter无 sources/source_url。
url: /docs/code-analysis/dynamic/tracing/code-analysis-dynamic-tracing-iast-taint-hash-collision-false-positive-triage/
draft: false
kb_aliases:
- DongTai IAST 误报
- 洞态 IAST 误报
- 污点 hash 碰撞
- taint hash collision
- source 节点回溯
- StringBuilder append 误报
- ServletRequest.getInputStream 污点泛滥
---

## 一句话结论

基于方法 hook + 污点 hash 池的 IAST（如 DongTai Java agent）在 SQL 注入等告警上出现误报时，根因多数在 source 端而不是 sink：source 把整个请求对象/集合标记为污点后，后续 `StringBuilder.append(",")` 这类常量拼接会因 hash 命中已污染的值而被整体视为可控，最终在 `prepareStatement` 等 sink 上报漏洞；研判时优先回溯调用链最上游的 source 节点（常见于 filter/AOP 中的 `ServletRequest.getInputStream()`、`getHeaders()`）。

## 原理

- IAST agent 在运行时 hook source、propagator、sink 三类方法，用对象/值的 hash（如 `TAINT_HASH_CODES`、`TAINT_RANGES_POOL`）记录污点传播范围；传播与命中判断依赖 hash 是否一致或范围是否重叠。
- source hook 经常把整个请求对象、参数集合、输入流作为污点载体：一个 `HttpServletRequest`、`ServletInputStream`、数组或 `ArrayList` 中可能包含 `,`、`'`、`+`、`(`、`)` 等大量字符及其 hash。
- 当业务代码对没有任何外部输入的数据执行 `sb.append(",")` 时，`,` 的 hash 若与污点池中的某个值碰撞/重叠，这个常量也会被标记为污点；随后整个 `StringBuilder` 在传播中被视为可控，走到 `java.sql.Connection.prepareStatement(String)` 等 sink 即产生 SQL 注入误报。
- 文章给出的最小机制示例：入参 `name` 被加入 `ArrayList a` 后整个 `a` 成为污点，迭代器 `b.next()` 取出的常量 `"123"` 因同一对象/范围被连带标记，`new File("123").getName()` 的返回值也被认为可控。这类“污点范围过大 + hash 命中”是大部分误报的成因。
- 因此，若告警链路中的 sink 参数完全由固定 SQL 和常量拼接而成，应优先怀疑 source 选取过宽或 propagator 的 hash 范围处理，而不是继续审计 sink。

## 触发条件

- 使用 DongTai IAST Java agent，或其他按 hash 池做污点传播的 IAST 实现；不同版本对 hash 范围的处理可能不同。
- 业务代码存在字符串拼接后进入 SQL/命令/文件/表达式等 sink 的路径，即使拼接内容全是常量，或最终使用的是 `PreparedStatement`。
- 请求链路中存在 filter/AOP/参数解析器频繁读取 `HttpServletRequest`（`getInputStream()`、`getHeaders()`、`getParameter()` 等），或 controller 方法签名里直接带 `HttpServletRequest` 参数，导致 source 携带大量无关值。
- 复现环境差异：Spring Boot fat jar（`java -jar`）下业务类由 `LaunchedURLClassLoader` 加载，而 agent 挂在 `AppClassLoader` 下；若 agent 用默认类加载器 `Class.forName` 查业务类，会找不到类，导致本地 IDE 复现与线上行为不一致。

## 利用步骤

1. 在 IAST 平台打开告警的污点调用链，先读最上游 source 节点的关键字段：`class`/`className`、`signature`、`callerClass`、`callerMethod`、`callerLineNumber`、`sourceValues`、`targetValues`，判断 source 是否把整个 request/集合/输入流都纳入了污点。
2. 沿链路检查 propagator 节点与 sink 节点，确认 sink 参数是否真的可由外部输入控制；若 SQL 文本来自常量拼接、参数走 `setString`，高度怀疑 hash 碰撞。
3. 回到业务代码，定位链路中可疑的 `append`/`concat` 常量（如 `","`、`"("`、`" and nSchoolId = ?"`），确认该常量是否可能落入污点池并被传播到 sink。
4. 本地无法稳定复现时改用远程 debug：启动参数追加 `-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005` 与 `-javaagent:/path/dongtai-agent.jar`，IDEA 远程连接后在 source hook/propagator 处断点，观察污点 hash 与范围。
5. 若 agent 侧存在按类名过滤 source 的逻辑（例如跳过 `ServletRequest` 类型的 `resolveArgument` 参数），确认它是否真的生效；涉及加载业务类时使用线程上下文类加载器：`Class.forName(name, true, Thread.currentThread().getContextClassLoader())`，否则 fat jar 场景下过滤逻辑会静默失效。
6. 确认是常量被连带污染后按误报处置，不修改业务；把 source 节点位置（多为 filter/AOP）和碰撞值反馈给 agent 维护方或加入排除规则。

## PoC

无利用 PoC；以下为最小误报演示代码。

```java
@RequestMapping("/iast17")
public String iast17(@RequestParam("name") String name) {
    ArrayList<String> a = new ArrayList<>();
    a.add("123");
    a.add(name);                  // 整个 a 被标记为污点
    Iterator<String> b = a.iterator();
    System.out.println(b.next()); // 常量 "123" 可能被连带标记
    System.out.println(b.next());
    File f = new File("123");
    return f.getName();           // 常量返回值被判为可控，产生误报
}
```

SQL 场景中，`StringBuilder sb = new StringBuilder(FIXED_SQL)`，循环里只 `sb.append(",")`、`sb.append(" ?")`，最后 `connection.prepareStatement(sb.toString())`；`sb` 没有任何外部输入却命中 sink，即为同一类误报。

## 变体与关联

- **source 变体**：`javax.servlet.ServletRequest.getInputStream()` 在 filter 中最常见，可一次携带大量污点值；`HttpServletRequest.getHeaders()` 会把 header 枚举对象及其中内容全部纳入；Spring MVC `resolveArgument` 处理 `HttpServletRequest` 参数时也会扩大 source。
- **agent 侧过滤**：通过在 `resolveArgument` 事件中用 `javax.servlet.ServletRequest.isAssignableFrom(getParameterType())` 判断并跳过，可减少无关 source，但受类加载器隔离影响可能不生效，且对高版本 Servlet 未必兼容。
- **关联**：SAST 侧同样存在 source 过宽/污点模型缺失导致的误报与漏报，可参考 CodeQL 的 source 覆盖、`summaryModel` 与 `isBarrier` 相关卡片。
- **局限**：hash 碰撞属于 IAST 实现细节，不同 agent 版本可能已修复或改变；本卡描述的是特定版本文章的观察结果，实际研判需以目标版本调用链为准。

## 检测与防御

- **告警研判**：先看 source 再看 sink；source 为 request/输入流/header 枚举、sink 参数由常量拼接产生时，优先判误报并记录碰撞位置。
- **工程修复**：SQL 全量参数化，避免把常量拼接结果与用户输入混在同一 `StringBuilder`；不要把 `HttpServletRequest` 传入服务层或 DAO 层。
- **agent 运维**：跟踪 IAST agent 版本与规则更新，对 filter/AOP 入口配置 source 排除或降噪；fat jar 环境验证过滤逻辑是否实际生效。
- **本卡性质**：属于 IAST 误报分析/调试方法论，不是攻击面；防御重点在于降低误报噪音、避免真实漏洞被误报淹没，同时不因降噪放过真实污点链。
