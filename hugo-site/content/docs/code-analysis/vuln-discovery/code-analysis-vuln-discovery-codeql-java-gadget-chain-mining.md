---
id: code-analysis-vuln-discovery-codeql-java-gadget-chain-mining
title: 用 CodeQL 从 sink 逐段反查挖掘 Java 反序列化 gadget 链
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery
technique: codeql-java-gadget-chain-mining
tags:
- java
- deserialization
- gadget
- codeql
- static-analysis
- vulnerability-discovery
- commons-collections
- semmle
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V20
  verified_at: '2026-11-05T02:18:11+08:00'
  notes: 已通读原文并逐张核对11张图：图01 InvokeCall.ql 在 3.2.1 命中 InvokerTransformer/PrototypeCloneFactory，图04 Transformer 实现类命中 ChainedTransformer/ConstantTransformer，图07 非 transform 调用者命中 LazyMap.get/TransformedMap.checkSetValue，图09 Map.get 调用点命中 AnnotationInvocationHandler.invoke/readObject，图10/11 人工补全动态代理与 entrySet 触发；卡内四段精简 QL 与原文思路一致并说明超长查询未收录、静态分析与人工验证边界。属方法论卡，原文演示完整挖掘流程，非未打通链。无版本/CVE；PoC 未在本机运行 CodeQL；frontmatter 无 sources/source_url。
url: /docs/code-analysis/vuln-discovery/code-analysis-vuln-discovery-codeql-java-gadget-chain-mining/
draft: false
kb_aliases:
- CodeQL 挖 CC 链
- CodeQL java gadget chain
- CodeQL 反序列化链挖掘
- CodeQL Method.invoke 反查
- 静态分析复现 CC1
---

## 一句话结论

对目标源码（如 commons-collections 3.2.1）和 JDK 建立 CodeQL Java 数据库，从 `Method.invoke` 这类 sink 出发，按“每个参与类都必须实现 `Serializable`”的约束逐段反查调用者（sink 调用者 → Transformer 聚合实现 → `transform` 的零参/内部调用者 → `Map.get` 调用者 → `readObject`），可以在不预先知道完整链的情况下系统复现并发现 Java 原生反序列化 gadget 链；原文用该方法重新拼出了 CC1 的 LazyMap + 动态代理版本。

## 原理

- **反序列化链的静态形状**：一条可用链是从 `readObject`（或 `hashCode`/`equals`/`toString` 等反序列化后会调用的方法）到危险 sink 的调用序列，且路径上每个参与对象都必须能出现在序列化流中——即类需实现 `java.io.Serializable`（或通过父类/`writeReplace` 可达）。因此把“`hasSupertype(Serializable)`”作为每段查询的硬约束，能过滤绝大多数无关调用。
- **CodeQL 的表达能力**：CodeQL 的 Java 库把 AST、类型、调用目标、继承关系建成数据库；`MethodCall.getMethod().getDeclaringType().hasQualifiedName(...)` 可精确锁定调用的是哪个类的方法，`getEnclosingCallable().getDeclaringType()` 可回到调用点所在的方法/类，`RefType.hasSupertype()` 做 Serializable 判定。这使“从 sink 反向问谁调用了它”变成一条声明式查询，而不是全文搜索。
- **逐段反查而不是正向搜索**：链的每一跳都是“某个可序列化类的方法调用了下一跳的方法”。先定 sink（`Method.invoke`），查它的可序列化调用者；再对“能被串起来的接口”（`Transformer`）查实现类中把多个 `transform` 串起来的聚合器（`ChainedTransformer`）；再查非 `transform` 方法中对 `Transformer.transform` 的调用（`LazyMap.get`、`TransformedMap.checkSetValue` 等）；最后查可序列化类中单参数 `Map.get` 的调用点，落到 `AnnotationInvocationHandler.invoke`/`readObject`。每步只保留可序列化类，链自然收敛。
- **为什么必须结合人工判断**：静态调用图不建模反射、动态代理与运行时分派，`Method.invoke` 的“目标方法”在静态上未知；CodeQL 只能告诉你“这里可能进入反射”，参数可控性和实际分派仍需回读源码。动态代理触发（`AnnotationInvocationHandler.invoke` 被 `Proxy` 调用）也不会出现在直接调用边里，需要人工补上。
- **局限**：需要可构建或可反编译的代码与完整 classpath（缺 jar 漏边）；JDK 内部类需要单独建库；查询结果可能含大量候选，必须逐个确认参数可污染且对象可序列化。

## 触发条件

- 能获得目标应用及其依赖（或目标组件源码，如 commons-collections 3.2.1）并用 CodeQL 建立 Java 数据库；必要时对 JDK 单独建库以覆盖 `AnnotationInvocationHandler` 等 JDK 内部类。
- 构建失败时可退化为 `--build-mode=none`（只做源码抽取，不执行构建）；老版本 Commons Collections 可能需要 JDK 7 才能编译。
- 分析者已知至少一个 sink 候选（`Method.invoke`、`Runtime.exec`、`TemplatesImpl.newTransformer`、JNDI `lookup` 等）；未知时可按危险方法名枚举。
- 本方法只产出候选链，最终仍需人工确认可达性、参数可控性并在授权环境验证。

## 利用步骤

1. **建库**：对组件源码执行 `codeql database create cc_chains --language=java --source-root . --build-mode=none`；构建失败时先 `mvn clean install -DskipTests`，或换用组件支持的 JDK 版本。JDK 内部类另建一个数据库（或把 JDK 源码纳入同一数据库）。
2. **定 sink 并加可序列化约束**：查询所有 `java.lang.reflect.Method.invoke` 调用，且调用点所在类实现/继承 `Serializable`。CC 3.2.1 中命中 `InvokerTransformer`（以及较少用的 `PrototypeCloneFactory`）。
3. **找“能把多个操作串起来”的聚合类**：查询实现 `org.apache.commons.collections.Transformer`、且自身 `transform` 方法体内又调用 `Transformer.transform` 的类，命中 `ChainedTransformer`；同时可看到 `ConstantTransformer` 这类“忽略入参返回常量”的补链组件。
4. **向上找 transform 的调用者**：查询方法名不是 `transform`、方法体调用 `Transformer.transform`、且所在类可序列化的方法，命中 `LazyMap.get`、`TransformedMap.checkSetValue/transformKey/transformValue`、`DefaultedMap.get` 等候选。
5. **向上找 Map.get 的调用者**：查询单参数、限定符类型为 `java.util.Map`（接口而非具体实现）、所在类可序列化、且类中存在 `readObject` 的 `get` 调用，命中 `AnnotationInvocationHandler.invoke` 与 `readObject`。
6. **人工补全触发段**：`readObject` 中 `memberValues.entrySet()` 会进入动态代理；`invoke` 中 `memberValues.get(member)` 进入 LazyMap；把“外层 handler 的 memberValues = 代理、内层 handler 的 memberValues = LazyMap”拼起来，得到 CC1 LazyMap 链。
7. **验证**：回到源码确认字段可控、序列化可达，再构造 payload 在授权环境测试；不要仅凭查询命中判定可利用。

## PoC

```sql
// 1) sink：可序列化类中调用 Method.invoke
import java

class InvokeCall extends MethodCall {
  InvokeCall() {
    this.getMethod().getDeclaringType().hasQualifiedName("java.lang.reflect", "Method") and
    this.getMethod().getName() = "invoke"
  }
}

predicate isSerializable(RefType rt) {
  exists(RefType st |
    rt.hasSupertype(st) and
    st.hasQualifiedName("java.io", "Serializable"))
}

from InvokeCall ic
where isSerializable(ic.getEnclosingCallable().getDeclaringType())
select ic, ic.getEnclosingCallable().getDeclaringType()
```

```sql
// 2) 聚合器：实现 Transformer 且 transform 内再调 Transformer.transform
import java

class TransformerType extends RefType {
  TransformerType() {
    this.getASupertype*().hasQualifiedName("org.apache.commons.collections", "Transformer") and
    exists(Method m | m = this.getAMethod() and m.getName() = "transform")
  }
  Method getTransformMethod() { result = this.getAMethod() and result.getName() = "transform" }
}

from TransformerType t
select t, t.getTransformMethod()
```

```sql
// 3) 向上：非 transform 方法中调用 Transformer.transform 的可序列化类
// （每段为独立查询；isSerializable 谓词按第 1 段重复声明，或合并进同一 .ql 文件）
import java

from MethodCall mc, Method enclosing
where
  mc.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.collections", "Transformer") and
  mc.getMethod().getName() = "transform" and
  enclosing = mc.getEnclosingCallable() and
  enclosing.getName() != "transform" and
  isSerializable(enclosing.getDeclaringType())
select mc, enclosing, enclosing.getDeclaringType()
```

```sql
// 4) 向上：可序列化类中单参数 Map.get（配合类中是否存在 readObject 人工筛选）
import java
import semmle.code.java.Maps

from MethodCall mc, Method enclosing
where
  mc.getMethod().getName() = "get" and
  mc.getNumArgument() = 1 and
  mc.getQualifier().getType() instanceof MapType and
  enclosing = mc.getEnclosingCallable() and
  isSerializable(enclosing.getDeclaringType())
select mc, enclosing, enclosing.getDeclaringType()
```

```text
# 原文执行结果（截图）：第 1 步命中 InvokerTransformer / PrototypeCloneFactory；
# 第 2 步命中 ChainedTransformer（及 ConstantTransformer）；
# 第 3 步命中 LazyMap.get、TransformedMap.checkSetValue 等；
# 第 4 步在 AnnotationInvocationHandler 的 invoke/readObject 中命中 memberValues.get。
# 未执行：本 worker 未运行 CodeQL 或任何 PoC。
```

## 变体与关联

- 变体：把 sink 换成 `Runtime.exec`、`ProcessBuilder.start`、`TemplatesImpl.newTransformer`、`InitialContext.lookup`、`ClassLoader.defineClass`，即可用同一“sink → 调用者 → 可序列化”框架挖其他链。
- 变体：对 `hashCode`/`equals`/`toString` 做 source 反查（CC5/CC6/CC7 的触发点），或在 source 阶段直接查 `readObject` 方法体。
- 变体：改用代码属性图工具（Tabby/Neo4j）或 joern；思路相同，都是“调用边 + 类型/可序列化约束”的路径搜索。
- 关联：[[code-analysis-vuln-discovery-tabby-cpg-gadget-chain-mining]]（CPG/Cypher 版挖链）、[[web-java-deser-commonscollections-cc1-transformedmap]]、[[web-java-deser-commonscollections-cc1-lazymap-proxy]]（本文挖出的链）、[[code-analysis-sast-codeql-custom-taint-steps]]（CodeQL 自定义污点传播）。
- 边界：JDK 内部类、反射/动态代理、运行时生成类、缺失依赖 jar 都会让静态结果与真实可达性不一致；文章中的超长 Map 类型查询包含多处自定义谓词，直接复用前需按本机 CodeQL 版本编译修正。

## 检测与防御

- 本方法用于授权的漏洞研究/代码审计，本身不产生危害。
- 防御侧：消除不可信 Java 原生反序列化；部署 JEP 290 `ObjectInputFilter` 白名单；升级存在已知 gadget 的组件（Commons Collections 3.2.2+）；监控反序列化后出现的反射调用链与子进程。
- 工程侧：CI 中可把 CodeQL 的“可序列化类中的反射调用/危险 sink”查询固化为审计规则，提前发现新增的自研 gadget。
