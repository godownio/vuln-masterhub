---
id: code-analysis-vuln-discovery-codeql-pathproblem-taint-gadget-chain-mining
title: 用 CodeQL path-problem + DataFlow 污点传播挖掘「反序列化→二次反序列化」gadget 桥链
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery
technique: codeql-pathproblem-taint-secondary-deser-bridge-mining
tags:
- codeql
- java
- static-analysis
- gadget-chain
- taint-tracking
- path-problem
- deserialization
- secondary-deserialization
- dynamic-proxy
- vulnerability-discovery
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-1
  verified_at: '2026-11-07T21:36:29+08:00'
  notes: 已对照原文核对：@kind path-problem 的 polyCalls 传递闭包枚举、只查 sink 规则（ReflectUtil.newInstance/IoUtil.readObj）、DataFlow::ConfigSig + isAdditionalFlowStep 全局污点传播（img09/10 路径 MapProxy:122→Convert→BeanConverter:92→ObjectUtil/SerializeUtil）、335 条接口 getter 查询与带 setter/public field 的 Bean 条件筛选均与 content.md 一致；为完整可复用的漏洞挖掘方法论（非未打通的利用链），路径合法，dedup 非同链、dup-scan 无 pair；未验证点：未在本机运行 CodeQL，该批次卡按 KB 现状不含 sources/source_url 溯源字段。
url: /docs/code-analysis/vuln-discovery/code-analysis-vuln-discovery-codeql-pathproblem-taint-gadget-chain-mining/
draft: false
kb_aliases:
- CodeQL path-problem 挖 gadget 链
- CodeQL DataFlow::ConfigSig
- polyCalls 传递闭包
- 二次反序列化 sink 挖掘
- InvocationHandler.invoke 污点传播
- getter/toString source 查询
---

## 一句话结论

对目标 jar（反编译源码）建立 CodeQL Java 数据库后，先用 `@kind path-problem` 的调用图传递闭包（可序列化类的 getter/toString 为 source，`readObject`/单参 `newInstance`/`Context.lookup` 为 sink，`edges+ = polyCalls`）批量枚举候选入口链，再用 `DataFlow::ConfigSig` 自定义污点传播（source = `InvocationHandler.invoke` 参数，sink = `IoUtil.readObj`/`ReflectUtil.newInstance` 参数，`isAdditionalFlowStep` 把 invoke 参数连到内部调用实参与返回值）确认参数可达二次反序列化，最后用辅助 QL 筛出「带 setter/public field 的无参 getter」确定动态代理可用的 Bean 返回类型，从而系统化挖出「Fury 反序列化 → Hutool MapProxy → 二次原生反序列化」这类桥链。

## 原理

- **候选链的形状 = 调用图可达性 + 可序列化约束**：一条可用反序列化链是从反序列化阶段会被调用的方法（`readObject`/`hashCode`/`equals`/`toString`/getter）到危险 sink 的调用序列。CodeQL 把类继承、方法调用目标建成数据库，用 `edges+(source, sink)`（`polyCalls` 的传递闭包）即可一次性求出「哪些入口方法能调到 sink」，不必逐段手写独立查询。
- **source/sink 的定义要贴目标场景**：source 取「实现/继承 Serializable 的类中，`get`/`set` 开头且无参的公开方法或 `toString`」——因为反序列化后最常被自动调用的就是 getter/toString；sink 取 `Context.lookup`（JNDI）、`readObject`（二次反序列化）、单参 `newInstance`（任意构造）这三类「能造成最终危害」的调用点。
- **path-problem 只给可达性，不给可控性**：传递闭包会返回大量候选（如大量 `toString → BasicDynaClass.newInstance` 路径），其中很多类被黑名单封锁或参数不可控，必须二次筛选。因此再写一条只查 sink 的规则，排除已知被封的包（`not qualifiedName matches "com.feilong.lib%"`）、按依赖情况舍弃 JNDI（无 tomcat / JDK 版本未知），把候选收敛到 `ReflectUtil.newInstance` 与 `IoUtil.readObj` 两个高价值 sink。
- **污点传播证明参数可达**：`DataFlow::ConfigSig` 的 `isSource` 把 `InvocationHandler.invoke` 的参数设为污点源（动态代理被调用时方法/参数来自攻击者），`isSink` 把上述两方法调用的实参设为汇；关键在 `isAdditionalFlowStep`——由于 `MapProxy.invoke` 内部把参数转交给 `Convert.convert`、再把内部调用结果作为返回值，静态数据流默认不跨「方法参数 → 内部调用实参 → return 表达式」，必须手工补 step：`node1.asParameter() = containingMethod.getAParameter() and node2.asExpr() = innerCall.getAnArgument()`，以及 `node1.asExpr() = innerCall and node2.asExpr() = ReturnStmt.getResult()`。`TaintTracking::Global` 据此输出 20~22 步完整路径（MapProxy:122 → Convert → ConverterRegistry → AbstractConverter → BeanConverter:92 `byte[]` → ObjectUtil/SerializeUtil），证明「受控值」确实流到二次反序列化。
- **辅助 QL 定 Bean 条件**：桥链能否成立还取决于代理接口 getter 的返回类型能否让 `Convert` 落到 `BeanConverter`。用 `m.getName().matches("get%")/matches("is%")`、`hasNoParameters`、`not getReturnType().hasName("void")` 查接口 getter（约 335 条），再加「存在 `set`+后缀同名单参 setter」或「实现类有同名 public 字段」约束（`BeanUtil.isBean = hasSetter || hasPublicField`），筛出 `Dialect.getWrapper()` 这类可用 getter。
- **为什么必须分而治之**：把 `toString`/`readObject`/`invoke` 三类 source 写进同一条数据流规则会因候选爆炸、数据流图构建不出来；实用做法是「面向答案」先锁定最可能的入口（本例是动态代理 `invoke`）单独跑污点传播，再回读源码人工确认。

## 触发条件

- 能拿到目标应用及其依赖 jar（或反编译源码），并用 `codeql database create --language=java` 建库；构建失败可退化为 `--build-mode=none` 只做源码抽取。
- 分析者至少已知一类 sink 候选（`readObject`/`newInstance`/`lookup`），或能按危险方法名枚举。
- 规则需按目标裁剪：排除被黑名单封锁的包前缀、按实际依赖舍弃不可达 sink（如无 tomcat 时弃 JNDI）。
- 结果只是候选链：反射、动态代理、运行时分派不被静态调用图建模，必须人工回读源码并在授权环境构造 payload 验证。

## 利用步骤

1. **建库**：对反编译出的目标源码与依赖执行 `codeql database create <db> --language=java --source-root . --build-mode=none`。
2. **规则 1（path-problem 枚举）**：定义 `Serializable`（`getASupertype*() instanceof TypeSerializable`）；`GetSource` = 可序列化类中 `get`/`set` 开头、无参、公开或名为 `toString` 的方法；`GetSink` = 调用 `Context.lookup` / `readObject` / 单参 `newInstance` 的方法；`query predicate edges(Method a, Method b) { a.polyCalls(b) }`；`where edges+(source, sink) select ...`。结果大量指向 feilong `BasicDynaClass.newInstance`（CC3 式任意构造），但目标 `TrAXFilter` 在黑名单，此路废弃。
3. **规则 2（只找 sink）**：`GetSink` 只保留 `readObject` 与单参 `newInstance` 调用者，`not qualifiedName matches "com.feilong.lib%"`，弃用 `lookup`；44 条结果里筛出 `ReflectUtil.newInstance`、`IoUtil.readObj`。
4. **规则 3（DataFlow 污点传播）**：按上文 `DataFlow::ConfigSig` 定义 source/sink/`isAdditionalFlowStep`，`TaintTracking::Global` + `flowPath` 输出完整路径，确认 `MapProxy.invoke` 参数可达二次反序列化 sink。
5. **规则 4（接口 getter）**：查 `get%`/`is%`、无参、返回非 void 的接口方法，得到可用 getter 清单。
6. **规则 5（Bean 条件）**：在规则 4 结果上要求存在对应 `setXxx` 单参 setter 或实现类同名 public 字段，筛出能把 `byte[]` 送进 `BeanConverter` 的返回类型（如 `Dialect.getWrapper`）。
7. **人工验证**：回读源码确认 `fieldName` 截取、`ConverterRegistry` 查找、`BeanUtil.isBean` 判断，构造 payload 在授权环境验证；不要仅凭查询命中判定可利用。

## PoC

```ql
// 规则 1：@kind path-problem —— 调用图传递闭包枚举 source→sink
class Serializable extends Method {
  Serializable(){ this.getDeclaringType().getASupertype*() instanceof TypeSerializable }
}
class GetSource extends Serializable {
  GetSource(){
    ((this.getName().indexOf("get") = 0 or this.getName().indexOf("set") = 0)
      and this.hasNoParameters() and this.getName().length() > 3 and this.isPublic())
    or this.hasName("toString")
  }
}
class GetSink extends Serializable {
  GetSink(){ exists(MethodCall a |
      ( (a.getCallee().hasName("lookup") and a.getCallee().getDeclaringType().getASupertype*().hasQualifiedName("javax.naming","Context"))
        or a.getCallee().hasName("readObject")
        or (a.getCallee().hasName("newInstance") and a.getCallee().getNumberOfParameters() = 1) )
      and this = a.getCaller() ) }
}
query predicate edges(Method a, Method b){ a.polyCalls(b) }
from GetSource s, GetSink k where edges+(s, k) select s, s, k, "$@ to $@"
```

```ql
// 规则 3：DataFlow::ConfigSig —— invoke 参数 → 二次反序列化 sink
module C implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    exists(Method m | m.getName() = "invoke" and n.asParameter() = m.getAParameter()
      and m.getDeclaringType().(RefType).getASupertype*().hasQualifiedName("java.lang.reflect","InvocationHandler"))
  }
  predicate isSink(DataFlow::Node n) {
    exists(MethodCall mc | n.asExpr() = mc.getAnArgument() and
      ( (mc.getMethod().getDeclaringType().hasQualifiedName("cn.hutool.core.io","IoUtil") and mc.getMethod().getName()="readObj")
        or (mc.getMethod().getDeclaringType().hasQualifiedName("cn.hutool.core.util","ReflectUtil") and mc.getMethod().getName()="newInstance") )
      and not mc.getMethod().getDeclaringType().getPackage().getName().matches("com.feilong.lib%"))
  }
  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    exists(MethodCall inner, Method cm |
      inner.getEnclosingCallable() = cm and cm.getName() = "invoke" and
      ( (n1.asParameter() = cm.getAParameter() and n2.asExpr() = inner.getAnArgument())
        or (n1.asExpr() = inner and exists(ReturnStmt rs | rs.getEnclosingCallable() = cm and n2.asExpr() = rs.getResult())) ))
  }
}
module Flow = TaintTracking::Global<C>;
import Flow::PathGraph
from Flow::PathNode s, Flow::PathNode k where Flow::flowPath(s, k) select s.getNode(), s, k, "source to sink"
```

（按文章 QL 最小化整理，未在本机运行 CodeQL；路径结果为 MapProxy:122 → Convert → BeanConverter:92 → ObjectUtil/SerializeUtil。）

## 变体与关联

- 变体：sink 换成 `Runtime.exec`/`TemplatesImpl.newTransformer`/`defineClass` 可挖其它链；source 换成 `hashCode`/`equals`/`readObject` 挖其它触发点。
- 变体：把 `polyCalls` 传递闭包换成 CPG（Tabby/Neo4j）或用更多自定义 taint step 覆盖反射/动态代理；三个 source 不要写进同一条数据流规则（图过大构建失败）。
- 关联：[[code-analysis-vuln-discovery-codeql-java-gadget-chain-mining]]（逐段反查 + `Serializable` 硬约束挖 CC1 的方法；本卡是 path-problem 传递闭包 + 全局污点传播，针对二次反序列化/动态代理桥）、[[code-analysis-vuln-discovery-tabby-cpg-gadget-chain-mining]]（CPG/Cypher 版）、[[web-java-deser-resolveproxyclass-blacklist-hutool-mapproxy]]（本方法可挖出的 MapProxy 二次反序列化桥链）。
- 边界：缺依赖 jar、JDK 内部类、反射与动态代理分派都会让静态结果与真实可达性不一致；QL 语法随 CodeQL 版本需调整；查询命中不等于可利用。

## 检测与防御

- 授权漏洞研究/代码审计方法，本身不产生危害。
- 防御侧：CI 中固化「可序列化类中的 `readObject`/单参 `newInstance` 调用」「动态代理 `invoke` 参数是否流向二次反序列化 sink」查询，提前发现自研 gadget；消除不可信反序列化、部署 JEP 290 `ObjectInputFilter`、升级含已知 gadget 的组件。
- 工程侧：把黑名单 / 依赖版本清单与真实 classpath 对齐，避免只封常见类而漏掉第三方桥接类（本例 feilong/hutool 均未被封）。
