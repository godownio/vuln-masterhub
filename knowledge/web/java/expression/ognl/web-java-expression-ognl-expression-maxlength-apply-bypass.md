---
id: web-java-expression-ognl-expression-maxlength-apply-bypass
title: OGNL expressionMaxLength 长度限制绕过：@ognl.Ognl@applyExpressionMaxLength 覆盖静态上限
type: scenario
domain: web
path: web/java/expression/ognl
technique: ognl-apply-expression-max-length-bypass
aliases:
- expressionMaxLength
- applyExpressionMaxLength
- freezeExpressionMaxLength
- struts.ognl.expressionMaxLength
- OGNL 长度限制绕过
- Parsing blocked due to security reasons
tags:
- java
- ognl
- expression-injection
- waf-bypass
- struts2
- confluence
- security-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V520
  verified_at: '2026-11-11T13:13:35+08:00'
  notes: 已对照原文及截图核对：struts.xml struts.ognl.expressionMaxLength=200(图08)、parseExpression 超长抛 Parsing blocked due to security reasons(图04/05)、Ognl 静态字段声明(图06)、applyExpressionMaxLength 源码含 OgnlSecurityManager/frozen/负值校验(图07)、调用后字段变为 20000000(图09/10) 均一致；PoC 请求体与原文一致。原文未写组件受影响版本，cve 为空、不设 affected_versions 合理。与库内 OGNL 黑名单反射绕过/JShell 绕过为不同技巧，原子独立。未验证点：未在真实 OGNL 注入点复测。
---

## 一句话结论

较新的 OGNL/Struts2 用静态字段 `ognl.Ognl.expressionMaxLength` 限制表达式长度（原文截图：struts.xml 中 `struts.ognl.expressionMaxLength` 为 200，Confluence 8.5.1 默认 200、8.5.3 默认 150），超长即抛 `Parsing blocked due to security reasons`；但公开静态方法 `@ognl.Ognl@applyExpressionMaxLength(20000000)` 可以在 OGNL 表达式内部直接调用，把进程级上限改成任意值，之后超长 payload（如内存马 defineClass）即可被正常解析。

## 原理

- **限制点**：`Ognl.parseExpression(String)` 开头执行 `Integer currentExpressionMaxLength = expressionMaxLength;`，若非 null 且 `expression.length() > currentExpressionMaxLength`，直接抛 `OgnlException("Parsing blocked due to security reasons!", new SecurityException(...))`。字段声明为 `private static volatile Integer expressionMaxLength`，默认由配置注入（Struts2 的 `struts.ognl.expressionMaxLength`）。
- **可写入口**：同类还有 `public static synchronized void applyExpressionMaxLength(Integer expressionMaxLength)`，逻辑为：`System.getSecurityManager() instanceof OgnlSecurityManager` 时拒绝；`expressionMaxLengthFrozen` 为 true 时抛 `IllegalStateException`；参数为负时抛 `IllegalArgumentException`；否则直接执行 `Ognl.expressionMaxLength = expressionMaxLength`。这是框架自用的配置方法，并未限制只能内部调用。
- **为什么攻击者能调用**：OGNL 表达式语法 `@全类名@静态方法(参数)` 允许调用任意可访问的静态方法。注入点拿到的执行对象（如 Confluence 的 OgnlTool / Struts2 OgnlValueStack）虽然有黑名单，但 `ognl.Ognl` 自身这类"框架内部类"通常不在黑名单里，因此一条几十字符的表达式即可改写防护配置。
- **持久性**：`expressionMaxLength` 是 static 字段，属于整个 JVM 进程；设置一次后对后续所有请求生效（原文第二次访问时在调试器中确认值已从 200 变为 20000000）。
- **本质**：防护阈值不是只读常量，写方法暴露在可被表达式调用的静态面上，属于"安全配置被攻击者从表达式内部改写"的典型。

## 触发条件

- 存在 OGNL 表达式注入点，且执行器设置了 `expressionMaxLength`（Struts2/Confluence 默认配置即符合）。
- 未启用 `OgnlSecurityManager`，且框架/业务没有调用过 `freezeExpressionMaxLength()`（冻结后写操作抛异常）。
- 注入表达式可访问 `ognl.Ognl` 类且黑名单不拦截该静态调用。

## 利用步骤

1. 先发送一条短表达式：`@ognl.Ognl@applyExpressionMaxLength(20000000)`，把上限改到 2000 万字符。
2. 再触发一次并确认限制已解除（原文在调试器中断点观察 `expressionMaxLength` 从 200 变为 20000000）。
3. 之后即可发送原本超长的 OGNL payload（内存马 defineClass、长反射链等）。

## PoC

原文在 CVE-2023-22527 的 `text-inline.vm` 注入点上的请求（`label` 为固定转跳串，`poc` 为设置长度的表达式）：

```http
POST /template/aui/text-inline.vm HTTP/1.1
Host: target:8090
Content-Type: application/x-www-form-urlencoded
Connection: close

label=aaa\u0027%2b#request.get(\u0027.KEY_velocity.struts2.context\u0027).internalGet(\u0027ognl\u0027).findValue(#parameters.poc[0],{})%2b\u0027&poc=@ognl.Ognl@applyExpressionMaxLength(20000000)
```

该请求成功进入 `applyExpressionMaxLength` 并改写静态字段；原文第二次访问时 `expressionMaxLength` 已显示为 20000000。

## 变体与关联

- **冻结场景**：若目标已调用 `freezeExpressionMaxLength()`，该写入口失效，需要压缩表达式长度（变量拼接、分段执行）或换其他执行原语。
- **通用性**：不局限 Confluence——任何能调用静态方法的 OGNL 注入点（Struts2 S2 系列等）都可以先放开上限再打长 payload。
- **关联卡**：入口与长 payload 场景见 [[web-java-component-confluence-cve-2023-22527-text-inline-ognl-rce]]；后续内存马注入见 [[web-java-component-confluence-servlet-request-listener-memshell]]；其他 OGNL 沙箱绕过见 [[web-java-expression-ognl-high-version-reflection-invoke-bypass]]、[[web-java-expression-ognl-jshell-eval-bypass]]。

## 检测与防御

- **表达式层面**：用 `MemberAccess` 白名单限制可访问的类/方法，禁止调用 `ognl.Ognl` 自身及任意静态方法；禁止不可信输入进入 OGNL。
- **冻结上限**：应用启动完成配置后调用 `freezeExpressionMaxLength()`，让后续写操作抛异常（需确认框架兼容）。
- **WAF/日志**：检测 `applyExpressionMaxLength`、`freezeExpressionMaxLength`、`@ognl.Ognl@` 等字样；对超长表单参数告警。
- **运行时**：监控 OGNL 表达式中对 `ognl.Ognl` 的静态调用，以及进程内 expressionMaxLength 被异常放大的情况。
