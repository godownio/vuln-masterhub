---
id: web-java-framework-spring-native-forwarded-header-proto-scheme-injection
title: 容器化 Spring Boot 默认 native 转发头策略使 X-Forwarded-Proto 成为未校验的 URI scheme，污染 baseUrl 构造
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-boot-native-forwarded-header-scheme-injection
aliases:
- X-Forwarded-Proto scheme 注入
- server.forwardHeadersStrategy=native
- DefaultHttpForwardedHeaderHandler withScheme
- 容器环境默认转发头解析差异
- baseUrl 构造被转发头污染
tags:
- spring-boot
- spring-cloud-gateway
- x-forwarded-proto
- forwarded-header
- netty
- scheme-injection
- url-construction
- container
- kubernetes
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-13
  verified_at: '2026-11-08T07:14:18+08:00'
  notes: 已对照原文与2张图核对：CloudPlatform/forwardHeadersStrategy=native 推断逻辑、NettyReactiveWebServerFactory#createHttpServer 的 server.forwarded(useForwardHeaders)、DefaultHttpForwardedHeaderHandler#parseXForwardedInfo 对 X-Forwarded-Proto 直接 trim 后 withScheme 不做 http/https 白名单、resolveBaseUrl 污染 baseUrl，均与原文代码引用一致；图01为 gateway 请求/过滤器流程示意，图02为 ForwardedHeaderTransformer 源码(build(true))，对应原文『本地 build=true 报错、复现不了』的定位过程，无误。结论确实克制在原语(medium/medium，未包装成 RCE/SSRF)，但原文未给出任何打通后的实际危害(仅称『存在一定的绕过逻辑』)；按原口径保留，属未验证点。已 --clear affected_versions：原文『spring cloud gateway 版本 3.1.9、4.1.0、4.3.0 都是有效的』是作者在测试环境的验证结果(原字段又带『(原文测试有效)』括号注释)，不是明确的受影响版本区间/组件版本声明，按 brief 不猜、清除。frontmatter 无 sources/source_url。
---

## 一句话结论

Spring Boot 在容器/云环境（KUBERNETES/CLOUD_FOUNDRY/HEROKU/SAP）下会自动启用 `server.forwardHeadersStrategy=native`（等价于显式 `spring.main.cloud-platform=KUBERNETES`），使 Netty 初始化 `DefaultHttpForwardedHeaderHandler`；其 `parseXForwardedInfo` 把 `X-Forwarded-Proto` 头值直接 `connectionInfo.withScheme(...)` 且**不校验只允许 http/https**，于是任意字符串都成为请求的 URI scheme，`ReactorServerHttpRequest#resolveBaseUrl` 组装出的 baseUrl 被污染，后续 `UriComponentsBuilder`/GlobalFilter 据此构造的 URL 结构不再符合预期，可被用于绕过或非预期请求。

## 原理

- Spring Boot `NettyWebServerFactoryCustomizer#getOrDeduceUseForwardHeaders()`：当 `server.forwardHeadersStrategy == null` 时用 `CloudPlatform.getActive(environment)` 检测当前是否运行在云/容器平台（通过特定环境变量识别），`platform != null && platform.isUsingForwardHeaders()` 为真即启用 native 转发头处理；显式配置 `server.forwardHeadersStrategy=native` 或 `spring.main.cloud-platform=KUBERNETES` 效果相同（`NONE` 可禁用检测）。
- `NettyReactiveWebServerFactory#createHttpServer()` 里 `server.forwarded(this.useForwardHeaders)` 为真时启用 `reactor.netty.http.server.DefaultHttpForwardedHeaderHandler`。
- `DefaultHttpForwardedHeaderHandler#apply` 优先解析 RFC 7239 `Forwarded` 头（`parseForwardedInfo`），否则走 `parseXForwardedInfo`：读 `X-Forwarded-Proto`，取逗号分隔第一段并 `trim()`，直接 `connectionInfo.withScheme(...)`。代码没有把取值限制在 `http`/`https`（尽管按语义本应只有这两种），攻击者可注入含 `<`、`>`、`?`、`://` 等字符的任意串。
- `ReactorServerHttpRequest#resolveBaseUrl` 用 `connectionInfo.getScheme()` 拼 `scheme://host:port` 作为 baseUrl；应用侧的 GlobalFilter / `UriComponentsBuilder#fromHttpRequest` / `adaptFromForwardedHeaders` 再基于它构造最终 URI，scheme 被污染后整条 URL 的解析结果发生偏移，产生"绕过逻辑"（原文用于 CVE-2022-22947 的利用请求构造）。
- 环境差异是定位难点：本地非容器环境未配置 `forwardedHeaderTransformer`、且 `build(true)` 会报错，完全复现不了；线上容器化部署却稳定走 native 路径。
- 原文验证该 scheme 获取逻辑在 Spring Cloud Gateway 3.1.9、4.1.0、4.3.0 均有效，并指出"正常来说应该只有 http、https 两种情况"——即根因是缺少协议白名单校验。
- **边界**：本文是一篇根因定位/复现记录，只证明"X-Forwarded-Proto 值成为未校验 scheme 并污染 baseUrl 构造"这一原语，CVE-2022-22947 的完整 SpEL 注入 RCE 链明确交由参考链接、未在本文展开；故本卡结论止于原语，不包装成 RCE/SSRF 完整危害，confidence 标 medium。

## 触发条件

- 应用为 Spring Boot WebFlux + Netty（如 Spring Cloud Gateway），部署在容器/K8s/云环境，或显式设 `server.forwardHeadersStrategy=native` / `spring.main.cloud-platform=KUBERNETES`；
- 攻击者可控制 `X-Forwarded-Proto`（或 `Forwarded: proto=`）请求头；
- 应用/过滤器使用 `resolveBaseUrl` 得到的 baseUrl 或 `UriComponentsBuilder` 再构造 URL，且未对 scheme 做白名单；
- 目标版本与原文测试一致（gateway 3.1.9 / 4.1.0 / 4.3.0 有效）。

## 利用步骤

1. 确认目标是容器化部署（或探测是否存在 native 转发头策略）：本地非容器环境复现不了，需到线上/测试环境验证。
2. 构造含特殊内容的 `X-Forwarded-Proto`（如 `<https://www.baidu.com/actuator>?`），随请求发送。
3. 观察 `DefaultHttpForwardedHeaderHandler.parseXForwardedInfo` 把该值写入 `connectionInfo` 的 scheme，`resolveBaseUrl` 与后续 `UriComponentsBuilder` 构造出被污染的 URL。
4. 结合具体应用逻辑（路由匹配、重定向、URL 校验、actuator 路径）评估可用的绕过点；本文仅定位到该原语。

## PoC

```http
POST /test/ HTTP/1.1
Host: www.xxxxx.com
Content-Type: application/json
X-Forwarded-Proto: <https://www.baidu.com/actuator>?
Content-Length: 340
```

```bash
curl 'http://127.0.0.1:8081/123123123' \
  -H 'user-agent: Mozilla/5.0' \
  -H 'x-forwarded-proto: <https://www.baidu.com/actuator?>'
```

```java
// 关键代码（reactor.netty.http.server.DefaultHttpForwardedHeaderHandler）
String protoHeader = request.headers().get(X_FORWARDED_PROTO_HEADER);
if (protoHeader != null) {
    connectionInfo = connectionInfo.withScheme(protoHeader.split(",", 2)[0].trim()); // 未校验 http/https
}
```

说明：结构复现的通用请求，头部取值/路径按目标调整；不访问、不执行。

## 变体与关联

- 变体：用 RFC 7239 `Forwarded: proto=<...>` 头经 `parseForwardedInfo` 的 `FORWARDED_PROTO_PATTERN` 同样写 scheme；`X-Forwarded-Host`/`X-Forwarded-Port`/`X-Forwarded-For` 也会改写 connectionInfo 的 host/port/remoteAddress。
- 变体：与 Host 头投毒、CRLF/URL 解析差异、缓存键污染等组合，把"可控 scheme/baseUrl"转成 SSRF 或校验绕过。
- 关联：[[web-java-expression-spel-spring-cloud-gateway-22947-actuator-route-rce]]（CVE-2022-22947 完整 SpEL RCE 链，本文未展开）；[[web-generic-auth-password-reset-host-header-poisoning]]（Host/转发头污染 URL 构造的同类问题）。

## 检测与防御

- 检测：请求中出现 `X-Forwarded-Proto`/`Forwarded` 值不是 `http`/`https`（含 `<`、`>`、`?`、`://` 等字符）；应用构造出的 baseUrl/URI 的 scheme 异常；容器环境自动启用 native 转发头策略的资产盘点。
- 检测：本地与线上行为不一致（转发头解析差异）、`DefaultHttpForwardedHeaderHandler` 被加载。
- 防御：显式配置 `spring.main.cloud-platform=NONE` 或 `server.forwardHeadersStrategy=NONE/FRAMEWORK`，不要依赖云环境自动推断；只在可信反向代理边界接受并重写转发头，边缘剥离外部传入的 `X-Forwarded-*`/`Forwarded`。
- 防御：对 scheme/host/port 做白名单校验（scheme 只允许 http/https）；基于 baseUrl 构造 URL 时使用 `UriComponentsBuilder` 的严格模式并校验最终 URI。
