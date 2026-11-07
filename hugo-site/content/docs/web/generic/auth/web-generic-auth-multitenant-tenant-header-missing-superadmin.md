---
id: web-generic-auth-multitenant-tenant-header-missing-superadmin
title: 多租户头缺失被当作超管：删 X-Access-Token 绕过 tenant_id 隔离跨租户越权
type: scenario
domain: web
path: web/generic/auth
technique: tenant-header-missing-fail-open-superadmin
tags:
- web
- java
- spring-boot
- mybatis-plus
- multi-tenant
- tenant-isolation
- auth-bypass
- idor
- access-control
- password-reset
- data-exposure
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: jshERP 3.5（原文标注版本；未给出修复版本）
verification:
  verified_by: verifier-V20
  verified_at: '2026-11-05T02:22:54+08:00'
  notes: 已通读原文并逐张核对17张图：图03 resetPwd 仅拦 loginName=admin；图04 Mapper 仅 WHERE id=#{id}；图07 改 token 为 _133 返回 loginOut；图08 删除 X-Access-Token 且用 /jshERP-boot/user/login/../resetPwd 返回 code 200 操作成功（已据此修正卡内误写的 /login/../user/resetPwd 路径，规范化后会变成 /user/user/resetPwd）；图09-15 supplier/role/user/info/person/account 越权响应与卡内一致，图13 user/info 确实返回 MD5 password。affected_versions 保留原文审计版本 jshERP 3.5，原文未给修复版本/区间。PoC 未在本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-multitenant-tenant-header-missing-superadmin/
draft: false
kb_aliases:
- jshERP 越权
- 管伊佳ERP 越权
- X-Access-Token 越权
- tenant_id 隔离绕过
- 删租户头越权
- TenantSqlParser 绕过
- TenantLineHandler 失效
- 多租户水平越权
- 任意用户密码重置
---

## 一句话结论

当多租户系统把“请求头里解析不出租户 ID”当作 `0`/`null` 并解释为“超管，不追加 tenant_id 条件”时，攻击者删除租户令牌头（再配合登录过滤器绕过），所有按主键操作的接口都会退化为跨租户操作，可重置任意用户密码、删除用户、改动供应商/角色状态并读取其他租户的账号与密码哈希。

## 原理

- 数据层的租户隔离完全依赖 MyBatis-Plus 的 `TenantSqlParser`/`TenantLineHandler` 自动改写 SQL：每次查询/更新前，`getTenantId()` 返回 `LongValue(tenantId)` 就追加 `tenant_id = ?`，返回 `null` 就不追加；`doTableFilter()` 还可按表名跳过改写。
- 问题实现里租户 ID 来自客户端请求头（如 `X-Access-Token`，形式为 `<session>_<tenantId>`），由 `Tools.getTenantIdByToken(token)` 解析。代码把 `tenantId == 0` 解释为超管分支并返回 `null`，而请求头缺失或解析失败时恰好也得到 `0`。于是“没有身份”与“超级管理员”共用了同一条 fail-open 分支。
- 控制器把用户可控的 `id`/`ids` 直接传给 Mapper，Mapper 的 `UPDATE ... WHERE id = #{id}` 本身不含 `tenant_id` 或归属校验；租户条件只由 SQL 改写器临时加上。一旦改写器被关掉，`WHERE` 里就只剩主键，跨租户读写成立。
- 登录过滤器本应阻挡未登录请求，但其放行判断是对**原始 URI** 做 `contains("/user/login")`。构造 `/jshERP-boot/user/login/../resetPwd` 时过滤器看到包含 `/user/login` 而放行，Spring 路由到规范化后的 `/jshERP-boot/user/resetPwd`；请求同时不带 `X-Access-Token`，两处缺陷首尾相接。该路径解析差异的通用原理见关联卡片。
- 重置密码服务只拦 `loginName == "admin"` 这一个超管账号，随后按 id 执行 `UPDATE jsh_user SET password = ? WHERE id = ?`，因此除字面量 `admin` 外的任意租户用户都能被改成默认口令。
- 更隐蔽的一点：`ResourceController.updateResource` 一类接口还允许请求体自带 `tenantId`，改写器放行后可直接把记录转移到攻击者指定的租户，等效于跨租户“搬走/删除”数据。

## 触发条件

- 使用 MyBatis-Plus 多租户插件，`TenantLineHandler#getTenantId()` 在“无头/解析失败/0”时返回 `null` 而不是拒绝请求。
- 租户 ID 由客户端可控的请求头派生，缺少服务端会话到租户的强绑定。
- 登录/鉴权过滤器可用原始 URI 与路由路径不一致绕过（`contains`/`startsWith` + `..`、`;`、编码等），或目标接口本身允许匿名访问。
- 业务 Mapper 只按 `id` 更新/删除，未在 SQL 中重复校验 `tenant_id`；控制器不校验资源归属。
- 原文环境：jshERP 3.5（Spring Boot 前后端分离版，`X-Access-Token: <session>_<tenantId>`）。

## 利用步骤

1. 正常登录任一租户账号，记下 `X-Access-Token` 的 `_` 后租户号（如 `_63`），确认普通请求会被自动加上 `tenant_id = 63`。
2. 找一个只按 id 操作的目标接口，例如 `POST /user/resetPwd`、`DELETE /user/delete`、`POST /supplier/batchSetStatus`、`POST /role/batchSetStatus`、`GET /role/allList`、`GET /user/info?id=`、`GET /person/getAllList`、`GET /account/getAccount`。
3. 构造过滤器放行路径：把 `/user/login` 作为前缀目录，再用 `..` 回到目标控制器，如 `/jshERP-boot/user/login/../resetPwd` 或 `/jshERP-boot/user/login/../../supplier/batchSetStatus`。
4. 删除 `X-Access-Token` 请求头后发送请求；若响应为业务成功而非 `loginOut`，说明已进入无租户条件分支。
5. 对目标用户 id 执行重置密码，得到默认口令 `123456` 后登录验证；对其他接口批量读取/修改。
6. 验证数据层是否真的失去租户条件：开启 SQL 日志，观察 `WHERE id = ?` 前不再出现 `tenant_id = ?`。

## PoC

```http
POST /jshERP-boot/user/login/../resetPwd HTTP/1.1
Host: target:9999
Content-Type: application/json

{"id": 132}
```

```text
# 无 X-Access-Token 时预期返回：{"code":200,"data":{"message":"操作成功"}}
# 服务端 SQL 日志由
#   SELECT ... FROM jsh_user WHERE jsh_user.tenant_id = 63 AND id = ?
# 变为
#   SELECT ... FROM jsh_user WHERE id = ?
# 随后 UPDATE jsh_user SET password = ? WHERE id = ? 命中其他租户用户
```

```http
GET /jshERP-boot/user/login/../../role/allList HTTP/1.1
Host: target:9999

GET /jshERP-boot/user/login/../../user/info?id=63 HTTP/1.1
Host: target:9999

POST /jshERP-boot/user/login/../../supplier/batchSetStatus HTTP/1.1
Host: target:9999
Content-Type: application/json

{"status": false, "ids": "74,"}
```

```text
# role/allList 未带令牌返回全部租户角色（含 tenantId 字段），可用于枚举目标 id；
# user/info 返回其他租户用户的 password 字段（MD5），可离线爆破后接管；
# supplier/role batchSetStatus 可批量禁用其他租户的业务对象。
```

## 变体与关联

- 变体：租户头改名（`X-Tenant-Id`、`tenant-id`、`TENANT`）或从 Cookie/query 取租户；核心是“缺失即超管”的默认值。
- 变体：`getTenantId()` 返回 `null` 的其它写法，例如 `if (tenantId == null || tenantId == 0L) return null;`、异常被 `catch` 后返回 `null`。
- 变体：请求体自带 `tenantId` 的更新接口（如 `ResourceController.updateResource`）可把记录迁到指定租户，形成跨租户转移/变相删除。
- 关联：[[web-java-framework-spring-custom-auth-path-parsing-bypass]]（原始 URI 与路由路径不一致导致过滤器放行，本链的前置条件）。
- 关联：[[web-generic-auth-authenticated-change-password-idor]]（登录后按 id/username 改他人密码的同类越权）。
- 关联：[[web-generic-auth-swagger-unauth-user-management]]（另一种绕过入口：文档暴露后直接调用管理接口）。
- 边界：若多租户处理器在缺失租户时抛异常/拒绝、若 Mapper 显式在 `WHERE` 中带 `tenant_id` 或数据库启用行级安全、若登录过滤器使用规范化路径且严格精确匹配，该链不成立。

## 检测与防御

- 修复（授权默认）：租户解析失败必须 fail-closed，返回 401/403；`0` 只能由服务端签发的超管会话映射得到，不能与“缺失”共用。
- 修复（数据层）：不要仅依赖可被输入关闭的 SQL 改写分支；关键表的更新/删除在 `WHERE` 中显式带 `tenant_id`，并在服务层校验 `resource.tenant_id == session.tenant_id`。
- 修复（接口）：重置密码、删除用户等敏感操作要求管理员角色并校验目标用户归属；只排除字面量 `admin` 不足以保护其他租户管理员。
- 修复（认证）：过滤器使用与路由一致的规范化路径（`getServletPath()` 或框架路由匹配）并做精确白名单；拒绝含 `..`、`;`、编码斜杠和连续 `/` 的路径；引入 `StrictHttpFirewall`。
- 加固：用户信息接口不返回 `password` 哈希；口令使用 bcrypt/argon2 而非裸 MD5；敏感操作加二次确认与审计。
- 检测：缺少租户令牌却通过鉴权并返回 200 的请求；URI 中出现 `/login/../` 等路径穿越片段；SQL 日志中业务更新缺少 `tenant_id` 条件；同一账号短时间跨多个租户 id 的读写；批量密码重置与状态变更告警。
