---
id: web-generic-auth-oauth-commented-js-client-secret-register-ownerid-admin
title: 前端注释泄露 OAuth 客户端凭证 + 注册接口 ownerId 直通 roleId：注册 SYSTEM 管理员并取得高权限 Token
type: scenario
domain: web
path: web/generic/auth
technique: oauth-client-secret-js-comment-register-ownerid-role-escalation
aliases:
- 注释残留 OAuth 凭证
- constant.js client_secret
- /regin ownerId 提权
- 注册接口角色参数篡改
- OAuth password 模式提权
- roleType SYSTEM 注册
tags:
- web
- oauth2
- client-secret
- javascript
- information-disclosure
- registration
- mass-assignment
- privilege-escalation
- authorization
- angularjs
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-05T12:36:47+08:00'
  notes: 核对员 V64 发现注册端点为 /regin 而卡内写作 /reg，已按原文 api.js 与图26/41/53 全量修正为 POST /regin，其余链路核对通过
---

## 一句话结论

SPA 的 `index.html` 把 `constant.js` 注释掉但文件仍可访问，其中残留 OAuth2 的 `client_id`/`client_secret`；注册接口 `/regin` 又直接接受 `ownerId` 并把它当作新用户的 `roleId`，攻击者从前端 `main.js` 取得 SYSTEM 管理员角色 ID，注册时传入 `ownerId=<管理员 roleId>`，即可创建 `roleType: SYSTEM` 的账号，再用 OAuth2 password 模式换取高权限 Token，访问原本 403 的用户列表等接口。

## 原理

- **注释不等于删除**：开发者把 `<script src="src/app/constant.js">` 在 `index.html` 中注释掉，但 `constant.js` 文件仍部署在 Web 目录；直接访问该路径或通过开发者工具搜索全部 JS 即可读到 `APP_CLIENT_ID`、`APP_CLIENT_SECRET`、`APP_GRANT_TYPE`、`APP_GRANT_SCOPE`。
- **OAuth2 两种授权模式**：泄露的 client 凭证可用于 `client_credentials` 模式换取 M2M Token，但该 Token 的 scope 不含用户接口所需权限，访问 `/v1/user/...` 返回 `INSUFFICIENT_SCOPE`；后端提示需要 OAuth2 password 模式认证。攻击者因此需要一个系统内账号。
- **注册接口的权限参数**：`/regin` 只要求 `username`/`password`，并接受可选的 `ownerId`。后端没有校验调用者是否有权指定角色，直接把 `ownerId` 的值写入新用户的 `roleId`。这是典型的批量赋值/权限参数篡改。
- **角色 ID 来自前端**：`main.js` 中定义了各角色的比较逻辑，如系统管理员 `roleId = '856172932159787008'`、公司管理员、小区管理员、物业管理员等；攻击者把这些常量当作可提交的 `ownerId` 候选。
- **完整提权链**：泄露 client 凭证 → 注册普通账号（roleType GUEST）→ password 模式换低权 Token → 发现权限不足 → 从 `main.js` 取管理员 roleId → 用 `ownerId=<roleId>` 重新注册 → 新账号直接是 `roleType: SYSTEM` → password 模式换高权 Token → 访问用户列表等受限接口。
- **危害放大**：管理员接口返回的用户对象中包含 `password` 字段（截图显示为口令值/哈希），进一步扩大凭据泄露面。

## 触发条件

- 目标为 SPA + OAuth2 架构，前端 JS 中存在可访问的配置文件或注释残留，包含有效 `client_id`/`client_secret`。
- 注册接口 `/regin`（或同类接口）接受 `ownerId`/`roleId`/`roleType` 等权限参数，且后端不做调用者授权校验。
- 前端代码中可找到管理员角色 ID 或角色映射逻辑。
- OAuth2 服务允许 password 模式，且注册账号可正常换取 Token。

## 利用步骤

1. 在页面源码/开发者工具中搜索 `client_secret`、`client_id`、`oauth`，检查被注释的 `<script>` 与 `constant.js`、`config.js` 等配置文件的直接访问。
2. 用泄露的 client 凭证请求 `/oauth/token`（`grant_type=client_credentials`），确认凭证有效；访问用户接口观察是否 `INSUFFICIENT_SCOPE`。
3. 分析 `api.js` 找到注册接口 `/regin`，先用普通参数注册一个账号，确认返回 `roleType: GUEST`。
4. 在 `main.js` 等前端代码中搜索角色判断逻辑，提取系统管理员 `roleId`（如 `856172932159787008`）。
5. 用 `username/password/ownerId=<管理员 roleId>` 重新注册，确认返回 `roleType: SYSTEM`、`roleId` 为管理员 ID。
6. 用新账号 + client 凭证走 `grant_type=password` 换取高权 Token（scope 含 `enterprise parking property`）。
7. 携带 Bearer Token 访问此前 403 的 `/v1/user/currentUser/read/page` 等接口，确认可读取用户列表及敏感字段。

## PoC

```http
# 1) 读取被注释但仍部署的配置
GET /src/app/constant.js HTTP/1.1
Host: target
# 返回：APP_CLIENT_ID / APP_CLIENT_SECRET / APP_GRANT_TYPE='password' / APP_GRANT_SCOPE

# 2) client_credentials 验证凭证
POST /oauth/token HTTP/1.1
Host: api.target
Content-Type: application/x-www-form-urlencoded

client_id=<CLIENT_ID>&client_secret=<CLIENT_SECRET>&grant_type=client_credentials&scope=parking property enterprise

# 3) 注册 SYSTEM 管理员（ownerId 直接变成 roleId）
POST /regin HTTP/1.1
Host: api.target
Content-Type: application/x-www-form-urlencoded

username=attacker&password=Test123456&ownerId=856172932159787008
# 响应：roleId=856172932159787008, roleType=SYSTEM

# 4) password 模式换取高权 Token
POST /oauth/token HTTP/1.1
Host: api.target
Content-Type: application/x-www-form-urlencoded

grant_type=password&username=attacker&password=Test123456&client_id=<CLIENT_ID>&client_secret=<CLIENT_SECRET>&scope=parking property enterprise

# 5) 访问管理员接口
GET /v1/user/currentUser/read/page HTTP/1.1
Host: api.target
Authorization: Bearer <ACCESS_TOKEN>
```

关键判断点：注册响应中的 `roleType` 从 `GUEST` 变为 `SYSTEM`，且 `roleId` 等于提交的 `ownerId`；随后同一账号的 Token scope 从 `user_detail` 变为 `enterprise parking property`，受限接口由 403 变为 200。

## 变体与关联

- 变体：`main.js` 中还有其他角色 ID（公司管理员、小区管理员、社区委员会管理员、物业管理员、占道停车管理员等），可注册对应角色的账号，按目标接口选择最小可用角色。
- 变体：`ownerId` 也可能用于指定数据归属（租户/公司/小区），即使不是角色 ID，也可能造成跨租户数据归属或越权。
- 变体：被注释的配置文件也可能通过 source map、备份文件、`config.js`、`envconfig.js` 等暴露；搜索范围应覆盖全部静态资源。
- 关联：[[pentest-recon-frontend-js-aes-key-encrypted-credential-mqtt-validation]]、[[pentest-recon-frontend-obfuscated-js-hardcoded-credentials]]——前端 JS 凭据泄露的通用挖掘。
- 关联：[[web-generic-auth-multitenant-tenant-header-missing-superadmin]]——同为前端可控权限参数导致越权。
- 边界：后端对注册角色做白名单/调用者校验、client secret 已轮换、或 password 模式被禁用时不成立；管理员接口可能还有二次校验。

## 检测与防御

- 检测：静态资源中出现 `client_secret`、`client_id`、`grant_type` 等 OAuth 配置；`/regin` 请求携带 `ownerId`/`roleId`/`roleType` 等权限字段；注册响应出现高权限 `roleType`；同一新账号短时间内从 GUEST 变为 SYSTEM；password 模式 Token 访问管理接口。
- 修复：不要把 client_secret 打包进前端；注释/删除不能替代移除文件，构建时排除敏感配置并轮换已泄露 secret。
- 修复：注册接口的角色/归属必须由后端根据认证上下文决定，禁止客户端提交 `ownerId`/`roleId`/`roleType`；对批量赋值字段做白名单。
- 加固：OAuth2 仅启用必要 grant type，限制 client_credentials 的 scope；对注册与角色分配做审计与告警；管理接口返回字段脱敏（不返回 password）。
- 响应：发现泄露后轮换 client_secret、禁用异常账号并排查通过该接口注册的高权限账号。
