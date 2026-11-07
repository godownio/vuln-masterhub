---
id: web-generic-auth-flowise-forgot-password-temp-token-response-leak
title: Flowise CVE-2025-58434 忘记密码接口响应回显 tempToken：仅凭邮箱重置任意账户密码接管
type: scenario
domain: web
path: web/generic/auth
technique: forgot-password-temp-token-response-leak-account-takeover
aliases:
- CVE-2025-58434
- Flowise 密码重置 token 泄露
- forgot-password tempToken
- Flowise 账户接管
- sanitizeUser 修复
tags:
- web
- flowise
- llm
- password-reset
- token-leak
- account-takeover
- unauth
- cve-2025-58434
cve:
- CVE-2025-58434
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: 3.0.5（原文复现版本，3.0.6 修复）
verification:
  verified_by: verifier-V227
  verified_at: '2026-11-07T06:55:22+08:00'
  notes: 已对照原文 CVE-2025-58434 章节与 img05-09 核对：/api/v1/account/forgot-password 路由、控制器 res.status(201).json(data)、service 末尾 return data 且 data.user.tempToken 已生成、resetLink 使用 tempToken、reset-password 按 email+tempToken 改密、3.0.6 的 sanitizeUser 删除 credential/tempToken/tokenExpiry、令牌默认 15 分钟均与原文一致。受影响版本按原文标记 3.0.5（原文复现版本，3.0.6 修复），未猜更宽区间。未验证点：未复跑 PoC。
---

## 一句话结论

Flowise `POST /api/v1/account/forgot-password` 在 201 响应体里把内部用户实体原样返回，包含 `tempToken`、`credential` 哈希和 `tokenExpiry`；攻击者只要知道目标邮箱，就能从响应中取走重置令牌并调用 `/api/v1/account/reset-password` 把该账户密码改成自己的，完成账户接管（管理员账户同样适用）。

## 原理

- 忘记密码服务 `AccountService.forgotPassword` 的正常流程是：按邮箱读取用户 → 生成 `tempToken` 写入 `data.user.tempToken` → 设置 `tokenExpiry` → 保存用户 → 用 `APP_URL/reset-password?token=${tempToken}` 拼接重置链接发邮件。
- 问题出在函数末尾直接 `return data`，而 `data.user` 正是被写入了 `tempToken` 的完整用户实体；控制器 `forgotPassword` 又直接 `res.status(201).json(data)` 返回，序列化时把 `tempToken`、`credential`、`tokenExpiry` 全部带出。
- 重置接口只按 `email + tempToken` 校验并更新密码，因此响应里泄露的 token 就是有效重置凭证；攻击者不需要访问受害者邮箱或点击邮件链接。
- 根因是把“内部持久化实体”当作“API 返回 DTO”使用，缺少输出字段白名单；修复版本 3.0.6 增加 `sanitizeUser`，在返回前删除 `credential`、`tempToken`、`tokenExpiry`。

## 触发条件

- 目标为受影响 Flowise（原文复现 3.0.5，3.0.6 修复），且使用企业版 account 路由与邮箱登录体系。
- 攻击者知道目标账户邮箱；该信息可从团队成员页、公开仓库提交记录、邮件往来或用户枚举接口获得。
- `/api/v1/account/forgot-password` 与 `/api/v1/account/reset-password` 按忘记密码流程应可匿名访问。
- 若目标配置了 SMTP，受害者也会收到重置邮件，但攻击者无需访问邮箱即可完成重置。

## 利用步骤

1. 向目标发送 forgot-password 请求，body 为 `{"user":{"email":"<victim@example.com>"}}`。
2. 从 201 响应的 `user.tempToken` 读取重置令牌；同一响应还会泄露 `user.id`、`credential` 哈希与 `tokenExpiry`。
3. 用 `email + tempToken + 新密码` 调用 `/api/v1/account/reset-password`。
4. 用新密码登录目标账户；若受害者为管理员，则接管后台，可继续结合后台节点加载等功能扩大影响。
5. 令牌有效期默认为 15 分钟（`PASSWORD_RESET_TOKEN_EXPIRY_IN_MINS` 未配置时），需在有效期内完成第 3 步。

## PoC

原文最小复现（占位符需替换为目标值；仅作结构示例，请勿在未授权环境执行）：

```http
POST /api/v1/account/forgot-password HTTP/1.1
Host: <target>
Content-Type: application/json

{"user":{"email":"<user@example.com>"}}
```

```http
POST /api/v1/account/reset-password HTTP/1.1
Host: <target>
Content-Type: application/json

{"user":{"email":"<user@example.com>","tempToken":"<响应中的 tempToken>","password":"NewSecurePassword123!"}}
```

原文截图确认 201 响应包含 `user.tempToken`、`tokenExpiry`、`credential`，随后使用该 tempToken 成功重置密码。

## 变体与关联

- 同类根因：注册、登录、邀请、验证等接口直接 `res.json(userEntity)` 导致 token/hash 泄露；审计时搜索把 ORM 实体直接交给 JSON 序列化的 controller。
- 关联利用：拿到管理员账户后可进入 Flowise 后台，衔接 CustomMCP 节点加载的 `Function()` 代码执行与未授权文件读取。
- 官方修复：3.0.6 在 `account.service.ts` 中用 `sanitizeUser` 过滤返回的用户对象。

## 检测与防御

- 修复：升级 Flowise >= 3.0.6；对 API 返回使用 DTO 白名单序列化，禁止直接返回持久化实体。
- 检测：HTTP 日志中出现 `/api/v1/account/forgot-password` 高频请求、同一 IP 对不同邮箱发起重置、随后同 IP 登录；响应体含 `tempToken` 或 `credential` 字段应立即告警。
- 加固：重置令牌一次性、绑定邮箱且有效期尽量短；重置接口限速；管理员账户强制 MFA；监控异常登录与密码变更。
