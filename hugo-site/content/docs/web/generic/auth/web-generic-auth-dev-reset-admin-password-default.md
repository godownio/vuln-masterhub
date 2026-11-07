---
id: web-generic-auth-dev-reset-admin-password-default
title: 开发调试接口 /dev/Reset 未授权重置管理员密码为 admin/admin
type: scenario
domain: web
path: web/generic/auth
technique: exposed-dev-reset-default-admin-password
tags:
- web
- auth
- password-reset
- dev-interface
- default-password
- aspnet
- admin-takeover
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V74
  verified_at: '2026-11-05T16:39:40+08:00'
  notes: 已对照 content.md 与图08/09核对：/dev/Reset 页面明示“重置管理员密码，重置后账号和密码都是admin”，点击重置后以 admin/admin 进入后台，与卡内一致。未验证点：重置请求与验证码流程未复跑。
url: /docs/web/generic/auth/web-generic-auth-dev-reset-admin-password-default/
draft: false
kb_aliases:
- 开发接口重置管理员密码
- dev Reset 未授权
- 默认口令 admin/admin
- ASP.NET 教务系统后台接管
- 调试接口密码重置
---

## 一句话结论

站点未删除的开发调试页 `/dev/Reset` 提供“重置管理员密码”功能，无需认证、无需旧密码，重置后账号与密码固定为 `admin/admin`；攻击者点击即可接管后台管理员。

## 原理

- 开发调试工具常内置“重置管理员密码”“初始化数据”等便捷功能，用于本地开发时快速恢复环境；这些功能被部署到生产后若未删除或未加访问控制，就成为未授权的账号接管入口。
- 该功能同时具备三个危险特征：无需认证即可调用、不需要旧密码或邮箱/短信验证、重置结果为固定默认口令（本例为 `admin/admin`）。任何能访问该路径的人都能得到可登录的管理员账号。
- 与常规忘记密码流程不同，这里没有 token、没有身份校验、没有速率限制；它不是“重置自己的密码”，而是直接改管理员账号。
- 同一开发接口常与数据库连接配置、代码生成、安装部署等功能放在一起，泄露面更大；攻击者获得管理员后还可继续利用后台的上传、SQL 注入等功能。
- 根因是开发功能未下线 + 缺少服务端鉴权 + 固定默认口令，三者叠加使认证边界完全失效。

## 触发条件

- 目标站点保留开发调试接口（如 `/dev`、`/dev/Reset`、`/install`、`/setup`）；
- 重置接口可从攻击者位置访问，且不需要登录/旧密码/验证码；
- 重置后的默认口令已知或可预测；
- 管理员账号可正常登录后台。

## 利用步骤

1. 通过目录扫描或页面导航发现 `/dev` 等开发入口，查看其功能标签（后台代码、前台代码、导入工具、重置密码、安装部署等）。
2. 打开“重置密码”页面，确认提示信息（如“重置后账号和密码都是 admin”）。
3. 触发重置请求（点击按钮或直接请求对应路径），记录响应。
4. 使用默认口令 `admin/admin` 登录后台，确认角色与管理权限。
5. 在授权范围内验证后台功能（如上传、报表），但避免修改生产数据；测试后恢复/重置口令并报告。
6. 将开发接口暴露面与默认口令问题一并纳入报告，建议删除接口并强制强口令/多因素。

## PoC

```http
GET /dev/Reset HTTP/1.1
Host: target.example.com
```

页面提示（示意）：

```text
重置管理员密码，重置后账号和密码都是 admin。
[重置]
```

重置后登录：

```http
POST /Login HTTP/1.1
Host: target.example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin&captcha=<captcha>
```

原文通过该方式成功以 `admin/admin` 进入后台管理员。

## 变体与关联

- 变体：`/dev/reset`、`/install/reset`、`/setup/admin`、`/api/resetPassword` 等路径；参数可能允许指定目标账号或直接返回新口令。
- 变体：默认口令可能是 `admin/admin`、`admin/123456`、`administrator/admin` 等；也可能由页面直接告知。
- 关联：[[pentest-recon-dev-code-generator-db-credential-leak]]（同一开发接口的数据库凭据泄露）、[[web-generic-auth-unauth-user-create-admin-takeover]]（另一类未授权创建管理员）。
- 边界：开发接口已删除/加认证、重置需要旧密码或管理员会话、默认口令被强制修改时，不成立。

## 检测与防御

- 检测：对 `/dev`、`/install`、`/setup` 等路径的访问；重置接口在无会话/无旧密码情况下被调用；管理员账号口令被改为默认值后立即登录；同一 IP 在重置后短时间内登录后台。
- 防御：生产环境删除开发/调试/安装接口，或在网关层禁止外部访问；必须保留的运维功能加认证、来源限制与审计。
- 防御：密码重置必须校验身份（旧密码、邮箱/短信 token、管理员会话），禁止固定默认口令；首次登录强制改密。
- 防御：管理员账号启用 MFA、登录告警与异常来源检测；定期审计后台账号与登录日志。
