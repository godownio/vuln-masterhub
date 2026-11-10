---
id: web-generic-auth-unauth-userinfo-default-password
title: 统一异常处理掩盖的未授权用户信息接口泄露 default_password：默认密码直接登录管理员后台
type: scenario
domain: web
path: web/generic/auth
technique: unauth-userinfo-default-password-leak
aliases:
- default_password 泄露
- 未授权用户信息接口
- 默认统一密码登录
- 统一错误响应误导
- 用户初始化接口未鉴权
tags:
- web
- auth
- broken-access-control
- unauth-api
- password
- php
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V383
  verified_at: '2026-11-09T08:42:35+08:00'
  notes: 已对照原文核对：未授权用户信息接口按 username 返回含 default_password 的对象、管理员用该密码登录成功、统一 200+业务错误码掩盖鉴权缺失均有截图/文字支撑；未验证点：原文登录口令经前端 CryptoJS DES（key/iv 从 JS 提取）加密，卡片 PoC 按明文口令简化；接口 act 与部分参数打码
---

## 一句话结论

后台初始化用的“获取用户信息”接口只按 `username` 查询、不校验会话，未登录即可返回用户对象，其中包含 `default_password` 字段；该字段就是系统给账号设置的默认统一密码，攻击者从前端注释拿到管理员用户名后，直接用它登录管理员后台——而全站其他接口统一返回 HTTP 200 + “用户未登录”这一业务错误，掩盖了这处鉴权缺失，容易在信息收集阶段被误判为“接口都有鉴权”。

## 原理

- **用户信息接口漏做鉴权**：登录后前端会调用类似 `/index.php?jsonVar=login&app=...&mod=User&act=<初始化动作>&username=<用户名>` 的接口初始化用户信息；后端把 `username` 当作唯一查询条件，直接返回完整用户对象，没有校验当前会话是否已登录、是否有权查看该用户。
- **响应对象包含口令字段**：返回 JSON 里有 `default_password`（系统默认统一密码/初始密码字段）以及一批权限标记（如 `is_system_admin`、`is_class_admin`）。这类“默认密码”本应只在服务端用于初始化或重置，不应出现在接口响应中；一旦回显即可直接用于登录。
- **统一异常处理造成误判**：应用对未授权/异常请求统一返回 200，并在 JSON 里用 `error_code`/`error_msg` 表示“用户未登录”“用户名或密码错误”（如 30001/30002）。攻击者若只看状态码或统一错误文案，会认为全部接口受保护；实际应比较响应体结构——返回真实用户对象与返回统一错误 JSON 的差异，才是判断鉴权是否生效的依据。
- **用户名来源**：登录页 JS（如 `login.js`）注释里遗留了多个不同权限的管理员用户名，为 `username` 参数提供了现成目标；即使没有注释，用户名也常可从登录报错、帮助页或枚举获得。
- **为什么危害高**：未授权即可获得管理员账号的有效口令，直接登录后台；后续可结合后台富文本组件（如 UEditor）继续打 SSRF/文件上传，形成完整攻击链。

## 触发条件

- 系统存在按 `username` 查询并返回用户对象的初始化/详情接口，且未做会话与对象级鉴权。
- 用户对象包含 `default_password`（或等价的默认口令/初始口令字段），且其值与实际登录口令一致。
- 攻击者能获得管理员用户名（前端 JS 注释、接口报错、默认命名枚举）。
- 登录入口未启用验证码、MFA 或来源限制，默认密码可直接登录。

## 利用步骤

1. 用 JSFinder/URLFinder/findsomething 等从前端 JS 与页面提取接口路径；访问若干接口记录“统一错误”响应（200 + 统一 `error_msg`）作为基线。
2. 手工审计登录页 JS，收集注释/变量中的管理员用户名与用户初始化接口路径（同一 `jsonVar` 网关下不同 `mod`/`act`）。
3. 未登录直接请求用户信息接口，参数带 `username=admin`；将响应与基线错误 JSON 对比，确认返回了真实用户对象。
4. 读取响应中的 `default_password` 字段；用该值作为口令登录管理员账号。
5. 验证登录成功与后台权限，检查该默认口令是否对所有账号统一、是否可在首登前利用；记录证据后停止。

## PoC

```http
GET /index.php?jsonVar=login&app=...&mod=User&act=<init-action>&username=admin HTTP/1.1
Host: target
```

```json
// 未登录响应（示意，字段名与结构来自截图，具体 act 名称以目标为准）
{"username":"admin","is_system_admin":0,"is_class_admin":0,
 "default_password":"<默认统一密码>","pwd_reset_flag":0, "...":"..."}
```

```http
POST /index.php?jsonVar=login&app=...&mod=User&act=<login-action> HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

username=admin&password=<default_password>
```

登录成功即进入后台（原文实际以该密码登录 admin 成功）。`act` 与部分参数在来源截图中被打码，复现时需按目标实际接口补齐；密码字段亦可能以哈希/掩码返回，需先实际登录验证。

## 变体与关联

- 变体：接口直接返回 `password` 明文或可逆密文，配合自增 id/用户名遍历可批量收集全站口令（见关联卡）。
- 变体：`default_password` 为系统统一默认密码时，一个泄露值即可尝试所有账号（首登未改密时命中率最高）。
- 变体：前端登录判断依赖登录响应 JSON 字段（如 `local_deploy`、`user.login`、`status`、`error_code`），篡改响应包可让前端进入后台页面并触发后续接口请求——但这只影响前端展示，真正接管仍取决于服务端接口是否鉴权，与本卡不是同一条链。
- 关联：[[web-generic-auth-user-api-plaintext-password-phone-enumeration]]（未授权用户接口回显口令的通用形态）、[[web-generic-auth-js-api-discovery-unauth-pii-mass-export]]（JS 提取接口 + 未授权接口枚举）、[[web-generic-auth-response-js-client-check-tamper]]（响应包客户端校验篡改）、[[cloud-metadata-ueditor-catchimage-aliyun-ram-credential]]（同场景后续利用链）。

## 检测与防御

- 防御：用户信息/初始化接口必须校验会话与对象级授权（只能查自己，管理员查他人需角色校验）；任何响应都不得返回 `password`、`default_password`、口令哈希等字段，按白名单序列化输出。
- 防御：统一异常处理不能代替鉴权；未授权请求应在网关/框架层返回 401/403，避免“200 + 业务错误码”掩盖授权失败；删除前端 JS 注释中的账号信息。
- 防御：默认密码强制首次登录修改；登录加失败锁定、验证码、MFA 与异常来源检测；口令字段加密存储且不可逆。
- 检测：未登录会话请求用户信息接口、响应体含 `default_password`/`password` 字段；同一用户名或 IP 高频探测初始化接口；使用默认口令批量登录的行为。
