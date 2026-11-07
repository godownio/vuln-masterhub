---
id: web-generic-auth-swagger-unauth-user-management
title: Swagger 暴露未授权用户增删接口导致账号创建与批量删除
type: scenario
domain: web
path: web/generic/auth
technique: swagger-unauth-user-management
aliases:
- Swagger 未授权接口
- Swagger 用户管理
- OpenAPI 未授权
- 接口文档暴露
- 按用户名删除用户
tags:
- web
- swagger
- openapi
- auth-bypass
- unauthorized
- user-management
- api
- idor
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:33:06+08:00'
  notes: 已对照原文与图31/33/34核对：Swagger UI 暴露 /user 系列接口，未授权 POST /user 返回 200 与用户 id，未授权 DELETE /user/zhangsan 返回 200，删除按用户名定位。卡中 createWithArray/createWithList/PUT 等变体与文档列表一致。原文未涉及版本区间。PoC 未在本机执行。
---

## 一句话结论

当 Swagger/OpenAPI 文档在公网暴露，且其中描述的用户管理接口没有服务端鉴权时，攻击者可直接通过文档的 “Try it out” 或 curl 创建用户、按用户名删除用户，甚至通过用户名枚举批量删除全系统账号。

## 原理

- Swagger UI（`/swagger-ui.html`、`/swagger-ui/index.html`）与 OpenAPI JSON/YAML（`/v2/api-docs`、`/v3/api-docs`）会列出后端所有接口、参数与示例。很多项目在生产环境未关闭或未加访问控制。
- 文档本身只是描述；真正的风险是后端接口缺少认证/授权。攻击者不需要理解业务，只要按文档构造请求即可调用管理功能。
- 用户管理接口常见的危险组合：`POST /user` 创建用户、`POST /user/createWithArray` 批量创建、`PUT /user/{username}` 修改用户、`DELETE /user/{username}` 删除用户、`GET /user/{username}` 查询用户。
- 按用户名删除的接口把“用户名”作为唯一资源标识，且不校验调用者身份。攻击者可用常见用户名/工号/邮箱前缀字典枚举，命中即删除，形成批量破坏。
- Swagger UI 的 “Try it out” 让测试零门槛，但即使 UI 被限制，直接 curl 文档中的路径同样有效。

## 触发条件

- Swagger/OpenAPI 文档可被未认证访问（或文档路径可猜测）。
- 文档中列出的用户管理接口没有认证/管理员角色校验。
- 创建接口接受用户名/密码等字段；删除/修改接口以可枚举的用户名作为路径参数。
- 后端未对高频失败/成功请求做速率限制或审计阻断。

## 利用步骤

1. 发现文档：访问 `/swagger-ui.html`、`/swagger-ui/index.html`、`/v2/api-docs`、`/v3/api-docs`、`/doc.html` 等常见路径。
2. 在文档中筛选 `user`、`admin`、`role`、`auth` 相关分组，记录创建/修改/删除接口及参数。
3. 去掉 Cookie/Token，用 Swagger “Try it out” 或 curl 调用创建接口，确认返回成功。
4. 用创建的账号尝试登录；若可登录，确认其角色与可访问功能。
5. 调用删除接口删除测试账号，确认未授权删除可行。
6. 评估批量删除风险：按用户名规则构造字典，先小批量验证，避免造成不可逆破坏（仅在授权范围内）。

## PoC

```bash
# 1. 发现文档
curl -s -o /dev/null -w '%{http_code}\n' 'https://target.example/v2/api-docs'
curl -s -o /dev/null -w '%{http_code}\n' 'https://target.example/swagger-ui/index.html'

# 2. 未授权创建用户
curl -i -X POST 'https://target.example/user' \
  -H 'Content-Type: application/json' \
  -d '{"username":"audit_test_01","password":"P@ssw0rd_2026","email":"audit_test_01@example.com"}'

# 3. 未授权删除用户（按用户名）
curl -i -X DELETE 'https://target.example/user/audit_test_01'
```

```text
# 预期：
# 创建返回 200/成功，响应含用户 id；
# 删除返回 200/成功，响应含被删除的用户名。
```

## 变体与关联

- 变体：`createWithArray`/`createWithList` 批量创建，用于账号轰炸或为后续攻击准备账号。
- 变体：`PUT /user/{username}` 修改密码/角色/状态，可接管现有账号或提升权限。
- 变体：`GET /user/{username}` 未授权读取用户信息（邮箱、手机号、角色），为社工/撞库提供素材。
- 关联：[[web-generic-auth-unauth-user-create-admin-takeover]]（后台新增用户接口的同类问题）；[[web-generic-auth-vue-router-frontend-guard-bypass]]（发现隐藏管理接口的另一条路径）；[[pentest-recon-error-driven-api-param-discovery]]（从报错迭代参数）。
- 边界：删除是破坏性操作，必须严格在授权范围内并先备份；案例中删除按用户名鉴权，意味着知道用户名即可删除，但若后端还有隐藏的角色校验则可能失败。

## 检测与防御

- 检测：扫描公网 Swagger/OpenAPI 路径；审计文档中所有用户管理接口的认证与角色校验；监控未登录状态下的用户创建/删除请求；对批量删除和用户名枚举做告警。
- 修复：生产环境关闭 Swagger 或加认证网关；所有用户管理接口强制管理员角色；删除/修改使用不可枚举的内部 ID 并校验资源归属。
- 加固：对用户管理接口做速率限制与操作审计；敏感操作加二次确认；定期清理测试文档与默认配置。
