---
id: web-generic-auth-icecms-square-comment-api-missing-jwt
title: IceCMS 广场/评论接口缺失 JWT 校验（CVE-2023-6757/6758）：未授权读取全站用户表与篡改评论
type: scenario
domain: web
path: web/generic/auth
technique: icecms-square-comment-api-missing-jwt
aliases:
- IceCMS 接口未授权
- CVE-2023-6757
- CVE-2023-6758
- GetAllSquareUser 未授权
- ChangeSquareById 未授权
- 广场用户信息泄露
tags:
- authz
- broken-access-control
- icecms
- jwt
- unauth
- info-disclosure
- java
- spring-boot
cve:
- CVE-2023-6757
- CVE-2023-6758
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
affected_versions: Thecosy IceCMS 2.0.1
verification:
  verified_by: verifier-V442
  verified_at: '2026-11-09T23:10:30+08:00'
  notes: 已对照原文与图14-16/18-20/36/40-43核对：空 Authorization 请求 /square/GetAllSquareUser 返回含 username/password/email 的全量用户 JSON，/squareComment/ChangeSquareById/122/hello 空 Authorization 返回1并成功改评论，/squareComment/getAllSquare/1/8 空 Authorization 返回评论列表；图1 VulDB 中 CVE-2023-6757 为 /adplanet/PlanetUser 信息泄露、CVE-2023-6758 为 /adplanet/PlanetCommentList 访问控制错误，映射成立。未验证点：原文未展示服务端拦截器代码，仅黑盒验证。
---

## 一句话结论

IceCMS 前端虽然全局带 JWT，但部分广场/评论接口在服务端没有校验它：直接 `GET /square/GetAllSquareUser` 就能拿到全站用户数组（含用户名、明文口令示例、邮箱、角色等），`GET /squareComment/ChangeSquareById/{id}/{content}` 不带 Authorization 也能把指定评论改成任意内容，`GET /squareComment/getAllSquare/{page}/{size}` 同样可未授权读取评论列表（CVE-2023-6757/6758）。

## 原理

- **鉴权只在前端**：Vue 前端在请求头里放 `Authorization: Bearer <JWT>`，但 Spring Boot 后端只对部分路由挂 JWT 拦截器/过滤器；广场与评论相关 Controller 未被覆盖，导致带不带 token 都能访问。
- **`GetAllSquareUser` 泄露面**：响应是整个用户表的 JSON 数组，字段包括 `userId`、`userAge`、`intro`、`gender`、`name`、`username`、`password`、`email`、`role`、`profile`、`status`、`created`、`lastLogin`、`vip*`、`integral` 等；示例数据中 `password` 为可读口令，等价于全站账号泄露。
- **`ChangeSquareById` 篡改**：路径参数直接决定目标对象与新内容，服务端既不校验 JWT 也不校验归属，返回 `1` 即修改成功；攻击者枚举 ID 即可批量篡改他人评论。
- **`getAllSquare` 读取**：分页接口同样无鉴权，可作为 ID 枚举与内容侦察的数据源。
- **危害链**：未授权拿到账号口令/邮箱 → 撞库或口令复用登录后台；再结合 `ChangeUser` 越权（另卡）可直接接管管理员。即使口令加密存储，用户枚举 + 邮箱也足以支撑钓鱼与横向。
- **判定要点**：删除请求中的 `Authorization` 头后仍返回完整数据/成功标志，且换一个干净浏览器（无 JWT）直接访问同样成立，可排除前端缓存或代理伪造。

## 触发条件

- 目标为 IceCMS 2.0.1（CVE-2023-6757/6758）。
- 后端服务的广场/评论接口可从外网访问（默认 8181 端口，前端 9528 代理）。
- 目标使用默认或可枚举的对象 ID；无需任何账号即可发起读取/篡改。

## 利用步骤

1. 访问前端或直接探测后端端口，确认 `/square/GetAllSquareUser` 可达。
2. 不带任何 `Authorization` 头请求，读取用户数组，收集 username/password/email/role。
3. 从广场/评论列表取目标评论 ID，请求 `/squareComment/ChangeSquareById/{id}/{新内容}`，返回 `1` 即篡改成功。
4. 用拿到的账号口令尝试登录后台；若口令被哈希则转入口令喷洒/钓鱼。
5. 结合 `/squareComment/getAllSquare/{page}/{size}` 批量拉取评论，枚举更多对象 ID。

## PoC

```bash
# 未授权读取全站用户（含示例明文口令字段）
curl -s "http://target:8181/square/GetAllSquareUser"

# 未授权修改 ID=122 的评论内容为 hello，返回 1 表示成功
curl -s "http://target:8181/squareComment/ChangeSquareById/122/hello"

# 未授权读取第 1 页、每页 8 条的评论
curl -s "http://target:8181/squareComment/getAllSquare/1/8"
```

实测删除 `Authorization` 头后三个请求均正常返回；换干净浏览器直接访问同样成立。

## 变体与关联

- 变体：同产品其他广场/文章接口同样可能漏挂 JWT，可按 Controller 路由字典批量探测“带/不带 token 响应一致”。
- 变体：若响应被前端隐藏，直接请求后端端口或改 `Accept: application/json` 可拿到原始 JSON。
- 关联：[[web-generic-auth-icecms-user-changeuser-idor]]（拿到账号后利用 userId 越权接管管理员）；[[web-generic-auth-icecms-delete-by-id-idor]]（同产品的删除接口越权）；[[web-generic-auth-cmsv6-standardlogin-getalluser-unauth]]（同类 CMS 用户表未授权泄露）。

## 检测与防御

- 检测：对敏感接口做“带 token / 不带 token / 过期 token”三路对照，响应体或状态码一致即疑似未授权；网关日志中出现无 Authorization 的 `/square/GetAllSquareUser` 等请求。
- 防御：统一在网关/过滤器层对全部 API 强制 JWT 校验（白名单仅登录/注册/公开内容）；Controller 内做对象级权限校验；响应中永不返回口令字段；对接口做鉴权覆盖测试并纳入 CI。
