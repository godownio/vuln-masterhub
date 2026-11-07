---
id: web-generic-auth-chartbrew-legacy-dashboard-team-role-idor-password-leak
title: Chartbrew 遗留 dashboard 路由只校验同团队角色不校验项目成员：同团队低权用户越权读取任意项目仪表盘并泄露原始 report password（CVE-2026-40603）
type: scenario
domain: web
path: web/generic/auth
technique: legacy-route-team-role-only-missing-project-object-authz-raw-password-leak
tags:
- nodejs
- express
- sequelize
- chartbrew
- idor
- authz
- missing-authorization
- object-level-authorization
- legacy-route
- password-leak
- cwe-284
- cve-2026-40603
cve:
- CVE-2026-40603
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V114
  verified_at: '2026-11-06T01:52:14+08:00'
  notes: 已对照原文图09（GitHub Advisory 全文截图）核对：CVE-2026-40603、CVSS 3.1 AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N=6.5、CWE-284；server/api/ProjectRoute.js 的 /project/dashboard/:brewName 仅用 getTeamRole(project.team_id, req.user.id) 做团队级判断，未校验 teamRole.projects.includes(project.id)；getPublicDashboard 按 brewName findOne 并 include Chart(onReport:true)/SharePolicy；路由 __cloneDeep+setDataValue('password','') 生成 processedProject 却返回原始 project；PoC GET /api/project/dashboard/sales_dashboard_42 与 Impact 均一致。原文/截图未给受影响版本区间（图08的 5.0.1 是审计目标版本），未设 affected_versions；PoC 未在本库环境复跑。
url: /docs/web/generic/auth/web-generic-auth-chartbrew-legacy-dashboard-team-role-idor-password-leak/
draft: false
kb_aliases:
- CVE-2026-40603
- Chartbrew 越权
- Chartbrew dashboard IDOR
- 遗留路由缺对象级授权
- brewName 越权
- 同团队水平越权
- 报表密码泄露
- getPublicDashboard 返回原始对象
---

## 一句话结论

Chartbrew 的遗留路由 `GET /api/project/dashboard/:brewName` 只校验请求者是该项目所属团队的任意成员，不校验其对具体项目是否有权限；而且它构造了清空 password 的副本却最终返回原始 Sequelize Project 对象，导致同团队低权用户用可猜的 brewName 读取他人仪表盘数据并拿到原始 report password（CVE-2026-40603，CVSS 6.5，CWE-284）。

## 原理

- Chartbrew 有团队（Team）与项目（Project）两层权限。团队角色只说明“能进这个团队”，项目成员关系（`teamRole.projects.includes(project.id)`）才说明“能看这个项目”。较新的 share-policy 路径会做项目级校验，遗留 dashboard 路由则只调用 `getTeamRole(project.team_id, req.user.id)` 判断请求者在团队里有没有角色。
- `getPublicDashboard(brewName)` 直接按 `brewName` 做 `db.Project.findOne`，并 include Chart（`onReport: true`）与 SharePolicy 关联对象，返回的是未脱敏的 ORM 实例。
- 路由中对结果做了 `__cloneDeep(project)` 并 `setDataValue("password", "")` 生成 `processedProject`，但最终响应发送的是原始 `project`，脱敏副本从未被使用。因此“脱敏”只是看起来存在，实际响应仍带 `password` 字段。
- brewName 通常是语义化、可分享的仪表盘名（如 `sales_dashboard_42`），同团队成员可以通过项目列表、报表链接、历史消息等途径获知或猜测，从而把“同团队”权限放大为“读取任意项目报表”。
- 泄露的 report password 还可能被用于访问受该口令保护的公开报表，进一步削弱报表分享面的访问控制。

## 触发条件

- 攻击者已认证，且与受害者项目属于同一 team；角色不限，包括未被授予该项目访问权的低权成员。
- 攻击者知道或能猜出目标项目的 `brewName`。
- 目标实例使用含该遗留路由的 Chartbrew 版本，且未额外加项目级授权中间件。

## 利用步骤

1. 以同团队普通成员身份登录 Chartbrew，取得 Bearer token。
2. 枚举同团队其他项目的 `brewName`：项目列表、仪表盘分享链接、报表 URL、聊天记录或常见命名。
3. 发送 `GET /api/project/dashboard/<brewName>`，携带该低权用户的 Bearer token。
4. 读取响应中的图表数据、dashboard filters、share policy 配置，以及原始 `password` 字段。
5. 用泄露的 report password 访问受保护的公开报表，或结合其他接口继续横向。

## PoC

```http
GET /api/project/dashboard/sales_dashboard_42 HTTP/1.1
Host: <chartbrew-host>
Authorization: Bearer <same_team_user_without_project_access>
```

响应返回受害者仪表盘对象，包含 charts、dashboard filters、share policy 数据及原始 `password` 字段。该请求来自文章中的漏洞报告，未在本库环境复跑。

## 变体与关联

- 业务键变体：把 `brewName` 换成数字 id、UUID、slug 或其他可枚举键，检查遗留接口是否同样只做团队级校验。
- 新旧接口并存变体：新版 share-policy 路径有项目级校验，旧路由未同步；任何“重构后遗留的兼容接口”都可能保留旧授权逻辑。
- 脱敏失败变体：同时存在 `processedProject` 与 `project` 两个对象时，检查最终 `res.send/return` 指向哪一个；同类问题也常见于日志、导出和 GraphQL resolver。
- 关联卡片：[[web-generic-auth-azuriom-servers-route-missing-gate-token-account-takeover]]（路由缺权限中间件）、[[web-generic-auth-mall-cancel-user-order-idor]]（资源归属未校验的水平越权）。

## 检测与防御

- 代码审计：搜索所有 `res.send(project)`、`return project` 与 `setDataValue("password", "")`/DTO 脱敏逻辑并存的位置，确认返回的是脱敏副本；检查遗留路由是否调用新版项目级授权函数。
- 统一授权：在路由层或集中 policy 强制校验 `teamRole.projects.includes(project.id)`，不能只校验 team 成员身份；删除或下线不再使用的遗留 dashboard 路由。
- 响应白名单：用显式 DTO/字段白名单序列化，禁止直接返回 ORM 实体；`password` 等敏感字段永不进入响应。
- 监控：同团队账号短时间遍历多个 `brewName`、大量 404/403、响应体出现 `password` 字段时告警。
- 修复验证：用无该项目权限的同团队账号请求目标仪表盘，应返回 403/404 而不是项目对象。
