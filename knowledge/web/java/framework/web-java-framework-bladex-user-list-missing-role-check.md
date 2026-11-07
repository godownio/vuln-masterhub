---
id: web-java-framework-bladex-user-list-missing-role-check
title: BladeX /api/blade-user/list 只校验登录不校验角色：低权限账号读取管理员账号与联系方式
type: scenario
domain: web
path: web/java/framework
technique: bladex-user-list-missing-role-check
aliases:
- BladeX 用户列表越权
- blade-user list 未授权
- BladeX 垂直越权
- BladeX 用户信息泄露
- blade-user page 参数删除
tags:
- java
- bladex
- spring-cloud
- authz
- vertical-privilege-escalation
- idor
- pii
- user-enumeration
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V242
  verified_at: '2026-11-07T13:43:14+08:00'
  notes: 已对照原文与 img/18、img/19 核对：/api/blade-user/page?current=1&size=... 改为 /api/blade-user/list 并删参数后，低权限账号返回 admin 的 account/name/realName/email/phone/deptId/roleName 等字段，与截图一致；未复跑目标。原文未给受影响区间，affected_versions 保持为空。
---

## 一句话结论

BladeX 的 `/api/blade-user/list` 只要求有效登录态、不校验调用者角色与数据权限；普通账号把用户管理的 `/api/blade-user/page` 改成 `/api/blade-user/list` 或删除筛选参数，即可返回全量用户记录，其中包含 `admin` 的账号、姓名、邮箱、手机号、部门与角色，形成垂直越权和管理员信息泄露。

## 原理

- BladeX 前端（Saber）按菜单/按钮做权限展示，但后端的用户控制器方法没有对应的角色注解或数据范围校验，属于典型的“前端鉴权、后端放行”。
- `/api/blade-user/page` 用于分页查询当前可管理用户，理论上应按租户/角色收窄；`/api/blade-user/list` 则是返回列表的另一个入口，代码路径更短，直接查全量用户。
- 该案例中，测试账号 `test1` 登录后，抓包发现 `/api/blade-user/page?current=1&size=10` 正常返回；随后把请求改成 `/api/blade-user/list`，删除其余筛选参数，响应中出现了 `account: admin`、`name/realName: 管理员`、`email`、`phone`、`deptId`、`roleName` 等字段。
- 根因不是“猜到了管理员 ID”，而是接口本身缺少功能级授权：只要登录就能列出所有用户，因此低权限账号也能拿到管理员身份信息，为后续撞库、钓鱼、社工或结合其他越权接口提供靶标。

## 触发条件

- 目标为 BladeX 后台，攻击者持有任意有效低权限账号（该案例通过验证码不刷新 + 口令爆破获得 `test1`）。
- `/api/blade-user/list`、`/api/blade-user/page` 等用户查询接口可达。
- 后端未做角色/权限注解校验，也未按租户或部门做数据范围过滤。
- 响应未被网关裁剪敏感字段（邮箱、手机号等）。

## 利用步骤

1. 用低权限账号登录后台，进入用户管理页面，用代理抓取用户列表请求（通常是 `/api/blade-user/page?current=1&size=10`）。
2. 将该请求改为 `/api/blade-user/list`，或删除 `current`/`size`/部门/角色等筛选参数，保持同一低权限 token。
3. 检查响应中的 `account`、`name`、`realName`、`email`、`phone`、`deptId`、`postId`、`roleName` 等字段，确认是否返回了非本部门/管理员记录。
4. 用返回的账号信息做进一步利用：管理员账号撞库、钓鱼、结合日志接口泄露的口令直接登录，或按用户 ID 尝试详情/改密接口的 IDOR。
5. 若 `/list` 被拦截，继续尝试 `/api/blade-user/page` 去掉筛选条件、`/api/blade-user/detail?id=`、`/api/blade-system/tenant/select` 等相邻接口。

## PoC

```http
GET /api/blade-user/list HTTP/1.1
Host: target
Authorization: Bearer <低权限 token>
Cookie: <低权限会话>
```

响应片段（字段值已占位）：

```json
{
  "tenantId": "000000",
  "account": "admin",
  "name": "管理员",
  "realName": "管理员",
  "email": "<admin email>",
  "phone": "<admin phone>",
  "deptId": "<dept>",
  "roleName": "超级管理员"
}
```

对照请求：

```http
GET /api/blade-user/page?current=1&size=10 HTTP/1.1
Host: target
Authorization: Bearer <低权限 token>
```

该案例通过把 `page` 请求改为 `list` 并删除其余参数完成越权，说明接口没有基于角色/数据范围的过滤。

## 变体与关联

- 变体：直接保留 `/api/blade-user/page`，删除 `deptId`/`roleId` 等筛选参数，或把 `size` 调大，批量拉取用户。
- 变体：`/api/blade-user/info`、`/api/blade-user/detail` 等按 ID/账号查询的接口若同样缺少归属校验，可结合本卡拿到的用户 ID 做水平越权。
- 变体：其他 BladeX 系统模块（角色、部门、租户、字典）也可能存在相同的“只验登录不验权限”问题，按 `/api/blade-*/list|page` 批量探测。
- 关联：[[web-generic-auth-missing-function-level-role-check]]（拦截器只验登录不验角色）。
- 关联：[[web-generic-auth-deepaudit-user-list-missing-role-check-pii-leak]]、[[web-generic-auth-kaifangqian-user-controller-missing-permission]]（其他系统的用户列表缺权限案例，可对比接口形态）。
- 关联：[[web-java-framework-bladex-log-api-list-credential-leak]]（本卡拿到的管理员账号可用于匹配日志泄露的口令）。

## 检测与防御

- 后端强制功能级授权：用户列表/详情/导出接口加管理员或相应角色注解，按租户、部门、数据范围过滤，不能只依赖前端菜单。
- 最小字段返回：列表接口不返回邮箱、手机号、角色等非必要字段；需要时单独授权并按需脱敏。
- 统一鉴权：在网关或全局拦截器中对 `/api/blade-*` 路径做角色与资源归属校验，避免新增接口漏配。
- 检测特征：低权限账号请求 `/api/blade-user/list`、`/api/blade-user/page` 时返回全量或跨部门记录；`size` 异常增大；短时间内枚举用户详情。
- 审计与响应：记录用户列表查询日志，发现越权后排查是否被用于撞库/钓鱼，并重置相关管理员凭据。
