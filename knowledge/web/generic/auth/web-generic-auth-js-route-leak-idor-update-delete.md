---
id: web-generic-auth-js-route-leak-idor-update-delete
title: 前端 JS 泄露隐藏接口：新注册账号调 list 拿他人记录，再用返回数据调 update/delete 越权
type: scenario
domain: web
path: web/generic/auth
technique: frontend-js-route-leak-object-authz-update-delete
aliases:
- 前端路由泄露越权
- JS 接口清单越权
- KeyAssistance 越权
- 隐藏接口 list/update/delete
- 对象级授权缺失
tags:
- web
- auth
- idor
- authorization
- frontend
- js
- api
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V231
  verified_at: '2026-11-07T09:49:11+08:00'
  notes: 已对照原文与图54-59核对：新注册账号无数据；JS 泄露 KeyAssistance list/update/delete 等路由；list 返回他人记录 id=766；复制记录改 cityPacName=999... 后 update 成功。原文仅实测 update，delete 为同类推断，未实测；未复跑。
---

## 一句话结论

系统前端 JS bundle 里直接写死了完整 API 路由表（`KeyAssistance/list`、`detail`、`add`、`update`、`delete`、`listExport` 以及 home-visit 等隐藏功能），新注册账号本身没有任何数据，但直接调用这些未在菜单中暴露的接口，`list` 会返回他人业务记录；把返回记录（含 `id`）复制到 `update`/`delete` 请求并修改字段，接口不校验对象归属与功能权限，即可越权修改/删除他人数据，形成“前端路由泄露 + 对象级/功能级授权缺失”的越权链。

## 原理

- 前端路由泄露：SPA 的 `app.*.js`/`chunk-*.js` 中常把全部 API 路径、菜单路径、按钮权限写成常量（如 `keyAssistanceList: '/web/support-service/v1/hnfc/KeyAssistance/list'`、`keyAssistanceUpdate: '.../update'`、`keyAssistanceDelete: '.../delete'`、`keyAssistanceExport: '.../listExport'`），即使菜单/按钮被权限隐藏，接口字符串仍在客户端可见。
- 后端授权缺失：服务端只依赖前端菜单做“功能隐藏”，没有在每个接口上做功能级授权；`list` 没有把查询范围绑定到当前用户/租户，新注册账号也能拿到数据（原文用新账号测试，返回了他人记录）。
- 对象级授权缺失：`update`/`delete`/`detail` 只按记录 `id` 操作，不校验该记录是否属于当前用户；攻击者从 `list` 响应中拿到 `id` 及完整字段，复制到更新请求中，修改一个字段即可更新他人记录。
- 发现方法：写脚本爬取前端 JS 得到 100+ 个接口，构造字典逐个请求；大量 403/504/400 中少数返回数据，返回包中的字段（`id`、`provincePacId`、`cityPacId` 等）可用于构造 update/delete 请求；全局搜索同一路径还能找到新增、删除、编辑、导出等兄弟接口。
- 为什么成立：前端可见 ≠ 后端授权；隐藏菜单只是 UI 层控制；列表接口返回的对象 id 为越权写操作提供了有效主键；更新接口直接信任请求体中的完整对象，没有字段级/归属校验。

## 触发条件

- 目标为 SPA/前后端分离系统，前端 JS 可访问且包含 API 路由常量。
- 攻击者能注册/获得一个低权限账号（原文注册账号无数据）。
- 隐藏接口在服务端可达，且没有功能级授权（不要求管理员/教师角色）。
- `list`/`detail` 返回的数据包含可复用主键（`id`）与更新所需字段。
- `update`/`delete` 只按主键操作，不校验对象归属；请求体接受客户端提交的完整对象。

## 利用步骤

1. 注册/登录一个低权限账号，确认账号本身没有业务数据。
2. 打开前端 JS（`app.*.js`、`chunk-*.js`），搜索 `url:`、`/web/`、`/api/` 等，提取全部 API 路由；也可用爬虫/JS 美化工具批量提取。
3. 对提取的接口构造字典（GET/POST、空参数/默认参数）批量请求，记录返回 200 且有 `data` 的接口。
4. 重点看 `list`/`detail` 返回的字段（`id`、`provincePacId`、`cityPacId`、`cityPacName` 等），复制一条完整记录作为 update 请求体。
5. 修改其中一个字段（原文把 `cityPacName` 改为 `99999...`），调用 `update`；再调用 `list`/`detail` 确认该记录被修改。
6. 用同一 `id` 调用 `delete` 验证删除权限；继续测试 `add`、`listExport`、home-visit 等兄弟接口，扩大越权面；仅在授权范围内操作。

## PoC

```http
# 1) 新注册账号直接调用隐藏 list 接口，拿到他人记录
GET /web/support-service/v1/hnfc/KeyAssistance/list HTTP/1.1
Host: <target>
Cookie: <low-priv-session>

HTTP/1.1 200 OK
{
  "result": 1,
  "msg": "成功",
  "data": [
    {
      "id": 766,
      "provincePacId": "...",
      "cityPacId": "...",
      "cityPacName": "...",
      "countyPacId": "...",
      "countyPacName": "...",
      "countryPacId": "...",
      "countryPacName": "..."
    }
  ]
}
```

```http
# 2) 复制记录到 update，修改字段（原文把 cityPacName 改为 99999...）
POST /web/support-service/v1/hnfc/KeyAssistance/update HTTP/1.1
Host: <target>
Cookie: <low-priv-session>
Content-Type: application/json

{
  "id": 766,
  "provincePacId": "...",
  "cityPacId": "...",
  "cityPacName": "999999999999999999999999999999999",
  "countyPacId": "...",
  "countyPacName": "...",
  "countryPacId": "...",
  "countryPacName": "..."
}

HTTP/1.1 200 OK
{"result":1,"msg":"成功"}
```

```http
# 3) 再次 list/detail 确认记录被修改；delete 同理
GET /web/support-service/v1/hnfc/KeyAssistance/detail?id=766 HTTP/1.1
Host: <target>
Cookie: <low-priv-session>
```

原文 JS 中泄露的兄弟接口（节选）：

```text
keyAssistanceList:   /web/support-service/v1/hnfc/KeyAssistance/list
keyAssistanceCommit: /web/support-service/v1/hnfc/KeyAssistance/commit
keyAssistanceDelete: /web/support-service/v1/hnfc/KeyAssistance/delete
keyAssistanceDetail: /web/support-service/v1/hnfc/KeyAssistance/detail
keyAssistanceAdd:    /web/support-service/v1/hnfc/KeyAssistance/add
keyAssistanceUpdate: /web/support-service/v1/hnfc/KeyAssistance/update
keyAssistanceExport: /web/support-service/v1/hnfc/KeyAssistance/listExport
homeVisitUrge / homeVisitContentList / homeVisitContentEdit / homeVisitContentDelete ...
```

## 变体与关联

- 变体（接口类型）：`list`/`detail` 读数据，`update`/`delete` 改数据，`add` 可伪造数据，`export` 批量导出；先找返回数据最多的接口，再找兄弟写接口。
- 变体（发现方式）：JS 常量搜索、SourceMap、Swagger/API 文档、前端路由表、字典 fuzz；原文还用了爬虫抓 100+ 接口。
- 变体（授权缺陷）：服务端可能只校验“已登录”不校验角色（垂直越权），或校验角色但不校验对象归属（水平越权）；两者常同时存在。
- 关联：[[web-generic-auth-missing-function-level-role-check]]（拦截器只验登录不验角色）、[[web-generic-auth-teacher-roster-api-student-token-lesson-enumeration]]（学生 Token 调教师接口）、[[web-generic-auth-deepaudit-user-list-missing-role-check-pii-leak]]（用户列表越权）。
- 边界：服务端对每个接口做角色与对象归属校验、`update`/`delete` 强制从会话取用户/租户并校验记录归属、返回数据不含可复用主键时，链路不成立；原文为授权 SRC 测试，未对生产数据造成破坏。

## 检测与防御

- 修复：每个接口（尤其 list/detail/update/delete/export）在服务端做功能级授权与对象级授权；更新/删除先从数据库按 id 取记录并校验 `owner_id`/`tenant_id` 与当前会话一致；请求体不接受客户端提交的 owner/tenant 字段。
- 加固：前端菜单/按钮隐藏只作为体验，不作为安全边界；对 API 路由做统一鉴权中间件，默认拒绝、显式放行；导出接口加权限与审计。
- 检测：低权限账号调用未在菜单中出现的接口；同一账号短时间内枚举大量 API 路径；`update`/`delete` 请求的 id 与当前用户数据无关联；导出接口异常大批量下载。
- 审计：对比前端 JS 路由清单与服务端鉴权配置，找出“前端隐藏但后端未授权”的接口；对新增接口做安全评审与自动化越权测试（替换 id/tenant）。
