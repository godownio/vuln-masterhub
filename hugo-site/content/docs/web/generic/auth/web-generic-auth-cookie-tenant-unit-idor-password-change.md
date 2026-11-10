---
id: web-generic-auth-cookie-tenant-unit-idor-password-change
title: 多租户系统 Cookie 单位编号/队伍编号未绑定会话：遍历 dw_id/yh_dm 跨校越权并修改密码
type: scenario
domain: web
path: web/generic/auth
technique: cookie-tenant-unit-idor-password-change
tags:
- web
- auth
- authz
- idor
- broken-access-control
- multi-tenant
- cookie
- password-change
- education
- horizontal-privilege-escalation
- vertical-privilege-escalation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-08T00:06:50+08:00'
  notes: 已对照全文与 27 图核对：图 21/22 登录 001 与 Cookie yh_dm=008;dw_id=001，图 23/24 改 dw_id=002 后返回另一单位(002)我的资料，图 25/26 改 yh_dm=011 后进入重庆某校页面且显示单位信息，均与卡片一致；改密接口路径为示意（原文只说明可修改密码，未给路径），卡内已注明关键在编号未绑定会话。未验证点：原文未展示改密 POST 与用新密码登录的截图。dedup top1 为自身，其余为不同越权模式；保留。
url: /docs/web/generic/auth/web-generic-auth-cookie-tenant-unit-idor-password-change/
draft: false
kb_aliases:
- yh_dm 越权
- dw_id 越权
- 单位编号遍历
- 队伍编号遍历
- 跨校越权
- 多租户 Cookie 越权
- 越权修改密码 教育系统
---

## 一句话结论

多租户系统把“学校编号 + 队伍编号”（如 Cookie 中的 `yh_dm=008`、`dw_id=001`）当作当前身份标识，服务端只校验“已登录”而不校验这两个编号是否属于当前会话；修改 `dw_id` 可越权到同校其他队伍，修改 `yh_dm` 可跨到其他学校（001-058），并能进入目标单位的“我的资料/修改密码”页面，实现跨租户账号接管。

## 原理

- 系统以“单位（学校）+ 队伍”为租户模型，登录后把 `yh_dm`（学校/单位编号）和 `dw_id`（校内队伍编号）写入 Cookie，后端每个请求直接从 Cookie 读取这两个值作为当前租户/队伍身份。
- 登录只校验单位账号与口令；会话 Cookie 中的身份字段是明文且没有签名绑定，或虽然存在服务端会话但业务代码仍信任 Cookie 里的编号，形成客户端可控的授权标识。
- 业务查询/更新以 `where yh_dm=? and dw_id=?` 之类的条件定位数据，但没有额外校验该记录是否属于当前登录单位；因此改哪个编号，就能读/写哪个单位或队伍的数据。
- “我的资料”页面提供登录密码修改，提交时同样以 Cookie 中的编号定位目标单位，因此水平/跨租户读写会直接升级为“越权修改密码”，进而接管其他单位账号。
- 根本原因是对象/租户标识由客户端控制且缺少服务端授权校验（broken access control），不是单纯的“Cookie 可以编辑”；只有前端展示差异、后端仍按会话过滤时不成立。

## 触发条件

- 系统为多学校/多单位共用，Cookie 或请求参数包含可枚举的单位编号、队伍编号、用户编号等身份字段。
- 后端信任该字段定位数据，不校验其与当前会话主体的绑定关系。
- 攻击者持有任意一个有效单位账号（例如通过初始口令登录获得）。
- 编号可枚举（如学校 001-058、队伍 001、002……）。

## 利用步骤

1. 用任意单位账号登录，打开开发者工具或抓包，查看 Cookie 与请求参数中的身份字段（本例为 `yh_dm`、`dw_id`）。
2. 在站内切换功能，确认哪些请求携带这两个字段；将 `dw_id` 从当前值改为相邻值（如 001→002），刷新页面时同步修改所有相关请求。
3. 观察响应是否返回另一队伍/单位的“我的资料”，核对单位名称、联系人与当前账号不同，确认校内横向越权。
4. 将 `yh_dm` 改为其他学校编号（如 001-058），重复第 2-3 步，验证跨校访问与页面所属赛事变化。
5. 在越权得到的“我的资料”页面修改登录密码（提交时保持篡改后的 Cookie），即可接管目标单位账号；测试前确认授权范围，避免破坏生产数据。
6. 用新密码登录目标账号验证接管，记录请求与响应作为证据。

## PoC

```http
GET /unit/profile HTTP/1.1
Host: target
Cookie: yh_dm=008; dw_id=002; <其他会话字段>
```

```http
POST /unit/updatePassword HTTP/1.1
Host: target
Cookie: yh_dm=011; dw_id=001; <其他会话字段>
Content-Type: application/x-www-form-urlencoded

newPassword=<new>&confirmPassword=<new>
```

```text
# 关键点不是路径，而是 yh_dm/dw_id 来自客户端且服务端未绑定会话。
# 若页面刷新会并发多个请求，需要同时修改每个请求中的 dw_id/yh_dm。
```

## 变体与关联

- 变体：字段名可能是 `schoolId`、`orgId`、`tenantId`、`teamId`、`userId`，位置可能在 Cookie、URL 查询串、隐藏表单或 JWT 明文 claim 中。
- 变体：只改一个编号即可横向（同校队伍）或纵向（跨校/跨租户）；若还存在角色/权限字段，可进一步尝试提升为管理员。
- 关联：[[web-generic-auth-authenticated-change-password-idor]]（改密接口 username 可控）、[[web-generic-auth-multitenant-tenant-header-missing-superadmin]]（多租户身份头缺失）、[[web-generic-auth-roleid-roleids-parameter-tampering-admin]]（角色参数篡改）、[[web-generic-auth-education-exam-studentid-dto-idor]]（教育系统 studentId 参数越权）。
- 边界：服务端从会话或签名 token 中取租户/队伍身份、或对编号做归属校验时失效；仅 UI 不同但后端按会话过滤也不成立。

## 检测与防御

- 检测：同一会话短时间内使用不同 `yh_dm`/`dw_id`/`tenantId` 访问；响应中的单位名称、队伍名称与会话账号不一致；改密请求的目标编号与会话主体不一致。
- 修复：租户/队伍/用户身份一律从服务端会话或签名 token 获取，禁止客户端提交身份字段；所有对象级操作校验归属。
- 加固：Cookie 使用签名/加密并绑定服务端会话；对身份字段做白名单与格式校验；改密等敏感操作要求二次认证、记录审计并告警；对编号遍历做速率限制。
