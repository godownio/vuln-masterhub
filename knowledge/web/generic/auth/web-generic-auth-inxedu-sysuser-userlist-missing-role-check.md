---
id: web-generic-auth-inxedu-sysuser-userlist-missing-role-check
title: inxedu /admin/sysuser/userlist 只校验登录不校验角色：普通用户会话读取全量后台用户信息
type: scenario
domain: web
path: web/generic/auth
technique: auth-inxedu-sysuser-userlist-missing-role-check
aliases:
- inxedu 越权
- 因酷后台用户列表越权
- sysuser/userlist 无权限校验
- 普通用户访问后台接口
- 前台用户越权读管理员信息
tags:
- access-control
- authorization
- horizontal
- java
- inxedu
- pii
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V555
  verified_at: '2026-11-12T00:19:02+08:00'
  notes: 已通读原文并逐张核读20张图：图13 管理员 Cookie inxedulogin_sys_user_=inxedulogin_sys_user_1 请求 POST /admin/sysuser/userlist（page.currentPage=1&querySysUser.keyword=）返回 admin/inxedu/inxedu@inxedu.com/8888888888/2015-03-17/2024-02-04 16:43/172.27.112.1/正常；图14 同一请求仅把 Cookie 换成 inxedulogin_sys_user_=inxedulogin_sys_user_2 后仍返回同一管理员列表，与卡内 PoC 及响应字段逐字一致；图15 SysUserController.querySysUserList 的 @RequestMapping("/userlist")，page.setPageSize(15)、querySysUserPage、视图 /admin/system/sys-user-list、sysRoleList，方法内无角色/权限判断，与卡内原理一致。dedup 三个 related（BladeX /api/blade-user/list、开放签 getAllUsers、IceCMS userId IDOR）均为不同产品不同接口，非同一链；dup-scan 无配对。未验证点：未本地复放，普通用户账号来源原文未展示；PoC 未本机执行。原文未标版本，不设 affected_versions；frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

inxedu 的后台用户列表接口 `POST /admin/sysuser/userlist` 只依赖登录会话、没有角色/权限校验：把浏览器 Cookie 从管理员 `inxedulogin_sys_user_=inxedulogin_sys_user_1` 换成普通前台用户的 `inxedulogin_sys_user_2` 后，同一个请求仍返回完整的后台用户列表（含 admin 账号、邮箱、手机号、注册 IP、状态等），普通注册用户即可越权获取管理员与他人的敏感信息。

## 原理

- **会话只证明「已登录」不证明「是管理员」**：控制器 `SysUserController.querySysUserList()`（`@RequestMapping("/userlist")`）直接 `page.setPageSize(15)`、调用 `sysUserService.querySysUserPage(querySysUser, page)`、把 `userList` 与角色列表放进 Model 返回视图 `/admin/system/sys-user-list`，方法中没有 `isAdmin`/角色判断/权限注解。
- **Cookie 是唯一身份凭据**：请求带的 `inxedulogin_sys_user_` Cookie 值区分用户（`_1` 为 admin，`_2` 为普通用户）。替换 Cookie 后服务端按该会话加载用户上下文，但接口本身不做资源归属或角色校验，于是低权用户拿到管理员功能的数据。
- **影响面**：返回 HTML 中包含所有后台用户的账号、邮箱（`inxedu@inxedu.com`）、手机号、注册时间、最后登录 IP、状态等 PII；这些信息可用于撞库、钓鱼、进一步社工管理员。
- **本题的本质**：垂直越权/功能级访问控制缺失——后台管理端点的 URL 路径（`/admin/...`）不是安全边界，真正的边界应在服务端按角色授权；仅靠「后台菜单不展示」或「随便一个登录态」不能阻止直接访问。

## 触发条件

- 目标为 inxedu（因酷在线教育）开源版。
- 攻击者拥有任意一个可登录的前台/普通用户会话（Cookie `inxedulogin_sys_user_*`）。
- `/admin/sysuser/userlist` 未做角色校验（原文代码无权限判断），仅要求会话有效。
- 后台路由未与前台路由做网络/网关层隔离。

## 利用步骤

1. 用管理员登录后台，访问「系统管理-用户管理」，抓 `POST /admin/sysuser/userlist` 请求，确认返回含用户列表的 HTML。
2. 退出登录，用普通用户账号登录，获取其 Cookie（如 `inxedulogin_sys_user_=inxedulogin_sys_user_2`）。
3. 复用第 1 步的请求，仅替换 Cookie 为普通用户会话，重放。
4. 响应仍返回完整后台用户列表；从 HTML 中提取管理员账号、邮箱、手机号、IP 等信息。
5. 视需要遍历 `page.currentPage` 与 `querySysUser.keyword` 拉取全部用户。

## PoC

```http
POST /admin/sysuser/userlist HTTP/1.1
Host: 127.0.0.1:81
Cookie: JSESSIONID=<普通用户会话>; inxedulogin_sys_user_=inxedulogin_sys_user_2
Content-Type: application/x-www-form-urlencoded

page.currentPage=1&querySysUser.keyword=
```

响应（普通用户会话）仍包含：

```html
<td align="center">admin</td>
<td align="center">inxedu</td>
<td align="center">inxedu@inxedu.com</td>
<td align="center">8888888888</td>
<td align="center">2015/03/17</td>
<td align="center">2024/02/04 16:43</td>
<td align="center">172.27.112.1</td>
<td align="center">正常</td>
```

## 变体与关联

- 变体：同项目其它 `/admin/**` 接口若同样只校验会话，可扩展为越权删除/修改（如文章删除接口）；结合 SQLi 可进一步扩大危害。
- 关联：[[web-generic-auth-oa-downloadfilter-protectfilter-path-substring-bypass]]（鉴权路径匹配缺陷的另一形态）、[[web-generic-auth-deepaudit-user-list-missing-role-check-pii-leak]]（同型「登录即可拉全量用户」）。
- 边界：需要有效普通用户账号；若网关层对 `/admin` 做了 IP 白名单/二次认证，则无法直达。

## 检测与防御

- 修复：后台所有 `/admin/**` 接口在服务端做角色/权限校验（RBAC 注解或拦截器），统一鉴权，不依赖 URL 前缀或前端菜单。
- 加固：管理员与普通用户会话分离（不同 Cookie/不同域名/不同会话表）；敏感列表接口做数据脱敏；后台入口限制来源 IP 与二次认证。
- 检测：审计控制器是否存在无权限注解/无角色判断的 `@RequestMapping` 方法；监控普通用户会话访问 `/admin/**` 的行为并告警。
