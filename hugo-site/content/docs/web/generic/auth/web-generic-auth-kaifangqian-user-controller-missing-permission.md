---
id: web-generic-auth-kaifangqian-user-controller-missing-permission
title: 开放签 sys/user/getAllUsers 与 userInfo 缺权限注解：任意登录用户越权枚举/查看用户信息
type: scenario
domain: web
path: web/generic/auth
technique: spring-shiro-missing-requirespermissions-user-enumeration
tags:
- auth
- authz
- broken-access-control
- idor
- pii
- spring
- shiro
- mybatis-plus
- java
- oa
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V216
  verified_at: '2026-11-07T04:43:55+08:00'
  notes: 已对照原文与25张图核对：getAllUsers 无 @RequiresPermissions 返回 userId/username/realname（Content-Length 3481704≈3.4MB），userInfo 无注解按 id 返回 phone/部门（截图中字段打码），均与卡一致；注解式权限模型由 SysAppVersionController @RequiresPermissions("system:develop") 佐证。未验证点：原文未说明测试账号角色，“任意登录用户”由缺注解+JwtFilter只验登录推断；未跨租户/其他接口实测；原文未标版本；frontmatter无sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-kaifangqian-user-controller-missing-permission/
draft: false
kb_aliases:
- 开放签越权
- 开放签用户信息泄露
- sys/user/getAllUsers 越权
- sys/user/userInfo IDOR
- 缺少 RequiresPermissions
- 登录用户枚举全量账号
- 电子签章系统越权
---

## 一句话结论

开放签电子签章系统（Spring Boot + Shiro + JWT）的 `SysUserController.getAllUsers` 与 `userInfo` 两个方法都没有标注 `@RequiresPermissions` 权限注解；任意持有有效登录 token 的普通用户都能直接调用：前者返回全量用户 id/账号/真实姓名，后者按任意 `id` 查询用户详情（含手机号等字段），形成账号枚举、PII 泄露与水平越权。

## 原理

- 项目采用注解式权限模型：例如 `SysAppVersionController.queryPageList` 标注了 `@RequiresPermissions("system:develop")`，说明开发者依赖 Shiro 的方法级权限注解来区分管理员与普通用户。
- 但 `SysUserController.getAllUsers`（`@GetMapping("/getAllUsers")`）和 `userInfo`（`@RequestMapping(value = "/userInfo", method = GET)`）都没有权限注解；因此 Shiro 的 `JwtFilter` 只完成“token 是否有效、用户是否存在”的登录校验（`checkUserTokenIsEffect` → `JwtUtil.verify`），没有回答“当前用户是否有权查看全部用户”。
- `getAllUsers` 调用 `sysUserService.listAll()`；实现为 MyBatis-Plus `LambdaQueryWrapper<SysUser>().eq(SysUser::getDeleteFlag, false)` 后 `this.list(...)`，即全表查询，没有按当前用户、租户或角色做数据范围过滤，再映射为 `SysUserDepVo`（id、username、realname）返回。
- `userInfo` 从 `MySecurityUtils.getCurrentUser()` 取当前用户（主要是拿 tenantId），但用请求参数 `id` 直接 `sysUserService.getById(id)` 查询目标用户，随后 `setPhone(sysUser.getPhone())` 并查询部门信息返回；没有校验 `id` 是否属于当前用户或当前用户是否有管理权限，属于对象级授权缺失（IDOR）。
- 根因是把“登录认证”当成了“功能授权”：前端菜单/按钮隐藏不能阻止直接请求后端接口，缺少注解的接口对任意已登录账号开放。

## 触发条件

- 目标为开放签电子签章系统，存在 `/sys/user/getAllUsers` 与 `/sys/user/userInfo` 接口。
- 攻击者拥有任意一个有效登录账号（普通用户即可），并能获取 `X-Access-Token`（登录响应或前端存储）。
- 目标未在网关/拦截器中额外限制这两个路径，且未升级到补上权限注解的版本。
- `getAllUsers` 返回全量数据、`userInfo` 按 id 返回目标用户数据（截图中部分字段由作者打码）。

## 利用步骤

1. 用任意普通账号登录，取得 `X-Access-Token`（也可尝试 `token` 请求参数，`executeLogin` 在请求头为空时会从参数取）。
2. 调用 `GET /sys/user/getAllUsers`，从响应中收集 `userId`、`username`、`realName` 列表；该接口一次返回全量用户（文章响应体约 3.4MB）。
3. 挑选目标用户 id，调用 `GET /sys/user/userInfo?id=<userId>` 获取该用户的详情（手机号、部门、角色等字段）。
4. 结合其他无权限注解的 `SysUserController` 接口继续扩大影响；也可用枚举到的手机号/账号做撞库、钓鱼或密码重置尝试。
5. 用不同角色账号（普通/管理员）对比同一接口的返回，确认垂直越权面。

## PoC

```http
GET /sys/user/getAllUsers HTTP/1.1
Host: target.example
X-Access-Token: <任意登录用户的 token>
Accept: application/json, text/plain, */*
```

```http
GET /sys/user/userInfo?id=<目标用户 id> HTTP/1.1
Host: target.example
X-Access-Token: <任意登录用户的 token>
Accept: application/json, text/plain, */*
```

```text
# 文章实测：两个请求均返回 HTTP/1.1 200，success=true
# getAllUsers 返回全量用户数组（userId/username/realName），响应体约 3.4MB
# userInfo 按 id 返回该用户 phone、部门、角色等字段
```

## 变体与关联

- 变体：`SysUserController` 中其他未标注 `@RequiresPermissions` 的方法同样对任意登录用户开放，审计时逐个核对注解覆盖情况。
- 变体：`userInfo` 的 `id` 可替换为任意 UUID；若租户校验只在部分分支生效，可跨租户读取。
- 关联：[[web-generic-auth-deepaudit-user-list-missing-role-check-pii-leak]]（用户列表缺角色校验导致普通用户拉全量 PII，同类场景不同产品/框架）；[[web-generic-auth-missing-function-level-role-check]]（拦截器只验登录不验角色的功能级授权缺失）。
- 边界：需要任意有效登录账号；文章截图中账号/手机号字段被作者打码，实际返回的敏感字段以目标版本为准；未验证其他接口的权限矩阵。

## 检测与防御

- 检测：审计所有 Controller 方法，确认是否有 `@RequiresPermissions`/`@PreAuthorize` 或等价的方法级授权；普通用户 token 请求 `/sys/user/getAllUsers`、`/sys/user/userInfo` 返回 200 且含他人数据时告警；统计用户列表接口的超大响应。
- 修复：给 `getAllUsers`/`userInfo` 补上管理员权限注解（如 `@RequiresPermissions("system:user:list")`），或在方法内校验当前用户角色与目标 id 的归属；详情接口仅允许本人或管理员访问。
- 加固：统一在 API 层做 RBAC + 对象级授权，默认拒绝；对手机号等 PII 做脱敏返回；记录敏感查询审计日志；用多角色账号做权限矩阵回归测试。
