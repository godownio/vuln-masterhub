---
id: web-generic-auth-roleid-roleids-parameter-tampering-admin
title: roleId/roleIds 参数篡改：从学生账号创建管理员与超级管理员
type: scenario
domain: web
path: web/generic/auth
technique: role-parameter-tampering-admin-creation
aliases:
- roleId 参数篡改
- roleIds 篡权
- 新增用户角色越权
- 前端隐藏超管创建绕过
- 角色参数信任客户端
- 垂直越权建管理员
tags:
- auth
- authorization
- privilege-escalation
- parameter-tampering
- mass-assignment
- role
- admin
- vertical-privilege
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V61
  verified_at: '2026-11-05T12:36:28+08:00'
  notes: 已对照原文与图08-16/20-24核对：登录包 roleId=3(图08)，改 1 提示用户名不存在(图09)，改 2 后新增管理员并登录后台(图10-16)；新增用户时 roleIds 提交为 28 并成功得到超级管理员(图21/22/23)，超管菜单可列 181058 条学生记录含 idCard(图24)。核对时修正卡内角色 ID：原文正文写 roleIds 改 1，但图22 实际提交为 [28]，已将原理/步骤/PoC 改为“按目标角色表确认，案例截图 28”，避免硬编码错误。未验证点：roleId=2 时是登录即建号还是已有管理员账号，原文/图未完全说明；PoC 未本机复跑；frontmatter 无 sources/source_url（全库惯例）。
---

## 一句话结论

当登录/新增用户接口直接信任客户端传入的 `roleId`/`roleIds` 时，攻击者可以把学生角色改成管理员，再在新增用户请求里把 `roleIds` 改成超级管理员，绕过前端隐藏/限制，直接创建管理员与超管账号。

## 原理

- 系统用 `roleId`/`roleIds` 表示用户角色（学生、教职工、管理员、超级管理员等）。正常流程中角色应由服务端根据业务规则决定，而不是由客户端提交。
- 若登录、注册或新增用户接口直接接收并落库 `roleId`/`roleIds`，且没有服务端白名单/权限校验，攻击者就能篡改角色值。案例中把学生登录请求的 `roleId` 从 3 改为 2（管理员）即可创建/获得管理员账户；随后在前端“新增用户”请求中把 `roleIds` 改为超级管理员对应值（原文正文写作 1，图22 实际提交 `[28]`，具体 ID 依目标角色表而定），绕过界面隐藏超管选项的限制。
- 这条链通常分两段：第一段用低权限账号或注册接口拿到管理员；第二段用管理员权限进入用户管理，直接构造超管创建请求。前端把“超级管理员”选项隐藏/置灰并不构成安全边界，只要接口接受该值。
- 根因是**角色字段由客户端控制 + 服务端缺少字段白名单与授权校验**；与 Spring `@RequestBody` 大量赋值同属“客户端可控属性直接映射到服务端对象”的问题，但这里更聚焦角色字段。
- 拿到超管后可访问全量学生 PII、系统配置、报表 SQL 等高风险功能，并进一步 RCE。

## 触发条件

- 登录/注册/新增用户接口接受 `roleId`、`roleIds`、`role`、`userType`、`isAdmin` 等角色字段。
- 服务端未把这些字段加入白名单/只读，也未在保存前强制覆盖为允许值。
- 攻击者能访问该接口（有低权限账号、可注册，或接口未鉴权）。
- 角色 ID 可枚举/可推测（案例 2=管理员、3=学生；超级管理员 ID 需按目标角色表确认，图22 为 28）。

## 利用步骤

1. 登录低权限账号，抓取登录/注册/新增用户请求，记录角色字段名与当前值（如 `roleId=3`）。
2. 修改为管理员值（如 2），发送；观察是否创建/切换为管理员账号。
3. 用新管理员账号登录管理后台，寻找用户管理/新增用户功能；抓取新增用户请求。
4. 在请求中把 `roleIds`/`roleId` 改为超级管理员对应的角色 ID（原文正文写 1，图22 截图为 28；需按目标角色表枚举确认），发送；前端隐藏/置灰不影响直接构造请求。
5. 用新超管账号登录，确认菜单/权限（全量用户、系统配置、报表 SQL 等）。
6. 继续收集 PII、配置或利用后台的高危功能（如 SQL 编辑器）。

## PoC

```json
// 1) 登录/注册请求：学生 roleId=3，改为 2
{
  "userId": "<encrypted-or-plain>",
  "password": "<password>",
  "roleId": 2,
  "schoolCode": "<school>",
  "loginType": 3
}
```

```json
// 2) 新增用户请求：前端只允许管理员，直接改为超管角色 ID（原文正文写 1，图22 为 28）
{
  "username": "admin11",
  "account": "admin11",
  "password": "<password>",
  "roleIds": [28]  // 按目标角色表替换
}
```

```text
# 预期：第一步创建/获得管理员；第二步创建超级管理员；
# 登录超管后可见全量学生信息、系统配置、报表 SQL 等高权限菜单。
```

## 变体与关联

- 变体：字段名可能是 `role`、`roleId`、`roleIds`、`userType`、`isAdmin`、`admin`、`level`；值为数字、字符串或数组。
- 变体：注册接口直接把 `role` 落库（mass assignment）；更新资料接口可改自己的角色；邀请/子账号接口可指定角色。
- 变体：前端隐藏超管选项、按钮置灰、菜单不下发都不算服务端校验；直接构造请求即可。
- 关联：[[web-java-framework-spring-requestbody-mass-assignment-privilege-escalation]]（Spring @RequestBody 大量赋值）、[[web-generic-auth-unauth-user-create-admin-takeover]]（未授权创建管理员）、[[web-generic-auth-jwt-signature-only-role-bypass]]（token 角色校验缺失）。
- 边界：服务端对角色字段做白名单/强制覆盖、创建超管需要二次审批/独立接口、接口有严格授权与审计时，本场景不成立。

## 检测与防御

- 检测：登录/注册/新增用户请求中出现 `roleId`/`roleIds`/`isAdmin` 等字段；同一账号从学生角色创建出管理员/超管；低权限账号调用用户创建接口；前端隐藏字段被构造。
- 修复：服务端不接收客户端角色字段，使用只含允许字段的 DTO；保存前按业务规则强制设置角色；创建管理员/超管走独立接口并做二次授权与审批。
- 加固：角色变更审计与告警；最小权限；对用户创建接口做服务端权限校验；定期检查是否存在越权创建的高权限账号。
