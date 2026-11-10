---
id: web-java-framework-jeecgboot-register-addsysuserrole-admin-escalation
title: JeecgBoot 注册接口+FUZZ 出的 addSysUserRole 接口自助提权管理员
type: scenario
domain: web
path: web/java/framework
technique: jeecgboot-register-addsysuserrole-admin-escalation
tags:
- web
- java
- jeecg
- authz
- privilege-escalation
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-25
  verified_at: '2026-11-08T14:17:04+08:00'
  notes: 已对照原文核对；register注册成功/role/list管理员roleId/addSysUserRole提权PoC证据链与原文一致；addSysUserRole成功响应为远程图未在本地，响应回显未复核；原文未标注JeecgBoot受影响版本
url: /docs/web/java/framework/web-java-framework-jeecgboot-register-addsysuserrole-admin-escalation/
draft: false
kb_aliases:
- jeecg 提权
- addSysUserRole
- 注册自助提权
- jeecg 角色分配接管
---

## 一句话结论

魔改路径的 JeecgBoot 若保留 `/sys/user/addSysUserRole`（或同名变体）接口且仅靠隐藏路径防护，攻击者注册普通账号后经 FUZZ 定位该接口与 `role/list` 查询管理员 roleId，将 `userIdList` 指向自己的 userId 即把账号提权为管理员。

## 原理

JeecgBoot 的角色分配操作在服务端拆成"查角色列表/查用户 ID"与"写入用户-角色关联"两类接口；`addSysUserRole` 接口只校验请求方携带的 token 有效性而不校验其是否有用户管理权限（垂直越权缺失）。系统部署时虽魔改了 URL 前缀使原版 PoC 路径失效，但接口命名习惯保留（`/sys/user/`、`api/sys/` 等），通过对已知接口族的字典 FUZZ 仍能定位；`role/list` 可直接读到 `roleCode=useradmin` 的管理员角色 id，`user/list` 类接口可查到 admin 与自己的 userId，三步拼出完整提权请求。

## 触发条件

- JeecgBoot 系统开放注册（`/sys/user/register` 或魔改变体，返回"注册成功"）。
- `addSysUserRole`、`role/list` 等管理接口仅依赖路径隐蔽，未做角色校验。
- 攻击者持有效低权限 token（X-Access-Token）。

## 利用步骤

1. POST 注册接口（username/realname/deptId/password/phone/smscode）创建普通账号并登录取 token。
2. FUZZ 魔改路径下的管理接口（字典含 `sys/user`、`role`、`user` 关键词组合）。
3. GET `.../role/list` 读取角色记录，记下"管理员/useradmin"的 roleId。
4. 经接口查询 admin 的 userId 与自己注册账号的 userId。
5. POST `.../jeecg-boot/sys/user/addSysUserRole`，body 为 `{"roleId":"<管理员roleId>","userIdList":["<自己userId>"]}`，携带 X-Access-Token。
6. 重新登录即获得管理员菜单/权限；进一步用新管理员口令尝试复用登录其他系统。

## PoC

```http
POST /xxxx/jeecg-boot/sys/user/addSysUserRole HTTP/1.1
X-Access-Token: <普通用户JWT>
Tenant-Id: 0
Content-Type: application/json

{"roleId":"<role/list 得到的管理员id>","userIdList":["<自己userId>"]}
```

响应成功后该账号拥有 admin 角色。

## 变体与关联

- 变体：直接改注册/更新用户请求里的 roleId/roleIds 字段（客户端参数篡改型）。
- 关联：JeecgBoot 历史接口族（dict/queryTableData/jimureport）多为同类"路径隐蔽+权限缺失"问题；jeecg 综合利用工具（GUI）可批量探测。
- 弱口令组合：admin:123456、jeecg:123456 及 `/v2/api-docs`、`/actuator/*` 泄露可加速定位接口。

## 检测与防御

- `addSysUserRole` 等管理接口必须在服务端校验操作者角色，而非依赖 URL 隐蔽；对魔改路径同样生效。
- 关闭公网注册或注册账号默认最小权限；`role/list`、用户列表接口按权限过滤。
- 审计低权限 token 调用管理接口的日志并告警。
