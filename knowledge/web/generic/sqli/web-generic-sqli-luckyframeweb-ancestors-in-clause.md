---
id: web-generic-sqli-luckyframeweb-ancestors-in-clause
title: LuckyFrameWeb 部门编辑把 ancestors 写入后再拼进 IN (${ancestors})：条件可达的二级 SQL 注入
type: scenario
domain: web
path: web/generic/sqli
technique: dept-ancestors-second-order-in-clause-injection
aliases:
- LuckyFrameWeb SQL注入
- ancestors 注入
- updateDeptStatus 注入
- IN (${ancestors})
- 部门状态更新注入
tags:
- sqli
- java
- mybatis
- second-order
- in-clause
- dept
- luckyframeweb
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: V3.1_Beta（原文测试版本）
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T08:50:47+08:00'
  notes: 已对照原文及27张图核对：图14 Dept.ancestors 为 String 且由请求绑定；图13 updateDept 仅在 parentId 查得到部门时用父部门值覆盖 ancestors，parentId 不存在时保留请求值，status=0 时进入 updateParentDeptStatus；图10 该方法按 deptId 重查后调 updateDeptStatus；图08 Mapper 为 where dept_id in (${ancestors})。原文未展示 updateDept Mapper 是否更新 ancestors 列、未展示成功注入回显，卡内已注明该条件与 medium confidence；入口 /system/dept/edit 的类级前缀原文未截图，属合理推断。PoC 未在本机执行。
---

## 一句话结论

LuckyFrameWeb V3.1_Beta 的部门编辑流程把请求中的 `Dept.ancestors` 先写入 `sys_dept`，随后 `updateDeptStatus` 用 `where dept_id in (${ancestors})` 文本拼接该字段；当 `parentId` 指向不存在的部门时，Service 不会用父部门数据覆盖 `ancestors`，攻击者提交的字符串会原样进入 SQL，形成二阶 `IN` 子句注入。

## 原理

- 实体 `Dept` 继承 `BaseEntity`，字段 `private String ancestors;`（祖级列表，逗号分隔的部门 ID 字符串）由请求体绑定，完全可控。
- 入口 `POST /system/dept/edit`（`@RequiresPermissions("system:dept:edit")`）调用 `deptService.updateDept(dept)`。
- Service 逻辑：
  - `Dept info = deptMapper.selectDeptById(dept.getParentId());`
  - 若 `info != null`：`String ancestors = info.getAncestors() + "," + info.getDeptId(); dept.setAncestors(ancestors);` —— 此时请求里的 `ancestors` 被数据库值覆盖，攻击者不可控；
  - 若 `info == null`（parentId 不存在）：`ancestors` 保持请求原值；
  - `deptMapper.updateDept(dept)` 把 `ancestors` 持久化到 `sys_dept`；
  - 若 `UserConstants.DEPT_NORMAL.equals(dept.getStatus())`（状态为 `"0"`），调用 `updateParentDeptStatus(dept)`。
- `updateParentDeptStatus` 先用 `dept.getDeptId()` 重新查库（取到刚写入的恶意 `ancestors`），再调用 `deptMapper.updateDeptStatus(dept)`；Mapper XML 中：
  ```xml
  <update id="updateDeptStatus" parameterType="Dept">
    update sys_dept ... where dept_id in (${ancestors})
  </update>
  ```
  `${ancestors}` 为文本替换，恶意字符串进入 `IN (...)` 语法层。
- 因此利用需要同时满足：有 `system:dept:edit` 权限、`parentId` 指向不存在的部门以跳过覆盖、`status = "0"` 触发状态更新、`updateDept` 的 SQL 确实更新 `ancestors` 列（原文未展示该 Mapper，属推断）。
- 根因：`ancestors` 本应是服务端维护的部门树路径，却被客户端绑定并可写入；下游又用 `${}` 把它当 SQL 片段拼接，两个缺陷叠加成二阶注入。

## 触发条件

- 目标为 LuckyFrameWeb V3.1_Beta（原文测试版本）。
- 攻击者拥有 `system:dept:edit` 权限（部门管理角色）。
- `parentId` 设为不存在的部门 ID，使 `info == null`，避免 `ancestors` 被父部门值覆盖。
- `status` 设为 `"0"`（DEPT_NORMAL），触发 `updateParentDeptStatus`。
- `updateDept` Mapper 更新 `ancestors` 列（需按目标源码确认；若未更新则注入不成立）。

## 利用步骤

1. 登录具备部门编辑权限的账号，抓取 `/system/dept/edit` 请求。
2. 提交一个 `parentId` 不存在的部门记录，`ancestors` 填入注入载荷，`status` 填 `"0"`。
3. 若接口返回成功，服务端已把载荷写入 `sys_dept.ancestors`，并进入 `updateParentDeptStatus` → `updateDeptStatus`。
4. 用报错/时间盲注确认：如 `ancestors=1) AND SLEEP(3)-- -`，观察响应时间；或构造 `1) AND extractvalue(1,concat(0x7e,database()))-- -`。
5. 确认后按 MySQL 语法读取数据；注意 `IN (` 前缀与 `)` 后缀，需保持语句闭合正确。
6. 记录请求与响应证据；验证后删除测试部门，避免影响业务。

## PoC

```http
POST /system/dept/edit HTTP/1.1
Host: target
Cookie: JSESSIONID=<有 system:dept:edit 权限的会话>
Content-Type: application/x-www-form-urlencoded

deptId=9999&parentId=999999&deptName=test&status=0&ancestors=1) AND (SELECT SLEEP(3))-- -
```

对应 SQL 片段（示意）：

```sql
update sys_dept set ... where dept_id in (1) AND (SELECT SLEEP(3))-- -)
```

原文仅跟踪到 `Dept.ancestors` 可控并断言存在注入，未展示成功注入的响应/时间差截图；上述 parentId 条件是对原文 Service 覆盖逻辑的补充说明。

## 变体与关联

- 变体：若 `updateDept` 不更新 `ancestors`，可改为先通过新增部门或其他写接口把恶意 `ancestors` 落库，再触发 `updateDeptStatus`。
- 变体：`ancestors` 也可用于 `FIND_IN_SET(#{deptId}, ancestors)` 的值参数（预编译），该处安全；危险点只在 `${ancestors}` 的 `IN` 拼接。
- 关联：[[web-generic-sqli-mybatis-dollar-brace-injection]]（MyBatis `${}` 在 IN 集合位置的通用原理）。
- 关联：[[web-generic-sqli-java-identifier-table-order-by-injection]]（Java 标识符/拼接触发点审计）。

## 检测与防御

- 防御：`ancestors` 不允许由客户端绑定，服务端根据 parentId 查询部门树后自行计算；DTO 中移除该字段。
- 防御：`IN` 集合使用 `<foreach collection="ancestors" item="id" open="(" separator="," close=")">#{id}</foreach>`，禁止 `${}`。
- 防御：部门编辑接口做参数校验（parentId 必须存在、status 枚举），并限制可更新字段。
- 检测：审计 `where ... in (${`、`${ancestors}`、`${ids}` 等模式；对部门编辑请求中 `ancestors` 出现括号、引号、注释符、`SLEEP` 等特征告警。
- 检测：`sys_dept.ancestors` 出现非数字/逗号内容；部门状态更新 SQL 报错或响应时间异常。
