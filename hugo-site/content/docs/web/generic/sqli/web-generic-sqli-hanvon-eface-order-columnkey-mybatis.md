---
id: web-generic-sqli-hanvon-eface-order-columnkey-mybatis
title: 汉王e脸通 MyBatis `${columnKey} ${order}` 排序注入：queryManyPeopleGroupList 与 queryAntiStealthyList 两个后台接口
type: scenario
domain: web
path: web/generic/sqli
technique: mybatis-order-columnkey-text-substitution-sqli
tags:
- web
- java
- mybatis
- sqli
- order-by
- springmvc
- hanvon
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V225
  verified_at: '2026-11-07T07:00:09+08:00'
  notes: 已对照原文与图14-23核对：AccessManyPeopleGroupDao.xml queryManyPeopleGroupList与AccessAntisubmarineDao.xml queryAntiStealthyList的ORDER BY分支均为${columnKey} ${order}；Controller manyPeopleGroupListFordatatables/queryAntisubmarineList以@RequestParam接收order/columnKey并setOrder/setColumnKey，调用链经Asm/Bsm到DAO；两个PoC URL与原文一致；原文未执行具体注入载荷
url: /docs/web/generic/sqli/web-generic-sqli-hanvon-eface-order-columnkey-mybatis/
draft: false
kb_aliases:
- 汉王e脸通 SQL 注入
- MyBatis order 注入
- columnKey 注入
- queryManyPeopleGroupList 注入
- queryAntiStealthyList 注入
---

## 一句话结论

汉王e脸通的 MyBatis Mapper 在 `ORDER BY` 后使用 `${columnKey} ${order}` 文本拼接，而两个 Controller 通过 `@RequestParam` 直接接收 `order` 与 `columnKey` 并 set 进查询参数；攻击者以白名单绕过前缀访问 `queryManyPeopleGroupList.do` 或 `queryAntiStealthyList.do`，在排序参数中注入任意 SQL，形成未授权 ORDER BY 注入。

## 原理

- MyBatis 的 `${}` 是文本替换，不是预编译参数绑定；拼进 SQL 的字符串会原样进入数据库解析。
- 第一处：`AccessManyPeopleGroupDao.xml` 的 `queryManyPeopleGroupList` 在 `order by` 后写死 `ID DESC`，但当 `order` 非空时改为 `${columnKey} ${order}`。
- 调用链：`AuthMultiplePeopleOpenController.manyPeopleGroupListFordatatables(@RequestParam String order, @RequestParam String columnKey)` → `record.setOrder(order); record.setColumnKey(columnKey);` → `AuthMultiplePeopleOpenAsm.queryManyPeopleGroupList(record)` → `AuthMultiplePeopleOpenBsm` → DAO XML。
- 第二处：`AccessAntisubmarineDao.xml` 的 `queryAntiStealthyList` 同样在 `order by` 后拼接 `${columnKey} ${order}`；`AntisubmarineController.queryAntisubmarineList(@RequestParam String order, @RequestParam String columnKey)` → `record.setOrder/setColumnKey` → `antisubmarineAsm.queryAntiStealthyList(record)` → DAO。
- 两处都由 `@RequestParam(required=false)` 直接接收字符串，未做列名/排序方向白名单；由于 `columnKey` 在 SQL 中位于 `ORDER BY` 后、`order` 紧跟其后，注入点可用于报错、时间盲注或联合查询（取决于数据库与返回处理）。
- 鉴权面：对应 PoC 使用 `/manage/mobiMeetingApp/..;/..;/...` 白名单路径绕过前缀，未登录即可到达 Controller。

## 触发条件

- 目标为汉王e脸通综合管理平台（文章基于反编译源码审计，未标注具体版本）。
- 目标启用 Spring MVC + MyBatis，且对应 Mapper 为上述 `${columnKey} ${order}` 写法。
- 攻击者可访问 `queryManyPeopleGroupList.do` / `queryAntiStealthyList.do`，并通过白名单 `..;/` 或伪造 token 绕过鉴权。
- 数据库账号具备对应查询权限；注入效果受数据库类型、错误回显与网络延迟影响。

## 利用步骤

1. 选择注入点：`/manage/mobiMeetingApp/..;/..;/authMultiplePeople/queryManyPeopleGroupList.do` 或 `/manage/mobiMeetingApp/..;/..;/antisubmarine/queryAntiStealthyList.do`。
2. 先发送正常排序参数确认接口可达，例如 `order=desc&columnKey=ID`。
3. 在 `order` 或 `columnKey` 中构造注入载荷：报错型、布尔型或时间盲注；`columnKey` 可尝试子查询/函数表达式，`order` 可尝试 `desc, (select ...)` 等。
4. 根据响应差异或延迟判断数据库类型与注入结果，进一步读取数据。
5. 原文仅给出参数位置的 PoC 模板，未给出具体注入载荷与数据回显截图；实际利用需按目标数据库调整。

## PoC

第一处：

```http
GET /manage/mobiMeetingApp/..;/..;/authMultiplePeople/queryManyPeopleGroupList.do?page=1&pageSize=10&name=testGroup&order=注入点1&columnKey=注入点2 HTTP/1.1
Host: <target>
Content-Type: application/json
```

第二处：

```http
GET /manage/mobiMeetingApp/..;/..;/antisubmarine/queryAntiStealthyList.do?page=1&pageSize=10&key=testKey&order=注入点1&columnKey=注入点2 HTTP/1.1
Host: <target>
Content-Type: application/json
```

原文截图确认两处 Mapper XML 的 `${columnKey} ${order}` 与 Controller 的 `@RequestParam` + `setOrder/setColumnKey` 代码路径；未执行具体注入载荷。

## 变体与关联

- 同系统批量：文章用 `.setOrder(order);` 特征在全项目搜索到 45 个文件 86 处匹配，说明还有大量同模式排序接口可测试。
- 参数位置变体：`order` 可控制排序方向拼接，`columnKey` 可控制列名/表达式；不同数据库可分别使用报错、布尔、时间盲注。
- 关联：先通过白名单 `..;/` 绕过或伪造 globalToken/recoToken 获得访问权限，再打本注入。
- 同类：BootDo `${sort} ${order}`、PageVo 分页实体污染、大华 MyBatis ORDER BY 注入。

## 检测与防御

- 修复：对 `order`/`columnKey` 使用服务端枚举白名单映射到固定列名与 `ASC/DESC`，禁止 `${}` 直接拼接；MyBatis 可用 `choose` 固定列名，或改为 ORDER BY 预定义字段。
- 检测：请求参数 `order`/`columnKey` 出现逗号、括号、`select`、`sleep`、`extractvalue`、`updatexml`、`case when` 等关键字；同一接口响应时间异常；WAF 对 ORDER BY 注入的告警。
- 加固：数据库最小权限；关闭详细 SQL 错误回显；对后台接口统一鉴权，修复白名单 `..;/` 绕过。
