---
id: ctf-web-redis-getkey-name-injection-read-adjacent-secrets
title: Redis 键名注入：用户输入直接作为 GET 的 key，提交 admin_password 等相邻键名读出敏感值
type: scenario
domain: ctf
path: ctf/web
technique: redis-get-key-name-injection
tags:
- ctf
- web
- redis
- nosql
- key-injection
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-28
  verified_at: '2026-11-08T15:06:03+08:00'
  notes: 已对照原文核对：图02-04 证实 HackBar 提交 famous_person=admin_password、admin 口令回显、下拉菜单隐藏键 flag_7392ilj8i32；dedup 候选均非同链
url: /docs/ctf/web/ctf-web-redis-getkey-name-injection-read-adjacent-secrets/
draft: false
kb_aliases:
- Redis key 注入
- 键名可猜测读取
- NoSQL 注入读相邻键
- redis getData 键注入
---

## 一句话结论

后端把用户输入直接当 Redis GET 的键名（`db.get(key)`）时，虽然界面只提供下拉名单，但 POST 参数可提交任意键名——提交同库中命名规律可猜的键（如 `admin_password`、`<username>_password`）即可读出敏感值，配合登录口令进入 admin 身份后，再从 admin 专属 JSON 数据（`JSON.GET admin_options`）里拿到隐藏键名（如 `flag_7392ilj8i32`）完成取数链。

## 原理

- `getData(person)` 把 `famous_person` 表单值原样传给 `db.get(key)`，仅有的过滤是「值里含 flag 且非 admin 则拒绝」——检查的是**提交的键名字符串**，而不是键名对应的真实键，因此 `admin_password` 这类不含 flag 字样的键畅通无阻。
- Redis 是扁平键值空间：应用按 `<username>_password`、`admin_password` 等约定命名键，攻击者一旦能以任意键名 GET，就等价于对整个库做键枚举读取。
- 第二跳：admin 身份下 `db.json().get("admin_options", "$")[0]` 渲染进下拉菜单，该 JSON 数组（如 `["hints", "fake_flag", "flag_7392ilj8i32"]`）暴露了真实 flag 键的名字（带随机后缀，无法直接猜），选中即由 `getData` 读出。

## 触发条件

- 存在把用户输入直接映射为 Redis GET/JSON.GET 键名的接口；
- 库内存在命名规律可预测的敏感键（`*_password`、`flag_*` 等）。

## 利用步骤

1. 从源码/前端确认 `get_quote` 接口把 `famous_person` 直接送进 `db.get`。
2. 用 HackBar 等工具 POST `famous_person=admin_password`，响应回显 `I_HopeYou4re8admin_iLoveTechn070g_9283910`。
3. 用该口令在 `/login` 以 admin 登录（校验逻辑为 `dbUser == "User" and dbPassword == password`，admin 键已预置）。
4. admin 身份首页下拉菜单出现 admin_options 中的隐藏键名 `flag_7392ilj8i32`，选中提交即得 flag。

## PoC

```
POST /get_quote
famous_person=admin_password
# 响应回显 admin_password 键的值
```

## 变体与关联

- 同族：Redis 键名/值拼接导致的数据污染（SET 类）、Memcached key 注入、以及把用户输入拼进 `JSON.GET` 路径表达式的注入；
- 与 SQL 注入的区别在于 NoSQL 无查询语言可注入，攻击面是「键空间可枚举」而非语法逃逸。

## 检测与防御

- 键名白名单化：接口只允许固定映射（如 person -> 预定义 key），拒绝任意字符串作键；
- 敏感键命名去规律化只是缓解，根治是禁止把凭据明文放 Redis 并对读取接口做权限校验；
- 监控同一会话对 `*_password`、`flag*` 等键的异常 GET。
