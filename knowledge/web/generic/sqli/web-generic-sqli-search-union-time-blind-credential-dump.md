---
id: web-generic-sqli-search-union-time-blind-credential-dump
title: search POST 参数 SQL 注入（UNION + 时间盲注）拖库获取明文口令并破解 MD5 admin 口令
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-union-time-based-blind-credential-dump
aliases:
- search 参数 SQL 注入
- sqlmap union/time-based 拖库
- 明文口令拖库
- MD5 口令 hash 字典破解
tags:
- sqli
- union
- time-based-blind
- credential-dump
- plaintext-password
- md5
- sqlmap
- pentest
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-13
  verified_at: '2026-11-08T07:35:04+08:00'
  notes: '已对照原文与图核对：图05 search=1'' or 1=1 # 返回全部 Staff Details；图07 sqlmap 报 time-based blind(SLEEP(5)) 与 Generic UNION query 6 columns、DBMS MySQL/MariaDB；图09 dump users.UserDetails 17 条明文口令；图11/13 另库 Staff.Users 的 admin 无盐 MD5 856f5de590ef37314e7c3bdf6f8a66dc 破解为 transorbital1——卡片『UNION+时间盲注、明文口令、MD5 admin 破解』与图/文一致。未验证点：原文未给出后端 SQL 语句，卡片『WHERE lastname LIKE %search%』为按 results.php 行为推断；目标为靶场 192.168.1.114，未复跑；frontmatter 无 sources/source_url。'
---

## 一句话结论

站点查询功能（`results.php` 的 `search` POST 参数）把用户输入直接拼接进 SQL，`search=1' or 1=1 #` 即可返回全部记录；用 sqlmap 确认存在 UNION（6 列）与时间盲注（SLEEP）两类注入，dump `users.UserDetails` 表得到 17 组明文用户名/口令，并在另一库 `Staff.Users` 中拿到 admin 的 MD5 口令 hash 经字典破解得明文，用于登录后台并进入后续文件包含/提权链。

## 原理

- 查询形如 `SELECT ... FROM UserDetails WHERE lastname LIKE '%<search>%'`，参数未参数化、未转义；单引号闭合原字符串后追加 `or 1=1`（恒真）并用 `#` 注释掉剩余语句，即返回整表。
- UNION 注入要求列数一致：本题为 6 列，用 `UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,CONCAT(...),NULL-- -` 之类逐列探测回显位；时间盲注用 `AND (SELECT SLEEP(5))` 在无显式回显时按响应时间逐字符推断。
- sqlmap 用 `-r <请求文件>` 复现 POST 注入，自动识别 `time-based blind` 与 `UNION query`，再 `--dump` 拖库。
- 应用把用户口令以**明文**存储 → 拖库即得可直接使用的凭据；另一张表的 admin 口令用无盐 MD5（如 `856f5de...`）→ sqlmap 内置字典可秒破为明文（本题 `transorbital1`）。
- 这些凭据的复用价值：登录后台（获得需认证的文件包含点）、作为 SSH 口令本爆破系统账号（Web 与系统账号同名同口令时命中）。

## 触发条件

- 存在把用户输入拼接进 SQL 的查询参数（POST/GET 均可）；
- 未使用预编译语句/参数化查询，未对引号与注释符做过滤；
- 数据库账号对所查库表有读权限，且能跨库读取（本题 users 库与 Staff 库）；
- 口令以明文或无盐弱哈希存储，便于直接复用/破解。

## 利用步骤

1. 抓查询请求（含 Cookie），把参数改为 `1' or 1=1 #` 验证：若返回全部记录则存在注入。
2. 保存请求为 `r.txt`，`sqlmap -r r.txt` 识别注入类型与列数。
3. `--dbs` / `--tables` / `--dump` 拖取用户表与凭据表，记录明文口令与 hash。
4. 对 MD5 hash 用 sqlmap 字典模式或 hashcat/在线库破解，得到 admin 明文口令。
5. 用凭据登录后台；整理用户名/口令本供后续 SSH 爆破（凭据复用）。

## PoC

```http
POST /results.php HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<会话>

search=1' or 1=1 #
```

```text
# sqlmap 自动化（请求文件 r.txt 含上述 POST）
sqlmap -r r.txt --dbs
sqlmap -r r.txt -D users -T UserDetails --dump
sqlmap -r r.txt -D Staff -T Users --dump        # 含 admin 的 MD5
```

说明：结构复现的通用 payload，注入点/库表名/列数按目标调整；不访问、不执行。

## 变体与关联

- 变体：布尔盲注、报错注入、堆叠注入；`UNION` 列数不同则调整 NULL 个数；过滤引号时用编码/宽字节绕过。
- 变体：口令 hash 为加盐/强哈希时改用离线破解或寻找其它可复用凭据；跨库读取可拿更多应用配置。
- 关联：[[web-php-file-inclusion-manage-file-param-wfuzz-traversal]]（用 admin 口令登录后的 LFI）；[[pentest-initial-access-knockd-conf-port-knocking-ssh]]（凭据用于 SSH 爆破）。

## 检测与防御

- 检测：WAF/日志中出现 `' or 1=1`、`UNION ALL SELECT`、`SLEEP(`、`#`/`--` 注释符；同一参数高频请求、响应行数异常。
- 检测：数据库出现整表读取、敏感表被批量导出；后台出现用拖库凭据的登录。
- 防御：使用预编译语句/ORM 参数化查询，禁止字符串拼接 SQL；最小权限数据库账号，禁止跨库访问。
- 防御：口令加盐强哈希（bcrypt/argon2）存储，禁止明文/MD5；部署 WAF 与登录异常检测。
