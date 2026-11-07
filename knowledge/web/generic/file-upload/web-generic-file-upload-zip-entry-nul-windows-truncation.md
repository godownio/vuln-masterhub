---
id: web-generic-file-upload-zip-entry-nul-windows-truncation
title: ZIP 条目名 NUL 截断：白名单看到 .pdf，Windows 解压落盘为 evil.php
type: scenario
domain: web
path: web/generic/file-upload
technique: zip-entry-filename-nul-truncation
aliases:
- zip 内文件名空字节截断
- evil.php%00.pdf
- 解压后文件名截断
- ZIP 条目名 NUL
- Windows 文件名空字节截断
tags:
- web
- file-upload
- zip
- null-byte
- truncation
- windows
- php
- webshell
- whitelist-bypass
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V68
  verified_at: '2026-11-05T12:07:24+08:00'
  notes: 已对照原文与图10-25核对：后缀白名单枚举（php3/php5/phtml/phar/pht/phps/大小写等）全 400 Invalid Extension（图11-13），.pdf 含 PHP 内容被 MIME 检测拦截（图16 无 Invalid MIME 细节、图13 有）；合法 PDF 与含 PDF 的 zip 上传成功（图14/15/17）；zip 内 test.php 被解压后复查后缀拦截（图17）；evil.php..pdf 在 Caido 中把 php 后第一个点改为 0x00、本地文件头与中央目录各一处（图18-22），解压落盘为 evil.php 并 phpinfo 成功（图23）；system 版本 400（图24），shell_exec 版本成功（图25）。卡内原理、两处 NUL 修改、白名单/MIME 检测顺序与内容黑名单绕过与原文一致。未验证点：仅 Windows+XAMPP 环境实测，PoC 未在本机复跑；原文无产品版本区间，未设 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

当服务端允许上传 ZIP、解压后只按“条目名最后一个点后的后缀”做白名单检查，且落在 Windows 文件系统时，把条目名写成 `evil.php\x00.pdf` 可让检查逻辑看到 `.pdf`，而 Win32 在创建文件时把 NUL 当字符串结束符，实际落盘为可执行的 `evil.php`。

## 原理

- **两套解析对同一个字符串的理解不同**：应用层用 `pathinfo($name, PATHINFO_EXTENSION)` 之类的字符串函数取后缀，函数看到的是完整的 `evil.php\x00.pdf`，最后一个 `.` 之后是 `pdf`，于是白名单通过。
- **写盘层在 Windows 上截断**：Windows 的路径/文件名 API 接收的是 C 风格字符串，遇到 `\x00` 即认为字符串结束。解压/写文件时传给 `CreateFileW` 的 `evil.php\x00.pdf` 被截成 `evil.php`，文件最终以 `.php` 后缀落在 Web 可访问目录。
- **检测顺序错位**：服务端对非 ZIP 文件同时做后缀白名单与 `finfo` 魔术字节/MIME 检测；对 ZIP 只检查上传包本身，解压后仅复查条目后缀，不再按内容做 MIME 检测，因此压缩包里的 PHP 代码不会在上传阶段被识破。
- **为什么必须放在 ZIP 里**：直接上传 `evil.php` 会先后被后缀白名单和 MIME 检测拦截；ZIP 是白名单允许的容器，且能保留条目名中的原始 NUL 字节。
- **NUL 需要改两处**：ZIP 的本地文件头（Local File Header）和中央目录（Central Directory）各存一份文件名，只改一处会导致解压器读到的名字与中央目录不一致，必须两处同时替换。
- 解压后的内容检查若存在，往往只是弱黑名单（例如只拦 `system(`），换用 `shell_exec` 等同义执行函数即可绕过。

## 触发条件

- 上传功能允许 `.zip`，且上传目录位于 Web 根下并允许 PHP 解析。
- 服务端会解压 ZIP，并按条目名的“最后一段后缀”做白名单校验。
- 落盘/解压发生在 Windows 主机（Windows 文件名 NUL 截断行为）。
- 解压后不再对文件内容做严格的魔术字节/MIME 检查，或只有可绕过的关键字黑名单。
- 上传后能通过返回的链接或可预测路径访问到解压出的文件。

## 利用步骤

1. 构造文件名 `evil.php..pdf`（两个点，第一个点稍后替换为 NUL），内容为最小 PHP 探针。
2. 压缩：`zip evil.zip evil.php..pdf`。
3. 用十六进制编辑器或代理的 Hex/不可见字符功能，把文件名中 `php` 后的第一个 `.` 替换为字节 `0x00`，得到 `evil.php\x00.pdf`；本地文件头与中央目录两处都要替换。
4. 上传 `evil.zip`，记录响应中给出的访问路径（通常形如 `/static/uploads/<hash>/`）。
5. 访问 `/static/uploads/<hash>/evil.php` 验证代码执行（如 `phpinfo()`）。
6. 换成命令马时，若 `system(` 被内容黑名单拦截，改用 `shell_exec`、`passthru` 等等价函数。

## PoC

ZIP 条目名（十六进制视角，`00` 为真实 NUL 字节）：

```text
evil.php\x00.pdf
```

最小 PHP 内容：

```php
<?php echo shell_exec($_REQUEST['cmd']); ?>
```

访问：

```bash
curl 'http://target/static/uploads/<hash>/evil.php?cmd=whoami'
```

说明：原文在 Windows Server 2019 + XAMPP + PHP 8.0.30 环境复现，`phpinfo()` 与 `whoami` 均执行成功；PoC 未在本会话执行。若服务端使用会主动拒绝含 NUL 路径的 PHP 文件函数（而非 ZIP 解压 API），该手法可能失效，需按实际写盘实现判断。

## 变体与关联

- **双扩展名占位**：先用 `..` 占位再替换为 NUL，避免本地工具在打包/复制阶段提前截断文件名。
- **其他截断字符**：Windows 上还可尝试 `:`（ADS/驱动器分隔）、结尾点/空格等归一化差异；不同解压实现行为不同。
- **内容黑名单绕过**：`system` 被拦时用 `shell_exec`、`passthru`、`popen`、反引号等；若 `disable_functions` 生效则需另找未禁用函数或绕过方式。
- **ZIP Slip 组合**：若解压未规范化条目路径，还可把文件写到上传目录之外；本条利用的是“名字检查值 ≠ 落盘值”，与路径穿越互补。
- 关联：[[web-generic-file-upload-null-byte-path-truncation]]（PHP 保存路径参数中的 NUL 截断，环境与触发点不同）；[[web-generic-file-upload-zip-slip-webshell-write]]；[[web-generic-file-upload-weak-suffix-bypass]]；[[web-generic-file-upload-thinkphp-admin-upload-unzip-webshell]]（ZIP 解压不复查条目后缀）。

## 检测与防御

- **检测**：上传请求中出现含 `0x00` 的 ZIP 条目名；同一条目在本地文件头与中央目录中名字不一致；解压后 Web 目录出现后缀与上传包声明不符的新脚本；访问 `/uploads/*.php` 或上传目录下新增可执行文件。
- **防御**：解压前遍历条目名，拒绝含 NUL、控制字符、`..`、绝对路径的条目；解压后按“实际落盘文件名 + 真实内容”重新校验，而不是只信条目名；上传目录移出 Web 根并禁止脚本解析；白名单以规范化后的最终路径为准；对归档内文件做内容扫描（解压后、落盘前）。
- **平台侧**：Windows 上尽量使用会显式拒绝 NUL 的文件 API，并在解压库层面做名称清洗；Web 服务器对上传目录关闭 PHP handler。
