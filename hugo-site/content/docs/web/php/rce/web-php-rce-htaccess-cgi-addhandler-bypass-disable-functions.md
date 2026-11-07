---
id: web-php-rce-htaccess-cgi-addhandler-bypass-disable-functions
title: .htaccess AddHandler cgi-script 让上传脚本由 CGI 执行绕过 disable_functions
type: scenario
domain: web
path: web/php/rce
technique: htaccess-cgi-handler-rce
tags:
- apache
- htaccess
- cgi
- rce
- disable-functions-bypass
- file-upload
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T02:19:03+08:00'
  notes: 已对照原文核对：Options +ExecCGI + AddHandler cgi-script .sh、shell.sh 带 Content-Type 头与 id、CGI 外部进程不受 disable_functions/open_basedir 限制均一致；卡片补充的可执行权限/mod_cgi/noexec 边界正确，原文未给受影响版本区间，未设置
url: /docs/web/php/rce/web-php-rce-htaccess-cgi-addhandler-bypass-disable-functions/
draft: false
kb_aliases:
- AddHandler cgi-script
- Options ExecCGI
- CGI 绕过 disable_functions
- .sh 上传执行
- Apache CGI 后门
---

## 一句话结论

目标用 `disable_functions` 禁用了 `system`/`exec` 等 PHP 函数时，只要 Apache 启用了 mod_cgi 且允许 `.htaccess`，上传一个 `.htaccess` 把 `.sh` 映射到 `cgi-script`，再上传带 shebang 的 shell 脚本，Apache 就会直接调用 `/bin/bash` 执行它，完全不走 PHP。

## 原理

- `disable_functions` 限制的是 PHP 语言层面的函数调用，PHP 进程本身仍然可以 fork/exec 外部程序（CGI 模式就是这样工作的）。
- Apache 的 `mod_cgi`/`mod_cgid` 负责把被标记为 `cgi-script` handler 的文件当作外部程序执行：Apache 启动子进程运行该文件，把请求的 method、headers、body 通过环境变量和 stdin 传入，把子进程 stdout 作为 HTTP 响应返回。
- `.htaccess` 中的 `Options +ExecCGI` 打开目录的 CGI 执行能力，`AddHandler cgi-script .sh` 把 `.sh` 后缀映射到该 handler。文件内容里的 `#!/bin/bash` 决定由哪个解释器执行。
- 因为执行者是独立进程，PHP 的 `disable_functions`、`open_basedir` 对该进程都不生效；`open_basedir` 甚至会限制 PHP 读脚本，但不影响 Apache 启动 CGI。
- CGI 协议要求程序先输出合法 HTTP 头（至少 `Content-Type`），否则 Apache 返回 500；因此脚本必须先打印头部再打印命令结果。

## 触发条件

- Apache 已加载 `mod_cgi` 或 `mod_cgid`（很多发行版默认加载）。
- 目标目录的 `AllowOverride` 允许 `Options` 与 `FileInfo`（或 `All`），`.htaccess` 可生效。
- 攻击者可上传 `.htaccess` 和一个脚本文件，且脚本落盘后具备可执行权限（或可借助其他手段 chmod；部分上传实现保留权限位，部分为 0644）。
- 服务器文件系统没有对上传目录挂载 `noexec`。

## 利用步骤

1. 上传 `.htaccess`，开启 `ExecCGI` 并把目标后缀映射到 `cgi-script`。
2. 上传 shell 脚本，内容包含 shebang、CGI 响应头和要执行的命令。
3. 确认脚本权限；若为 0644，尝试通过上传实现、压缩包解压、其他写文件原语补上执行位。
4. 访问脚本 URL，命令由 `/bin/bash` 执行，结果出现在响应体。

## PoC

`.htaccess`：

```apache
Options +ExecCGI
AddHandler cgi-script .sh
```

`shell.sh`：

```bash
#!/bin/bash
echo "Content-Type: text/plain"
echo ""
id
```

访问：

```bash
curl -s 'http://target/upload/shell.sh'
```

响应体应包含 `uid=...`。若返回 500，先检查脚本是否有执行权限、`mod_cgi` 是否加载、以及 `Options` 是否被父目录覆盖。

## 变体与关联

- 后缀变体：`AddHandler cgi-script .cgi`、`.pl`、`.py`，配合对应的 shebang；`SetHandler cgi-script` 可让整个目录/匹配文件都走 CGI。
- 若 `Options` 被限制，可尝试只改 handler；但 `ExecCGI` 通常是必需项。
- 与 `AddType application/x-httpd-php .jpg` 的区别：后者仍由 PHP 解析，受 `disable_functions` 限制；CGI 走外部进程，是绕过 PHP 限制的关键。
- 关联：[[web-php-rce-htaccess-setenv-ld-preload]]（同样利用 Apache 派生子进程，绕过 PHP 层限制）；[[web-generic-file-upload-htaccess-handler-override]]（handler 覆盖的基本形态）；[[web-php-rce-htaccess-ssi-includes-exec]]（SSI 的 `#exec` 也由 Apache 子进程执行）。
- 边界：`AllowOverride None`、未加载 mod_cgi、上传目录 `noexec`、脚本无可执行权限且无法 chmod 时，本手法不成立。

## 检测与防御

- 检测：Web 目录出现 `.htaccess` 且含 `AddHandler cgi-script`/`Options +ExecCGI`；上传目录出现 `.sh`/`.cgi`/`.pl` 文件；Apache 子进程执行上传目录中的脚本；响应中出现 CGI 头后跟命令输出。
- 防御：`AllowOverride None`；不加载不需要的 `mod_cgi`；上传目录 `noexec` 且禁止脚本执行；上传白名单只允许图片并重命名；以最小权限运行 Apache，禁止其读取敏感文件。
