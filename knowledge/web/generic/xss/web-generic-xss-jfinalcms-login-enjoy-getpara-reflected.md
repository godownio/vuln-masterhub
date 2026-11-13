---
id: web-generic-xss-jfinalcms-login-enjoy-getpara-reflected
title: JFinalCMS 后台登录页 getPara 参数经 Enjoy 模板未转义输出导致反射型 XSS
type: scenario
domain: web
path: web/generic/xss
technique: jfinalcms-login-enjoy-getpara-reflected-xss
aliases:
- JFinalCMS 登录反射 XSS
- LoginController getPara XSS
- Enjoy
- JreCms 反射型 XSS
tags:
- web
- java
- jfinalcms
- jrecms
- xss
- reflected
- enjoy
- code-audit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V607
  verified_at: '2026-11-12T18:44:58+08:00'
  notes: 已对照原文 0x01 与图01-03 核对：LoginController.index getPara(username/password)→setAttr→render login/index，模板 <input ... value="#(username)"> 未转义；图03 访问 /admin/login/index?username="><script>alert(1)</script>&password=1 弹窗，PoC 与原文一致。affected_versions 原文未声明。未在本机复跑。
---

## 一句话结论

JFinalCMS 的 `LoginController.index` 用 `getPara("username")`/`getPara("password")` 取请求参数并 `setAttr` 到视图，登录模板又以 `value="#(username)"` 直接输出；Enjoy 模板未做 HTML 属性上下文转义，攻击者构造 `username="><script>alert(1)</script>` 的登录链接即可让受害者浏览器执行脚本。

## 原理

- **污染路径**：`@RouteMapping(url = "/admin/login")` 的 `index()` 中，`String username = getPara("username"); String password = getPara("password"); setAttr("username", username); setAttr("password", password); render(getView("login/index"));`——参数原样进入模板模型。
- **输出点**：`login/index.html` 中 `<input type="text" id="username" name="username" value="#(username)">` 与 password 同理。`#()` 把值直接写入 HTML 属性，没有做上下文转义；注入 `"><script>...` 先闭合 value 引号，再插入脚本标签。
- **为什么成立**：模板引擎的自动转义并非默认或并非覆盖所有输出语法；在 HTML 属性值上下文中，未转义的 `"`/`<`/`>` 可打破属性边界。即使 password 字段类型为 password，也出现在 value 属性中，同样可利用。
- **验证要点**：访问 `/admin/login/index?username="><script>alert(1)</script>`，观察是否弹窗；查看响应 HTML 中 payload 是否原样出现在 value 属性内。

## 触发条件

- 目标为 JFinalCMS/JreCms，`/admin/login` 路由可访问。
- 登录模板使用 `#(username)` 等未转义输出，未有全局 HTML 转义配置。
- 受害者访问攻击者构造的带 payload 的登录 URL（钓鱼链接、短链、邮件等）。
- 浏览器未拦截（无 CSP 或 CSP 允许 inline script）。

## 利用步骤

1. 访问后台登录页并确认 username/password 参数被回显到 input value。
2. 构造 `username="><script>alert(1)</script>` 或 `username=" autofocus onfocus=alert(1) x="` 等属性逃逸 payload。
3. 将完整 URL 发给已登录/未登录的管理员或受害者，诱导点击。
4. 脚本在目标站点 origin 下执行，可读取页面数据、发起带会话的请求或配合 CSRF/钓鱼。
5. 验证：浏览器弹窗；响应 HTML 中 payload 未被转义。

## PoC

```text
https://target/admin/login/index?username=%22%3E%3Cscript%3Ealert(1)%3C/script%3E&password=1
```

```html
<!-- 响应中未转义输出 -->
<input type="text" id="username" name="username" value=""><script>alert(1)</script>">
```

## 变体与关联

- [[web-generic-xss-jfinalcms-guestbook-getmodel-stored-admin-review]]：同产品留言功能的存储型 XSS（后台审核触发）。
- [[web-generic-xss-jfinalcms-profile-realname-beetl-unescaped-default]]：同产品 Beetl 模板未转义的另一个 XSS。
- 变体：password 参数同样可注入；可换 `onfocus`/`onmouseover` 等无需 `<script>` 的 payload 绕过简单过滤；结合 CSP 缺失可加载外部脚本。
- 边界：模板启用自动转义、CSP 限制 inline script、参数被过滤时需换 payload。

## 检测与防御

- 检测：登录页请求参数回显到 HTML；响应中出现未转义的 `<`/`"`；WAF/日志中的 XSS payload。
- 防御：按输出上下文转义（HTML 属性用实体编码），或使用模板引擎的自动转义模式；对回显参数做白名单；设置 CSP；Session Cookie 加 `HttpOnly`；对登录页错误回显做最小化。
- 响应：排查是否已有利用该链接的钓鱼/会话窃取。
