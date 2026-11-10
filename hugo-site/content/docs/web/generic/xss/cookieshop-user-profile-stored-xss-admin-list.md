---
id: cookieshop-user-profile-stored-xss-admin-list
title: CookieShop 注册资料存储型 XSS：邮箱/描述/地址未过滤，后台用户与订单列表直接渲染
type: scenario
domain: web
path: web/generic/xss
technique: stored-xss
tags:
- xss
- stored-xss
- java
- spring-boot
- jsp
- jstl
- code-audit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-18
  verified_at: '2026-11-08T12:17:17+08:00'
  notes: 已对照原文核对：img27/28 注册表单仅校验 userName/password、img29/30 后台用户列表触发弹窗（/b/ 与 /a/），sink 为注册资料入库后后台列表渲染，实测成立。与同篇 goods-search 反射 XSS 卡为不同 sink（后台列表渲染 vs JSP ${param.keyword} 输出），dedup 工具单向判 likely_duplicate 经核对为不同漏洞点位，dup-scan pair 判并列保留。未验证点：订单列表页地址字段 XSS 原文未单独截图。
url: /docs/web/generic/xss/cookieshop-user-profile-stored-xss-admin-list/
draft: false
kb_aliases:
- CookieShop 存储型XSS
- CookieShop 用户描述 XSS
- CookieShop 注册字段 XSS
- 后台用户列表存储型XSS
---

## 一句话结论

CookieShop 的注册/资料修改接口只在前端校验用户名与密码，`email`、`address`、`description` 等字段原样入库，后台用户列表、订单列表页通过 JSP/JS 直接渲染这些值，普通用户提交带脚本的注册资料即可在管理员会话中执行任意 JS。

## 原理

漏洞成立需要两个条件同时满足：写入端不校验、输出端不转义。

写入端：`/userController/addUser` 接收 `UserBean`（字段含 `email`、`address`、`description`、`phone`、`gender` 等），前端 `register.html` 的 `registerUser()` 只对 `userName`、`password`、`confirmPassword` 做非空与一致性判断，其余字段不做任何长度/字符检查，后端也没有做 HTML 实体化或黑名单过滤，因此 `<img src=x onerror=...>` 这类字符串按原值写入 `cs_users` 表。

输出端：后台 `pages/users.html` 用 EasyUI datagrid 渲染用户清单，列的 `formatter` 把 `description`、`email`、`address` 等字段拼成 HTML 字符串插入单元格；jQuery 的 `html()`/字符串模板会按 HTML 解析，`<img onerror>` 因此在管理员浏览器里执行。`customers.html`（客户/订单）里的收货地址列是同一模式，下单时填写的地址同样会被后台渲染。

之所以是“存储型”：payload 与触发页面解耦，攻击者只需一次提交（甚至只是正常注册一个账号填资料），之后任何管理员打开用户/订单列表都会命中，无需诱导点击特定链接。

## 触发条件

- 目标开放前台注册，或存在可修改个人资料的接口（`/userController/addUser`、`updateUser` 一类）；
- 攻击者填写的 `email`/`address`/`description` 未被服务端过滤即入库；
- 管理员在后台浏览用户列表、订单列表等展示这些字段的页面；
- 后台页面使用 HTML 拼接方式渲染字段（EasyUI formatter、JSP EL 直接输出、innerHTML）。

## 利用步骤

1. 访问 `/user_register`（或注册弹窗），只填必填的用户名/密码，其余字段填入 payload；
2. 提交后登录后台“用户资料/用户列表”，观察列表单元格是否触发脚本；
3. 若无回显，检查是否存在“查看详情/编辑用户”弹窗，payload 可能在弹窗渲染时才执行；
4. 在订单流程中把收货地址设为 payload，管理员查看订单时同样触发；
5. 实战中把 alert 换成窃取后台功能的请求（如带 CSRF token 的删除/改密接口），把存储型 XSS 升级为后台操作。

## PoC

注册请求（字段值与正常注册一致，仅注入字段不同）：

```http
POST /userController/addUser HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Cookie: JSESSIONID=<任意用户会话>

userName=test&password=<sha1hex>&confirmPassword=<sha1hex>&firstName=test&lastName=test&email=test%40a.com&address=test&phone=test&description=%3E%22%3Cimg+src%3Dx+onerror%3Dalert(%2Fb%2F)%3E&gender=test&isAdmin=false&active=true
```

后台用户列表 `pages/users.html` 渲染该行时弹窗 `alert('/b/')`；同一账号把 payload 放进收货地址，后台订单列表 `admin/order_list` 处也会触发。

## 变体与关联

- 字段变体：`email`、`description`、`address`、`phone`、`firstName`/`lastName` 均未被单独校验，任选一个即可，多字段同填可提高命中率；
- 载体变体：用户列表 → 订单列表 → 订单详情，同一个库值在多处渲染，命中面随功能增加；
- 关联：反射型 XSS（商品搜索 `keyword`）、CSRF（后台删除类 GET 接口无 token）；三者组合可在管理员会话里完成“读数据 + 改状态”的完整操作；
- 关联：后台列表 EasyUI/DataGrid 的 `formatter` 返回 HTML 是这类“入库不过滤+前端拼 HTML”CMS 的通病，审计时应优先检查所有 `formatter`。

## 检测与防御

- 输出编码：所有字段在 HTML 上下文输出时做实体编码（JSP 用 `<c:out>` 或 `fn:escapeXml`，EasyUI formatter 用 `$('<div>').text(v).html()`）；
- 输入校验：对 `email` 做正则校验、`address`/`description` 做长度与字符白名单，服务端拒绝 `<`、`>`、引号等危险字符并不等于安全，根因仍在输出端；
- 富文本需求：若确需保留 HTML，使用白名单 sanitizer（OWASP Java HTML Sanitizer），不要用黑名单替换；
- 检测：注册/改资料接口提交 `<img/onerror>`、`<svg/onload>` 后由管理员账号访问列表，观察是否弹窗；SIEM 侧监控资料字段中的 `<script`、`onerror=`、`javascript:` 特征。
