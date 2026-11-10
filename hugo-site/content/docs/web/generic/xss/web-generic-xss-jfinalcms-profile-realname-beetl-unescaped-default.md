---
id: web-generic-xss-jfinalcms-profile-realname-beetl-unescaped-default
title: jfinal cms 个人资料 realname 入库后由 Beetl 模板 ${user.realname} 原样输出：默认不转义的存储型 XSS
type: scenario
domain: web
path: web/generic/xss
technique: beetl-default-no-escape-stored-xss-profile-field
tags:
- java
- xss
- stored-xss
- beetl
- cms
- template-escaping
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T12:05:36+08:00'
  notes: 已对照原文核对：PersonController.save 收集 model.realname 后 model.update 走预编译（无注入）、userinfo.html 中 \ 原样输出、payload model.realname=m<svg/onload=alert(1)> 与原文一致；原文未标注受影响版本，未设 affected_versions；未复跑（需 jfinal cms 环境）
url: /docs/web/generic/xss/web-generic-xss-jfinalcms-profile-realname-beetl-unescaped-default/
draft: false
kb_aliases:
- jfinal cms 存储型 XSS
- Beetl 默认不转义
- realname 注入
- ${user.realname} 输出
- 个人资料 XSS
---

## 一句话结论

jfinal cms 前台“个人信息保存”接口把 `model.realname` 等字段直接 `update` 入库（SQL 用预编译，所以没有注入），但展示页 `userinfo.html` 里写的是 `${user.realname!''}`——Beetl 默认**不做 HTML 转义**，于是保存 `m<svg/onload=alert(1)>` 后，任何打开该用户信息页的人（含管理员）都会触发存储型 XSS。

## 原理

- **入库无过滤、输出无转义，两处都缺才成立**：`PersonController.save()` 用 `getModel(SysUser.class)` 收集 `model.realname`，随后 `model.update()` 走 `PreparedStatement` 参数化（SQL 注入被挡住），但值本身原封不动写入 `sys_user.realname`；渲染时模板 `${user.realname!''}` 直接把字符串拼进 HTML。
- **Beetl 的默认转义策略**：Beetl 有 `<#escape>` / 全局 `HTML_TAG_FLAG` 之类机制，但默认配置下 `${...}` 输出不做实体编码（与 JSP EL、Thymeleaf 的默认行为不同），所以“模板用了安全框架”并不等于“输出安全”。
- **为什么是存储型而非反射**：payload 落在数据库，展示点（用户信息卡片、评论/回复列表里的作者名、后台用户列表）每次渲染都会重新触发；不需要构造带 payload 的链接去钓鱼。
- **危害面**：触发者是浏览该页面的其他用户/管理员；同源脚本可读取管理员会话内的 CSRF token、调用后台接口（如本批次的模板编辑/文件管理器），把 XSS 升级为后台操作甚至 RCE。
- **为什么 `getModel` 的字段名可控**：`model.realname=m<svg/onload=alert(1)>` 这类 `model.<字段>` 参数由 jfinal 的 `getModel` 按属性名绑定，只要实体类有该属性即可写入；`save()` 里只校验 `userid == session userid`（防止改别人的资料），没有内容校验。

## 触发条件

- 应用使用 Beetl 且未开启全局 HTML 转义（jfinal cms 默认如此）。
- 个人信息/昵称/签名/备注等字段可被当前登录用户自由填写并入库。
- 存在把该字段原样输出的模板（`${user.realname}`、`${user.remark}` 等）。
- 受害者（含管理员）会浏览到该字段的展示页。

## 利用步骤

1. 注册/登录普通账号，进入“个人信息”页。
2. 抓 `POST /person/save` 请求，确认参数形态：`model.userid=<自己的 id>`、`model.realname=<payload>`、`old_password/new_password` 等。
3. 用最小 payload 验证：`model.realname=m<svg/onload=alert(1)>`，保存后访问个人主页/评论区，观察是否弹窗。
4. 确认可执行后换成实战 payload：读取同源页面里的 token、以当前用户身份请求后台接口，或外带 `document.cookie`（若 cookie 非 HttpOnly）。
5. 若管理员会查看该用户资料，可进一步用 XSS 借管理员会话调 `admin/template` 模板保存或 `admin/filemanager` 写文件（见 [[web-generic-ssti-beetl-static-class-reflect-runtime-blacklist-bypass]]、[[web-java-component-filemanager-arbitrary-read-write-path-traversal-jfinal-filter]]）完成 RCE。

## PoC

```http
POST /jfinal_cms/person/save HTTP/1.1
Host: target:8081
Cookie: JSESSIONID=...; session_user=...
Content-Type: application/x-www-form-urlencoded

model.userid=3&model.realname=m<svg/onload=alert(1)>&model.email=a@b.c&old_password=123456&new_password=&new_password2=&model.remark=&model.tel=&model.title_url=&search_header=
```

保存后访问 `userinfo.html` 渲染的页面（个人主页/帖子作者信息）即触发。

## 变体与关联

- 变体：`remark`、`title_url`、`tel` 等同批字段同样原样输出，可挑不过滤长度/字符集的那个。
- 变体：Beetl 若开启了 `<#escape>` 局部转义，检查是否只包住了部分模板片段（常见遗漏是 `includes/userinfo.html` 这类被 include 的片段）。
- 变体：后台用户列表、评论回复列表等二次展示点往往比个人主页更容易被管理员看到，优先在这些位置验证。
- 关联：[[web-generic-xss]] 通用存储型/反射型手法、[[web-generic-ssti-beetl-static-class-reflect-runtime-blacklist-bypass]]（同一模板引擎的代码执行升级）、[[web-generic-sqli-jfinalcms-baseform-orderby-extractvalue]]（同 CMS 的注入面）。

## 检测与防御

- 修复：模板输出统一转义（`${user.realname!''}` 改为经过 HTML 实体编码的函数/`<#escape>` 包裹），或在入库前做白名单（昵称只允许字母数字与少量符号）。
- 加固：Beetl 开启全局 HTML 转义；对富文本字段单独用白名单清洗（而不是全局转义）。
- 检测：请求体中出现 `<script`、`<svg`、`onload=`、`javascript:` 等片段写入用户资料字段；响应页面中原样出现这些片段。
- 响应：清理已入库的恶意字段、对受影响模板加转义后重新发布、审计管理员在 XSS 时间窗内是否调用了敏感后台接口。
