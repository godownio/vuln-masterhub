---
id: web-generic-xss-self-xss-csrf-auto-create
title: self-XSS 经 CSRF 自动创建资源放大：仅自己可见的存储型 XSS 变成可打任意登录用户
type: scenario
domain: web
path: web/generic/xss
technique: self-xss-csrf-escalation
aliases:
- self-xss 提升危害
- self-xss 加 CSRF
- XSS 与 CSRF 组合拳
- 自打 XSS 放大
- CSRF 自动创建 payload
tags:
- xss
- csrf
- stored-xss
- self-xss
- exploit-chaining
- web
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V514
  verified_at: '2026-11-11T11:43:27+08:00'
  notes: 已对照原文与全部19张截图（含07/09/10/15/16/19降采样图）：POST /v1/handout/add、name字段HTML落库并在编辑页解析、Burp text/plain CSRF自动提交、创建响应handout_id/edit_uri、alert(document.cookie)均可见。修正两处技术细节：原PoC的value='"value=1"}'会生成非法JSON，改为value='value=1"}'并更新演示body；SameSite=Lax不随跨站POST携带，改为None/旧浏览器；edit_uri按截图改为login?redirect&readOnly跳转。dedup报告中的duplicate为同id同文自匹配，非真实重复；与库内存储型XSS/text-plain CSRF卡不同链。原文无产品名/版本，不设affected_versions。
---

## 一句话结论

当存储型 XSS 只在自己的账号里可见（self-XSS：payload 落库后仅创建者能打开的编辑/预览页会渲染它），而创建接口又没有 CSRF Token 与 Origin/Referer 校验时，攻击者可用 `enctype="text/plain"` 的 HTML 表单诱导已登录受害者的浏览器自动提交创建请求，把 payload 写进受害者自己的账号，随后受害者打开自己的新建资源页时 XSS 在其会话内执行，危害由「自己弹自己」放大为可打任意登录用户。

## 原理

- **self-XSS 的判定**：功能点（如新建个人课件）提交后只有创建者本人能进入带个人 token 的编辑/预览页，别人没有该资源的访问权限，payload 只在创建者自己的浏览器触发，常规认知是「自慰洞」没有实际危害。
- **创建接口无 CSRF 防护**：新建课件的 JSON API（如 `POST /v1/handout/add`）只依赖 Cookie 会话鉴权，不校验 CSRF Token，也不校验 Origin/Referer，因此任何第三方页面都能以受害者身份发起创建请求。
- **为什么用 text/plain 表单发 JSON**：普通表单会把 JSON 里的 `{`、`"`、`:` 等 URL 编码，后端无法按 JSON 解析；`enctype="text/plain"` 时浏览器按 `name=value` 原样拼接请求体、Content-Type 也是 `text/plain`，而目标后端只读原始 body 按 JSON 解析、不校验 Content-Type，于是能跨站直发 JSON。表单会在字段名后自动追加 `=`，构造时把需要吸收该等号的内容放进某个字符串值（`'value='` 技巧），保证最终 body 仍是合法 JSON 或被宽松解析器容忍。
- **为什么在受害者浏览器能触发**：payload 是受害者自己的浏览器请求创建的，资源天然属于受害者账号；创建响应返回 `handout_id` 与 `edit_uri`（原文截图显示为带 `login?redirect=…&readOnly=…` 参数的编辑跳转链接），受害者编辑页会把落库的 name/正文按 HTML 渲染，`<img/src/onerror=...>` 立即执行；攻击者无需知道受害者的 token 或资源 id。
- **关键放大点**：不是「攻击者替受害者创建」，而是「利用受害者自己的会话与权限创建后由受害者自己的页面渲染」，绕过了 self-XSS 的访问隔离。

## 触发条件

- 存储型 XSS 点位于「创建后仅创建者可见」的资源（个人课件、笔记、草稿、收藏夹等），且创建接口允许 HTML 原样落库、渲染页会解析。
- 创建接口无 CSRF Token、无 Origin/Referer 校验；后端接受 `text/plain` 请求体仍按 JSON 解析（或不存在 Content-Type 强校验）。
- 受害者已登录目标站，且会话 Cookie 能随跨站 POST 携带（`SameSite=None`；`SameSite=Lax` 的 Cookie 不会随跨站 POST 提交，只有旧浏览器或未启用 SameSite 的场景才成立）。
- 攻击者能把 CSRF PoC 页面托管在外部站点并诱导受害者访问。

## 利用步骤

1. 找到带输入框的功能点，先插 `<h1>111` 探测；提交后列表/详情不解析，但进入编辑/预览页时正文被解析，确认是存储型 XSS；再确认该资源别人无法访问 → 判定 self-XSS。
2. 抓取创建请求（JSON API，如 `POST /v1/handout/add`），验证只靠 Cookie 鉴权、无 CSRF Token、无自定义头校验，Content-Type 改为 `text/plain` 后后端仍能解析。
3. 用 Burp 的 Engagement tools → Generate CSRF PoC 生成 `enctype="text/plain"` 表单，把 `name` 字段的值替换为 XSS payload（如 `<img/src/onerror=alert(document.cookie)>`）。
4. 把提交控件改成自动触发（`<script>` 中 `document.querySelector('button').click()`，或 `<body onload>` 直接 `submit()`），页面挂到攻击者 VPS。
5. 诱导已登录的受害者打开 PoC 链接：浏览器带着会话自动创建课件（响应返回 `handout_id`/`edit_uri`）；受害者随后打开自己的新建课件编辑页（或按 `edit_uri` 跳转）时，payload 在受害者会话内执行。
6. 实战把 `alert` 换成数据外带（读 cookie/localStorage、页面 DOM 回传攻击者服务器），注意 payload 内的引号要适配 text/plain 表单与 JSON 的拼接方式。

## PoC

```html
<html>
<body>
<!-- 压低历史记录，避免后退暴露 -->
<script>history.pushState('','','/')</script>
<form action="https://target.example/v1/handout/add" method="POST" enctype="text/plain">
  <!-- 整段 JSON 放进 name：rubbish 的字符串在 name 末尾留开引号，value 补上剩余内容，
       使浏览器自动追加的 = 落入字符串值内部，最终 body 仍是合法 JSON -->
  <input type="hidden" name='{"name":"<img/src/onerror=alert(document.cookie)>","grade":"1","type":"2","school":"1","rubbish":"' value='value=1"}'>
  <button type="submit">Submit request</button>
</form>
<script>
  var btn = document.querySelector('button');
  btn.click(); // 打开页面即自动提交，无需受害者交互
</script>
</body>
</html>
```

```text
浏览器实际发送（Content-Type: text/plain）：
{"name":"<img/src/onerror=alert(document.cookie)>","grade":"1","type":"2","school":"1","rubbish":"=value=1"}
name 属性在 rubbish 字符串的起始引号后结束，浏览器补的 = 与 value 内容一起落在该字符串值内部（rubbish 值为 "=value=1"），整体仍是可解析 JSON；末尾的换行由 text/plain 表单追加，宽松解析器会忽略。
```

## 变体与关联

- 变体：不只「创建」，self-XSS 还可以通过 CSRF 调「保存/更新」接口，把 payload 写进受害者账号里已有且自身可见的资源（个人简介、笔记正文、草稿），同样由受害者后续打开时触发。
- 变体：若创建接口强制 `application/json`（触发 CORS 预检），可退回到无预检的 `GET` 型写操作、`multipart/form-data` 表单，或寻找允许空 Origin 的 JSON API。
- 变体：CSRF 也可以只用来「把资源设为公开/分享」，配合分享页放大存储型 XSS 的触达面。
- 关联：[[web-generic-csrf-json-text-plain-form-enctype]]（`enctype=text/plain` 直发 JSON、`'value='` 吸收等号的通用原理）、[[web-generic-csrf-missing-token-state-changing-endpoint]]（无 Token 状态变更接口的通用判定）。
- 边界：接口有 CSRF Token、严格校验 Origin/Referer、Cookie 为 `SameSite=Strict`，或渲染页对 HTML 做了净化时不成立。

## 检测与防御

- 修复：所有状态变更接口（尤其创建）加 CSRF Token 并校验 `Origin`/`Referer` 必须存在且同源；JSON 写接口拒绝 `text/plain` 并要求自定义头。
- 修复：富文本字段在服务端落库前/输出时做 HTML 白名单净化，不要依赖「只有本人可见」作为安全边界。
- 加固：会话 Cookie 设 `SameSite=Lax/Strict`、`Secure`、`HttpOnly`；敏感创建操作加验证码或二次确认。
- 检测：状态变更请求 Content-Type 为 `text/plain` 但 body 是 JSON、Origin/Referer 缺失或跨站；新建资源正文出现 `<script`、`onerror`、`onload` 等特征。
