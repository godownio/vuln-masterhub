---
id: web-generic-http-smuggling-content-encoding-request-body-waf-bypass
title: Content-Encoding 压缩请求体：WAF 不解码而后端解码导致请求体检查绕过
type: scenario
domain: web
path: web/generic/http-smuggling
technique: content-encoding-request-body-waf-bypass
tags:
- web
- waf-bypass
- content-encoding
- gzip
- brotli
- parser-differential
- http
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V14
  verified_at: '2026-11-05T01:38:06+08:00'
  notes: 已对照原文与3张图核对；RFC9110依据、aiohttp/Node等支持栈、11/15绕过、CRS restricted header防御一致；brotli短明文回退已写明；未复现PoC
url: /docs/web/generic/http-smuggling/web-generic-http-smuggling-content-encoding-request-body-waf-bypass/
draft: false
kb_aliases:
- Content-Encoding WAF 绕过
- gzip 请求体绕过 WAF
- brotli 请求体绕过
- 压缩请求体 WAF bypass
- RFC 9110 请求编码差异
---

## 一句话结论

RFC 9110 允许 `Content-Encoding` 用于请求 body；Node（express/koa + body-parser inflate）、aiohttp、Apache mod_deflate InputFilter、Warp 等服务端会解压请求体，而多数 WAF 未实现请求体解码（或把该头视为仅响应使用），于是攻击者把 SQLi/XSS 等 payload 压缩后发送，WAF 看到的是不可解析的二进制而放行，后端解压后正常执行。

## 原理

- HTTP 语义中 `Content-Encoding` 表示“消息 body 已应用的编码”，RFC 9110 并未限制只能出现在响应；服务器对不支持的编码应返回 415。但绝大多数客户端不发压缩请求，导致“请求侧 Content-Encoding”成为实现盲区。
- 一些 HTTP 栈的请求与响应共用同一套 body 解析器：aiohttp 的 `HttpPayloadParser` 同时处理请求/响应的 `Content-Encoding` 与 `Transfer-Encoding`；Node 生态的 body-parser 默认 `inflate: true`，接受 gzip/deflate/br；Apache `mod_deflate` 可配置 `InputFilter`；Warp 提供对应 filter。
- WAF 通常只检查明文 body；遇到 `Content-Encoding: gzip/br` 时要么不解析、要么直接放行原始字节（部分会自动解 gzip，但少解 brotli/zstd）。而后端会解压并交给业务解析器，安全检查与业务执行看到的是两份不同的内容。
- 这是“协议实现差异”类问题：WAF 与后端对同一请求的 body 解码能力/范围不一致，与多 member gzip 解压范围错位（另一类差异）不同，本质是“一方完全不解码”。

## 触发条件

- 目标在 WAF/网关之后，且后端使用支持请求体 Content-Encoding 的栈：
  - Node：Express/Koa + body-parser（`inflate` 默认 true）、raw-body 等，支持 deflate/gzip/brotli；
  - Python：aiohttp，支持 deflate/gzip/brotli/zstd；
  - Apache httpd + mod_deflate 且启用 InputFilter（deflate/gzip）；
  - Rust Warp 启用解压 filter（deflate/gzip/brotli）。
- WAF 未对请求 `Content-Encoding` 做限制/解码，或仅解码 gzip 不解 brotli；
- 攻击 payload 能通过压缩后传输（body 内容越短，brotli 可能保留明文，需加长）。

## 利用步骤

1. 判断后端栈（响应头 `Server`、报错、静态资源特征；Node/Express 常见）。
2. 选择 body 型攻击（JSON SQLi、命令注入、SSTI、反序列化等）。
3. 用 gzip/brotli 压缩 payload，保留原始 `Content-Type`，添加 `Content-Encoding: gzip` 或 `br`。
4. 发送请求，观察 WAF 是否放行、后端是否按解压后的内容执行。
5. 若 gzip 被 WAF 自动解码检查，改用 brotli（支持广、WAF 少解码）；必要时加长 payload 避免 brotli 明文回退。

## PoC

gzip 请求体：

```bash
echo "$payload" | gzip -f | curl -v http://target/api/v0/example \
  -H "Content-Type: application/json" \
  -H "Content-Encoding: gzip" \
  --data-binary @-
```

brotli 变体：

```bash
echo "$payload" | brotli -9 -f | curl -v http://target/api/v0/example \
  -H "Content-Type: application/json" \
  -H "Content-Encoding: br" \
  --data-binary @-
```

示例（对 Node 靶场登录接口的 JSON SQLi）：

```bash
echo '{"email":"'"'"' or 1=1 ;--","password":"test"}' | gzip -9 -f | \
curl --data-binary @- -H "Content-Encoding: gzip" -H "Content-Type: application/json" \
  http://target/rest/user/login
```

aiohttp 最小验证（服务端会解压并 echo 明文）：

```python
from aiohttp import web
async def echo(request):
    return web.Response(text=await request.text())
app = web.Application(); app.router.add_post('/', echo)
web.run_app(app, port=8080)
```

## 变体与关联

- 编码变体：`deflate`、`gzip`、`br`、`zstd`；brotli 支持广且 WAF 解码少，优先级高；zstd 支持面小。
- 后端栈变体：Node body-parser/raw-body、aiohttp、Apache mod_deflate InputFilter、Warp decompression filter。
- 关联：多 member gzip 解压范围错位（WAF 解首 member、后端解全部）；HTTP 请求走私（CL/TE 解析差异）；其他 RFC 实现差异（Transfer-Encoding 多编码、头部解析）。
- 边界：WAF 若像 OWASP CRS 一样把 `Content-Encoding` 列为 restricted header 并拒绝，或强制 415，则失效；后端不支持请求编码时 payload 不会被解压。

## 检测与防御

- WAF/网关：拒绝或限制请求中的 `Content-Encoding`（OWASP CRS 默认把 `content-encoding` 列入 restricted headers）；对支持的编码先完整解压再检查；不支持的编码返回 415；限制多重编码与异常压缩比。
- 后端：若业务不需要压缩请求体，关闭 body-parser 的 `inflate`/对应解压 filter；只接受明确允许的编码。
- 在网关统一解压并转发解码后的 body，确保检查与执行看到同一份内容。
- 日志与检测：请求带 `Content-Encoding` 但 body 为不可读二进制、压缩比异常、br/zstd 等少见编码；结合响应异常判断是否绕过了 WAF。
