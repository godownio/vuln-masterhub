---
id: web-generic-ssrf-url-parser-differential-allowlist-bypass
title: URL 解析器分歧导致主机白名单绕过 SSRF
type: scenario
domain: web
path: web/generic/ssrf
technique: url-parser-differential-allowlist-bypass
aliases:
- 反斜杠 SSRF
- fast-uri 白名单绕过
- URL 解析差异
- parser differential SSRF
tags:
- ssrf
- nodejs
- fastify
- fast-uri
- url-parser
- allowlist
- cve-2026-16221
- cve-2026-18446
cve:
- CVE-2026-16221
- CVE-2026-18446
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: CVE-2026-16221：2.3.1–2.4.2、3.0.0–3.1.3、4.0.0–4.1.0；CVE-2026-18446：<2.4.4、3.0.0–3.1.4、4.0.0–4.1.1
verification:
  verified_by: verifier-C
  verified_at: '2026-11-04T19:08:13+08:00'
  notes: 已对照原文与28张图核对：两 CVE 版本区间、fast-uri/Node 双向解析分歧、四类解析器、补丁只置 error 不拒绝、%5C/全角/NFKC 残余绕过、ajv-formats 三档均一致；PoC 为最小化复现，原文脚本未逐行执行
---

## 一句话结论

当校验端用 `fast-uri` 解析 URL、执行端用 Node 原生 WHATWG `URL`/`fetch` 时，同一个含反斜杠的 URL 在两边解析出不同主机：白名单看到 `allowed.com`，实际请求却连到 `127.0.0.1`，从而绕过主机白名单形成 SSRF。

## 原理

- RFC 3986 中反斜杠 `\`（U+005C）不是合法 URI 字符，也不是 authority 分隔符；`fast-uri` 按这个口径解析，把它当作 userinfo 中的普通字符，因此 `http://127.0.0.1:9011\@allowed.com` 的 host 仍是 `allowed.com`。
- WHATWG URL 规范对 special scheme 做错误恢复，把 `\` 当成 `/`。Node 原生 `URL` 因此把它解析为 host `127.0.0.1:9011`、path `/@allowed.com`。
- 校验与执行看到的是同一个字符串，却得到两个主机名。守卫若只比较 `parse().host`，就只看到 `allowed.com` 而放行；执行端却按 Node 的解析结果连接内网。
- 第二类形态出在相对引用解析：`resolve(base, "\\\\evil.com/path")` 中，`\\`、`/\`、`\/` 是否构成 authority 引入符，`fast-uri` 与 WHATWG 判定不同。旧版把整段折进 path，认为仍在 `allowed.com`；Node 则认为去了 `evil.com`。
- 修复版 `fast-uri` 对可疑 authority 只赋值 `parsed.error`，不抛异常、不修改 `host`。因此“升级即安全”不成立，调用方必须显式检查 `error`。

## 触发条件

- 应用提供“按 URL 抓取/预览/代理/Webhook”功能，并用主机白名单限制目标。
- 校验使用 `fast-uri`（Fastify 生态常见，或直接依赖），执行使用 Node `fetch`/`undici`/`http` 或框架自身的请求方法。
- 守卫代码只读 `parse().host`，没有检查 `parse().error`。
- 目标内网存在可访问服务（回环、私网、云元数据等）。

## 利用步骤

1. 找到接受 URL 的参数，确认存在主机白名单且只允许特定域名。
2. 用带反斜杠的 payload 测试：`http://127.0.0.1:PORT\@allowed.com`。
3. 观察响应或回连：若请求实际到达 `127.0.0.1`，说明校验端与执行端解析分歧成立。
4. 将目标换成内网服务、云元数据地址或需要读取的本地端口。
5. 若字面反斜杠被拦，尝试 `%5C`、全角 `U+FF3C`/`U+FF0F`/`U+FE68`，以及相对引用 `\\evil.com/path` 等形态。

## PoC

```text
# 校验端 fast-uri 看到 host=allowed.com；Node 实际连接 127.0.0.1:9011
http://127.0.0.1:9011\@allowed.com

# 反向写法：校验端看到 127.0.0.1，执行端看到 allowed.com（用于探测解析差异）
http://allowed.com\@127.0.0.1:9011/

# 相对引用 + 引入符形态（base = https://allowed.com/）
\\evil.com/path
/\evil.com/path
\/evil.com/path

# 编码/归一化形态
http://127.0.0.1:9011%5C@allowed.com
http://127.0.0.1:9011<U+FF3C>@allowed.com   # 链路若做 NFKC，会折叠成 U+005C
```

```javascript
// 有漏洞的守卫：只看 host，忽略 error
const p = fastUri.parse(rawUrl)
if (p.host === 'allowed.com') return fetch(rawUrl) // 实际连到 127.0.0.1
```

## 变体与关联

- 变体：`%5C` 在修复版仍不报错（补丁只匹配字面 `U+005C`），若后续环节做百分号解码即可再度分歧。
- 变体：全角字符本身不会打穿 Node；只有链路上某一环先做 NFKC 归一化、而校验端读的是归一化前字符串时才成立。
- 变体：`ajv-formats` 的 `format: uri` 在 `mode: "full"` 用纯正则拒绝反斜杠，但 `mode: "fast"` 会放行；`%5C` 在三种模式下都通过，因为“正则校验字符串”与“URL 解析”本就不同。
- 关联：任何“校验用一个解析器、执行用另一个解析器”的场景都可能复现同类问题（Python `urllib.parse`、Go `net/url`、Java `URI`、curl 对同一输入也各不相同）。

## 检测与防御

- 检测：请求参数中出现 `\`、`%5C`、`%5c`、`U+FF3C`、`U+FE68`、`U+FF0F`，尤其是紧跟 host 或 `@` 的位置。
- 检测：URL 抓取功能对回环、私网、链路本地地址发起连接；内网服务日志中出现来自业务服务器的异常请求。
- 修复：升级 `fast-uri` 只是前提；守卫必须 `if (p.error) return false`，并兼容旧版本无该字段的情况。
- 修复：先做 NFKC 归一化再比对，且校验与执行必须使用同一个“最终请求字符串”；不要在校验后再让框架重新解析原始串。
- 加固：不要用字符串做主机白名单；真正连接前解析出 IP，拒绝回环、私网、链路本地（含 `169.254.0.0/16` 元数据地址）后再发起请求。
- 回归：把 `\`、`\\`、`/\`、`\/`、`%5C`、全角变体及其 NFKC 结果写成“必须拦截”的测试用例，而不是“host 等于某值”的断言。
