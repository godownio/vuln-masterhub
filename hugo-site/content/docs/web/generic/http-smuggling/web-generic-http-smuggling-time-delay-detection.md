---
id: web-generic-http-smuggling-time-delay-detection
title: 请求走私的时间延迟检测：构造后端等待不完整 chunk 的请求，以响应耗时判定 CL.TE/TE.CL
type: scenario
domain: web
path: web/generic/http-smuggling
technique: request-smuggling-time-delay-detection
tags:
- http-smuggling
- detection
- timing-attack
- cl-te
- te-cl
- chunked
- content-length
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V614
  verified_at: '2026-11-12T20:50:39+08:00'
  notes: "已对照原文『检测扩展-时间差异』CL.TE/TE.CL 两段核对：CL.TE 探测 CL 4 + 正文 1\r\nA\r\nX；TE.CL 探测 CL 6 + 正文 0\r\n\r\nX；与原文 PoC 完全一致。该节无本地截图（图16起为响应差异靶场），卡片依据正文。未验证点：未本机计时验证；无 sources；无版本/CVE。dedup：pause-based-desync-timeout 是反向利用超时的注入原语，非检测方法；库内无同类检测卡，保留。"
url: /docs/web/generic/http-smuggling/web-generic-http-smuggling-time-delay-detection/
draft: false
kb_aliases:
- 时间延迟检测请求走私
- time delay request smuggling
- CL.TE 时间检测
- TE.CL 时间检测
- Burp Scanner smuggling
---

## 一句话结论

向目标发送一个让前端按一种长度截断、后端按另一种长度继续等待剩余字节的请求，若响应出现稳定的秒级延迟，即可在不依赖回显差异的情况下判定 CL.TE 或 TE.CL 请求走私。

## 原理

- 走私的根因是前后端对请求体结束位置理解不一致。检测时反过来利用这一点：故意构造"一端认为已结束、另一端认为还没读完"的报文，让后端阻塞等待永远不会到达的字节。
- CL.TE 探测：前端信 `Content-Length`，只转发前几个字节；后端信 `Transfer-Encoding: chunked`，读到第一个非零块后等待下一个块，直到超时。
- TE.CL 探测：前端信 `Transfer-Encoding: chunked`，在 `0` 块处结束并只转发到该处；后端信 `Content-Length`，认为还有剩余字节未到，阻塞等待。
- 为什么能作为判据：正常请求不会让服务器等待未声明的字节；只有两端解析长度不一致时才会出现"服务器等一个不存在的块/字节"的稳定延迟。Burp Scanner 即采用此类时间差技术。
- 判据是相对延迟：同一目标、同一路径下与正常请求对比，延迟显著且可重复；单次偶发慢请求不足以确认。

## 触发条件

- 目标位于 HTTP/1.1 前后端架构中，存在 CL/TE 解析差异的可能。
- 攻击者可发送原始 HTTP 请求并控制 CL/TE 头与正文。
- 服务器/代理的读取超时在可观测范围内（常见数秒），且网络抖动较小。
- 目标允许同连接或新建连接上的重复探测，不因异常请求直接断开。

## 利用步骤

1. 先测量基线：对同一 URL 连续发送多次正常请求，记录响应时间分布。
2. CL.TE 探测：发送 `Transfer-Encoding: chunked`、`Content-Length: 4`，正文 `1\r\nA\r\nX`；前端只转发 4 字节，后端等待下一块。若响应明显慢于基线（如数秒），疑似 CL.TE。
3. TE.CL 探测：发送 `Transfer-Encoding: chunked`、`Content-Length: 6`，正文 `0\r\n\r\nX`；前端在 `0` 块结束，后端按 CL 等待剩余字节。若出现稳定延迟，疑似 TE.CL。
4. 重复 3~5 次确认延迟可复现，并与正常请求、错误长度请求做对照，排除后端业务慢查询与网络抖动。
5. 用差分响应法进一步确认具体方向（见关联卡），再进入利用阶段。

## PoC

CL.TE 时间探测：

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```

TE.CL 时间探测：

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0

X
```

说明：两组请求分别让后端等待"下一个 chunk"与"剩余 CL 字节"，超时表现为响应延迟。PoC 为原理性构造，未在本机执行，仅用于授权测试。

## 变体与关联

- 变体：调整 `Content-Length` 与块长度制造更长等待；或在同一连接上先发探测再发正常请求，观察正常请求是否被延迟/污染。
- 变体：用响应体差异（404、错误页、反射内容）替代时间作为判据，适合超时不可观测的环境。
- 关联：[[web-generic-http-smuggling-cl-te-basic-chunk-prefix]]、[[web-generic-http-smuggling-te-cl-basic-chunk-prefix]]（探测到后按对应方向利用）、[[web-generic-http-smuggling-differential-response-confirmation]]（差分响应确认）、[[web-generic-http-smuggling-pause-based-desync-timeout]]（把超时等待反过来用于注入前缀）。
- 边界：前端主动拒绝 CL+TE 并存、超时极短或极长、链路抖动大时，时间判据可能失效。

## 检测与防御

- 检测（防守方）：监控同一来源出现 CL 与 TE 并存、chunk 体不完整、连接在后端长时间空闲后超时的请求；统计异常响应时长与同连接请求数。
- 防御：前端拒绝 CL+TE 并存请求；统一解析器；代理到后端禁用连接复用或设置短读取超时并关闭异常连接。
- 加固：WAF 识别时间探测模式（重复异常长度请求）；对异常请求限速与告警；部署 desync 检测网关。
