---
id: web-generic-http-smuggling-te-te-obfuscated-transfer-encoding
title: TE.TE 请求走私：重复/畸形 Transfer-Encoding 头诱导一端忽略分块解析，退化为 CL.TE 或 TE.CL
type: scenario
domain: web
path: web/generic/http-smuggling
technique: te-te-obfuscated-transfer-encoding-header
aliases:
- TE.TE
- TE.TE request smuggling
- Transfer-Encoding obfuscation
- Transfer-Encoding cow
- 重复 TE 头
- 畸形 Transfer-Encoding
tags:
- http-smuggling
- te-te
- transfer-encoding
- content-length
- header-obfuscation
- http1
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V614
  verified_at: '2026-11-12T20:50:37+08:00'
  notes: '已对照原文『TE.TE vulnerabilities』节及图12-15核对：重复 TE（Transfer-Encoding: chunked + cow）、CL 4、chunk 5c、GPOST 请求，二次请求 403 GPOST，Solved；与图13/14一致。混淆写法清单（xchunked/冒号空格/tab/obs-fold/头名换行）与原文列举一致。未验证点：未本机复跑；无 sources；无版本/CVE。dedup：unknown-te-cl-differential 是代理见 TE 即 chunked + Flask 回退 CL 的具体案例；本卡为重复/畸形 TE 通用手法，非同一条链，保留。'
---

## 一句话结论

当前端与后端都支持 `Transfer-Encoding: chunked` 时，利用重复的 TE 头、未知 TE 值、头名空格、obs-fold、大小写/编码等畸形写法，诱导其中一端认为"这不是 chunked"而退回 `Content-Length` 解析，从而把 TE.TE 退化成 CL.TE 或 TE.CL 完成走私。

## 原理

- 双方都"支持 TE"并不等于双方对同一个畸形头得出相同结论：不同代理/框架对重复头、未知值、空白、折叠头的容错策略不同。
- 常见混淆写法包括：`Transfer-Encoding: xchunked`、`Transfer-Encoding : chunked`（冒号前空格）、`Transfer-Encoding:[tab]chunked`、`[space]Transfer-Encoding: chunked`、`X: X\r\n Transfer-Encoding: chunked`（obs-fold）、`Transfer-Encoding\r\n: chunked`（头名换行）、以及同时发两个 TE 头（如 `Transfer-Encoding: chunked` + `Transfer-Encoding: cow`）。
- 只要一端把这些写法判为"无效/未知 TE"并忽略该头、改用 `Content-Length`，另一端仍按 chunked 解析，就会出现和 CL.TE/TE.CL 相同的边界分歧。
- 为什么成立：HTTP 规范对畸形头的处理留有余地，真实实现以"尽量容错"为常态；安全边界依赖两端解析结果一致，而这是实现细节而非协议保证。
- 选择哪种混淆取决于目标：要制造 CL.TE，就让前端忽略 TE（按 CL）、后端仍按 chunked；要制造 TE.CL，则反过来让后端忽略 TE。

## 触发条件

- 前端与后端都声明支持 chunked，但对重复 TE 头、未知 TE 值、空白/折叠等畸形写法的处理不一致。
- 前端会原样转发 TE 头而未规范化或拒绝畸形头。
- 前后端复用连接。
- 攻击者可以逐字节构造原始请求并尝试多种混淆变体。

## 利用步骤

1. 先确认两端都接受标准 chunked：发送正常 chunked 请求观察是否被正确解析。
2. 逐一变体测试混淆写法，观察哪些写法会让一端退回 CL：常用 `Transfer-Encoding: chunked` 与 `Transfer-Encoding: cow` 重复头、`xchunked`、冒号前空格、tab、obs-fold。
3. 找到有效变体后，按 CL.TE 或 TE.CL 的方向构造正文：CL 覆盖整包、后端按 chunked 在 `0` 块终止；或前端按 chunked 截断、后端按 CL 继续读取。
4. 用 `0\r\n\r\nG` 或完整 `GPOST / HTTP/1.1` 验证方法错乱，再用完整管理请求做利用。
5. 若一种写法被两端一致拒绝，换用另一种；不同产品组合（Nginx/Apache/HAProxy/各语言框架）的有效变体不同。

## PoC

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: cow

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```

说明：重复 TE 头中一个为标准 `chunked`、一个为未知值 `cow`；某端按最后一个/未知值忽略 TE 并退回 CL，另一端仍按 chunked，形成 TE.CL/CL.TE 等价分歧。`Content-Length` 与 chunk 长度需按目标实际解析结果调整。PoC 为靶场流程的结构化复现，未在本机执行，仅用于授权测试。

## 变体与关联

- 变体写法：`xchunked`、`chunked, identity`、大小写混用、冒号前/后空格、tab、头名折行、`Transfer-Encoding` 单独一行后接 `: chunked`。
- 变体：重复 `Content-Length` 制造 CL.CL 分歧，或 TE 头与 CL 头数量不一致。
- 关联：[[web-generic-http-smuggling-cl-te-basic-chunk-prefix]]、[[web-generic-http-smuggling-te-cl-basic-chunk-prefix]]（TE.TE 成功后按这两种方向利用）、[[web-generic-http-smuggling-unknown-te-cl-differential]]（未知 TE 值导致后端回退 CL 的具体案例）。
- 边界：前端严格规范化并拒绝畸形 TE、或两端使用同一解析库时，难以找到有效变体。

## 检测与防御

- 检测：重复 `Transfer-Encoding` 头；未知 TE 值；头名/冒号前后异常空白、tab、obs-fold；同一请求 TE 与 CL 并存；响应出现方法错乱或异常延迟。
- 防御：前端拒绝重复 TE、未知 TE 值、头名空白、obs-fold（返回 400）；统一按 RFC 9112 解析并在转发前重新序列化；对 CL+TE 并存请求一律拒绝。
- 加固：代理与后端使用同一 HTTP 解析实现或经过一致性测试；部署能检测 desync 的网关；监控跨层请求数不一致。
