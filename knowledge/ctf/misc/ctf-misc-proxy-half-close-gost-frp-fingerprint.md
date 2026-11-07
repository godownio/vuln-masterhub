---
id: ctf-misc-proxy-half-close-gost-frp-fingerprint
title: TCP 半关闭语义指纹：gost 与 frp 代理识别与 PoW 交互
type: scenario
domain: ctf
path: ctf/misc
technique: tcp-half-close-proxy-fingerprint
aliases:
- Proxyport
- gost vs frp
- TCP 半关闭
- 代理指纹
- PoW sha256 26 bit
- 未完成 HTTP 请求头
tags:
- ctf
- misc
- network
- proxy
- gost
- frp
- tcp
- half-close
- fingerprint
- pow
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V116
  verified_at: '2026-11-06T01:47:55+08:00'
  notes: 已对照原文核对：两个 TLS 入口、sha256(prefix||suffix) 前 26 bit 为 0 的 PoW、20 轮、未完成 HTTP 头 + stdin EOF 的半关闭探测、gost 返回 400 Bad Request / frp 2 秒无响应、使用 ncat --ssl 而非 SSLSocket.shutdown 的理由均一致。未验证点：PoC 未在本机复跑；目标域名已过期的比赛实例；frontmatter 无 sources/source_url。
---

## 一句话结论

题目有两个 TLS 入口：一个交互判题端要求先完成 `sha256(prefix || suffix)` 前 26 bit 为 0 的 PoW，然后进行 20 轮“判断转发端背后是 gost 还是 frp”。完整 HTTP 请求两者都会正常转发，差异在 TCP 半关闭语义：发送一个未以空行结束的 HTTP 请求头后让 stdin EOF，gost 会把半关闭继续传给后端，后端认为头已结束但格式不完整并返回 `400 Bad Request`；frp 会继续等待更多请求头字节，2 秒内无响应。用 `ncat --ssl` 复现该半关闭行为，每轮一次 probe 即可全部答对。

## 原理

- **PoW**：交互端 banner 给出十六进制 `prefix`，要求提交十进制 `suffix`，使 `sha256(prefix || suffix)` 的前 26 bit 为 0；多进程暴力搜索即可。每次连接 prefix 变化。
- **为什么完整请求无法区分**：发送 `GET http://forward.service-service/ HTTP/1.1\r\nHost: ...\r\n\r\n` 时，gost 和 frp 都会把完整请求转发到后端并返回同类 HTTP 响应，指纹一致。
- **半关闭差异**：发送 `GET ... HTTP/1.1\r\nHost: ...\r\n`（没有最后的空行），然后关闭发送方向（stdin EOF）。gost 会把“客户端不会再发送更多字节”的半关闭状态继续传给后端；后端看到已结束但缺空行的请求头，返回 `400 Bad Request`，代理把响应回传。frp 在后端仍等待后续请求头字节，2 秒内没有响应。
- **客户端选择**：探测端使用 `ncat --ssl` 而不是 Python `SSLSocket.shutdown()`，因为后者会额外影响 TLS close_notify/半关闭行为，与题目给出的 `ncat` 交互模型不完全一致。
- **判定规则**：2 秒内出现 `400 Bad Request` -> gost；2 秒内无响应 -> frp。20 轮、每轮最多 5 次 probe，实际每轮 1 次即可。

## 触发条件

- 有一个可控制的 TCP/TLS 转发端，背后运行 gost 或 frp，且允许客户端半关闭。
- 后端对不完整 HTTP 请求头的处理可观测（400 或超时）。
- 交互端提供 PoW 与轮次判定，probe 次数有限但足够。
- 探测客户端能精确控制“发送数据后关闭发送方向”的行为。

## 利用步骤

1. 连接交互端，解析 PoW prefix，暴力搜索满足前 26 bit 为 0 的十进制 suffix，提交 `pow <suffix>`。
2. 每轮收到 `round NN/20 ready` 后，用 `ncat --ssl` 向转发端发送未完成 HTTP 请求头，stdin EOF，`timeout 2`。
3. 若输出含 `400 Bad Request` 判 gost；若 2 秒内无输出判 frp。
4. 发送 `answer gost` 或 `answer frp`；重复 20 轮，读取最终 flag。

## PoC

```python
import hashlib, multiprocessing as mp, subprocess, re, socket, ssl, time

FORWARD_HOST = "r2bgtfecg6csp2yrh7cerzwcf5u.cloud.d3c.tf"
INTERACTIVE_HOST = "rile4iqb4ji6bkdx6gutkldm4f4.cloud.d3c.tf"

def pow_worker(prefix, start, step, outq):
    n = start
    while True:
        suffix = str(n).encode()
        d = hashlib.sha256(prefix + suffix).digest()
        if d[0] == 0 and d[1] == 0 and d[2] == 0 and d[3] < 0x40:
            outq.put(suffix); return
        n += step

def solve_pow(prefix):
    workers = max(1, mp.cpu_count())
    outq = mp.Queue()
    procs = [mp.Process(target=pow_worker, args=(prefix, i, workers, outq)) for i in range(workers)]
    for p in procs: p.start()
    suffix = outq.get()
    for p in procs: p.terminate(); p.join()
    return suffix

def probe_once():
    payload = (b"GET http://forward.service-service/ HTTP/1.1\r\n"
               b"Host: forward.service-service\r\n")
    try:
        p = subprocess.run(["timeout", "2", "ncat", "--ssl", FORWARD_HOST, "443"],
                           input=payload, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=3)
        text = p.stdout
    except subprocess.TimeoutExpired:
        text = b""
    return ("gost" if b"400 Bad Request" in text else "frp"), text

def main():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((INTERACTIVE_HOST, 443), timeout=10)
    with ctx.wrap_socket(raw, server_hostname=INTERACTIVE_HOST) as sock:
        banner = recv_until(sock, [b"submit: pow"], timeout=20)
        prefix = re.search(rb"prefix: ([0-9a-f]+)", banner).group(1)
        sock.sendall(b"pow " + solve_pow(prefix) + b"\n")
        for _ in range(20):
            ready = recv_until(sock, [b"ready", b"All answers", b"d3ctf{"], timeout=20)
            if b"d3ctf{" in ready or b"All answers" in ready:
                break
            ans, _ = probe_once()
            sock.sendall(f"answer {ans}\n".encode())
        print(recv_until(sock, [b"d3ctf{"], timeout=20).decode(errors="replace"))
```

## 变体与关联

- 其他代理/服务器指纹：错误页、`Server` 头、HTTP/2 设置、TLS 指纹、连接复用、超时/半关闭行为；代理层差异常在 TCP 语义而非应用协议。
- 半关闭探测可换成 `SHUT_WR`、`Connection: close`、分块传输截断、慢速请求；注意 TLS close_notify 会改变行为。
- PoW 可换成 Argon2/内存硬或更大前导零；多进程/GPU 搜索。
- 关联：代理指纹、TCP 状态机、PoW 求解卡。

## 检测与防御

- 代理部署应统一半关闭/超时/错误响应行为，避免暴露实现指纹；对不完整请求头设置一致超时与错误页。
- 限制探测频率，记录异常半关闭/未完成请求；对 PoW 难度与连接数做限制。
- 防守方也可用半关闭行为做客户端异常检测；但不要依赖单一行为做安全边界。
