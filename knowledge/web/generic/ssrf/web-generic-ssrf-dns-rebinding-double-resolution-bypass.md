---
id: web-generic-ssrf-dns-rebinding-double-resolution-bypass
title: SSRF 校验与请求两次 DNS 解析：DNS 重绑定 + 短 TTL 竞争访问 127.0.0.1 内部服务
type: scenario
domain: web
path: web/generic/ssrf
technique: ssrf-dns-rebinding-double-resolution
aliases:
- DNS 重绑定 SSRF
- 解析校验与连接分离
- 短 TTL rebinding
- rbndr.us
- SSRF IP 黑名单绕过
- register/trigger 两次校验
tags:
- ssrf
- dns-rebinding
- toctou
- ip-blacklist
- loopback
- internal-service
- race
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V206
  verified_at: '2026-11-07T02:23:45+08:00'
  notes: 已对照原文与图07-09核对：is_ip_allowed 用 socket.gethostbyname 校验一次，requests.post 连接时再解析一次；rebinder A=127.0.0.1/B=8.8.8.8 生成 7f000001.08080808.rbndr.us，注册成功、trigger 先报 IP 127.0.0.1 not allowed 后成功返回 flag，证明双解析竞争。dup-scan 与 19243 重定向链卡为 related，机制不同（解析层 vs 302 跳转），并列保留。未复跑 PoC。
---

## 一句话结论

当 SSRF 防护用 `socket.gethostbyname(host)` 解析一次并拒绝私网/回环地址、而真正发请求时 `requests`/`urllib3` 又独立解析一次域名时，攻击者可用自己控制的短 TTL 重绑定域名（如 `7f000001.08080808.rbndr.us`）让校验阶段解析到公网 IP、请求阶段解析到 `127.0.0.1`，从而访问只监听在本机的内部服务；两次校验（注册与触发）都需要运气与重试，但短 TTL 使竞争可行。

## 原理

- **校验与使用分离（TOCTOU）**：`is_ip_allowed(url)` 内先 `urlparse` 取 host，再 `socket.gethostbyname(host)` 得到一个 IP，判断 `is_private/is_loopback/is_link_local/is_reserved`。但函数返回后，`requests.post(url)` 会重新做一次 DNS 解析来建立连接；两次解析结果可以不同。
- **DNS 重绑定**：攻击者控制的域名在权威 DNS 上返回两条 A 记录（公网 IP 与 127.0.0.1），TTL 设为 0/极短，或按查询次数交替返回。校验查询命中公网 IP 时通过；连接查询命中 127.0.0.1 时访问内网。公开服务 `rbndr.us` 用“两个 IP 的十六进制拼接”生成主机名（如 `7f000001.08080808.rbndr.us` 在 `127.0.0.1` 与 `8.8.8.8` 间随机解析）。
- **两次检查的额外约束**：注册与触发各调用一次 `is_ip_allowed`，触发时 `requests.post` 还会再解析一次；要达到“检查=公网、连接=内网”，单次成功率取决于解析器缓存/随机性，通常需要反复注册/触发或准备多个 rebinding 域名。
- **为什么短 TTL 重要**：TTL 长会让操作系统/解析器缓存上一次结果，校验与连接拿到同一 IP；TTL=0/1 让每次查询都可能变化，制造校验与使用之间的窗口。
- **目标内部服务**：示例在 `127.0.0.1:5001` 起一个仅处理 `POST /flag` 的 HTTP 服务，返回 flag；它不校验来源，只依赖“外部不可达”作为边界，SSRF 一旦能从本机发起请求即可读取。
- **为什么防护失效**：IP 黑名单只在“解析一次”的时点生效，没有把校验结果固定为连接时使用的 IP（没有自定义 resolver/pinned connection），也没有在连接层再次校验实际对端地址。

## 触发条件

- SSRF 目标 URL 由用户可控，且校验函数对 hostname 做一次 DNS 解析后按 IP 分类拒绝内网。
- 真正发起请求的 HTTP 客户端（requests/urllib3/curl 等）在连接时独立解析域名，且不强制复用校验时的 IP。
- 攻击者能控制一个域名（或使用公开 rebinding 服务），可返回短 TTL 的两条 A 记录。
- 内部服务监听在 127.0.0.1/私网地址，且攻击者知道端口与路径（可从源码、端口探测、常见 5000/8000/8080 等猜测）。
- 服务端允许出站 DNS 与 HTTP（至少能解析攻击者域名）。

## 利用步骤

1. 审计 SSRF 校验逻辑：确认是否 `gethostbyname` 一次、请求库是否再次解析、是否有 DNS 缓存/连接池复用。
2. 用 rebinding 服务生成域名：公网 IP 选一个可通过校验的地址（如 8.8.8.8 或自己的公网服务器），内网 IP 选目标（如 127.0.0.1），得到 `7f000001.08080808.rbndr.us` 这类主机名。
3. 注册 webhook/URL：提交 `http://<rebind-host>:<port>/flag`，反复尝试直到注册成功（校验解析到公网 IP）。
4. 触发：调用 `/trigger`，服务端再次校验并 `requests.post`；反复触发，观察响应；成功时返回内部服务的内容（示例 flag）。
5. 若目标端口未知，先对 127.0.0.1 常见端口做 SSRF 探测（5000/5001/8000/8080/3000），或用错误信息区分连接拒绝与超时。
6. 若 `requests` 使用连接池/缓存导致成功率低，换多个 rebinding 域名或让域名按查询顺序交替返回；必要时在自己 DNS 上精确控制 A 记录顺序与 TTL。
7. 记录成功请求与时间窗口；控制重试频率，避免触发风控。

## PoC

```python
# 依赖公开 rebinding 服务 rbndr.us：127.0.0.1 + 8.8.8.8 交替解析
import requests, time

TARGET = "http://sun-shop.example"          # 存在 SSRF 的应用
REBIND = "http://7f000001.08080808.rbndr.us:5001/flag"
s = requests.Session()

for attempt in range(200):
    r = s.post(f"{TARGET}/register", data={"url": REBIND})
    if r.status_code == 200 and "registered" in r.text:
        wid = r.json()["id"]
        for _ in range(20):
            t = s.post(f"{TARGET}/trigger", data={"id": wid})
            if t.status_code == 200 and "flag" in t.text:
                print("hit:", t.text)
                raise SystemExit
            time.sleep(0.2)
    time.sleep(0.2)
print("no hit; retry with another rebinding domain / longer run")
```

```text
原理验证：在攻击者 DNS 上把同一域名配置两条 A 记录（公网 IP + 127.0.0.1）、TTL=0，
让校验查询与连接查询拿到不同结果；服务端代码对同一 URL 调用了两次解析。
```

## 变体与关联

- 变体：校验用 `gethostbyname`、请求用 `curl`/Go `http.Client`/Java `URL`，解析器与缓存策略不同；有的客户端会缓存 DNS，需要更短 TTL 或多次尝试。
- 变体：目标先 302 重定向到内网，属于重定向绕过而非重绑定；两者可组合。
- 变体：IP 表示变形（十进制、八进制、IPv6 映射、`0.0.0.0`、`127.1`）可绕过简单字符串黑名单，但对“解析后校验 IP”的实现无效，需用重绑定。
- 变体：云元数据 `169.254.169.254` 也可作为重绑定目标（若校验只拒绝 RFC1918/loopback 而漏掉链路本地，则甚至不需要重绑定）。
- 关联：[[web-generic-ssrf-ip-notation-blacklist-bypass]]（IP 变形与重绑定变体）、[[web-generic-ssrf-redirect-chain-meta-refresh-error-body]]（重定向链绕过）、[[cloud-metadata]]（云元数据目标）。

## 检测与防御

- 修复：在解析阶段得到 IP 后，把该 IP 固定用于后续连接（自定义 DNS resolver/连接钩子），禁止连接时再次解析；或使用出站代理统一做域名/IP 校验。
- 修复：连接建立后校验实际对端 IP（`getpeername`），拒绝私网/回环/链路本地/保留地址；禁用或逐跳校验重定向。
- 加固：出站默认拒绝，仅允许白名单域名/IP 与端口；对内部服务加认证，不依赖“仅本机可达”作为安全边界。
- 检测：同一域名在短时间内被多次解析且结果变化；SSRF 请求的 Host 解析到私网但校验日志记录的是公网；注册/触发接口高频重试；内部服务出现来自本机 IP 的异常请求。
