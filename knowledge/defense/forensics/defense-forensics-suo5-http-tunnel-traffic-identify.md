---
id: defense-forensics-suo5-http-tunnel-traffic-identify
title: Suo5 HTTP 隧道流量识别：/connect 分块 POST、UA 口令与内存马注入特征
type: scenario
domain: defense
path: defense/forensics
technique: suo5-http-tunnel-traffic-identify
aliases:
- Suo5 流量识别
- Suo5 内存马隧道
- Suo5 /connect
- Suo5 UA 口令
- HTTP 隧道流量分析
tags:
- forensics
- traffic-analysis
- suo5
- tunnel
- memshell
- http
- user-agent
- internal-network
cve: []
severity: medium
confidence: medium
status: draft
created: '2026-11-07'
updated: '2026-11-07'
---

## 一句话结论

被注入 Suo5 内存马后，内网代理流量表现为对同一 Web 路径（文中为 `/connect`）反复发送 `Transfer-Encoding: chunked` 的 POST，请求头 User-Agent 会被用作连接口令并随请求变化；在控制通道（哥斯拉 EKP 马）解密后可看到 `evalClassName`、`methodName`、`urlPattern=/connect`、`userAgent` 等注入字段，结合端口扫描回显即可还原“内存马 + HTTP 隧道 + 内网扫描”的完整后利用链。

## 原理

- Suo5 是一个把 TCP 流量封装进 HTTP 请求/响应的隧道工具，客户端与目标上的 Suo5 服务端（可以是独立进程，也可以是注入 Tomcat 的内存马）通过固定的 HTTP 端点交换分块数据；因此流量看起来像普通的 chunked POST，而不是传统反弹 Shell 的长连接。
- 服务端需要认证/会话标识，Suo5 常用请求头（如 `User-Agent`）作为密码或标识；文中观察到两次 `/connect` 请求的 UA 不同、其中一个成功（返回 200、另一个 404），并据此判断代理在检查 UA。对 UA 原文做 MD5 得到 `e3c77fd790af8d25fe271cd275eb405e`，与题目答案一致，说明 UA 字符串本身就是口令。
- 内存马注入通常通过另一个 WebShell 通道完成：文中哥斯拉 EKP 马的解密流量中出现 `evalClassName`（形如 `org.apache.coyote.introspect.*`、`org.apache.coyote.util.*`）、`methodName`（`inject`/`run`）、`urlPattern=/connect`、`userAgent` 等字段，说明攻击者先注入 Suo5 代理类并注册 `/connect` 路由，再通过该路由建立隧道。
- 隧道建立后，攻击者可在本地用代理客户端把内网端口映射出来，再运行 fscan 等工具扫内网；文中解密出的扫描请求包含 `127.0.0.1` 和端口列表，回显按行返回 `<ip> <port> <status>`（0 关闭、1 开放），开放端口为 222 和 8081。
- 为什么难以直接发现：所有隧道流量都复用一个合法的 JSP/Web 路径，使用 chunked 编码，HTTP 状态码可能正常也可能是 404；没有明显的 `cmd.exe`/`/bin/bash` 命令行，也没有持续的单条 TCP 长连接，传统基于命令关键字或端口黑名单的规则容易漏报。

## 触发条件

- 目标 Web 应用已被注入 Suo5 内存马（或部署了 Suo5 服务端），且攻击者能访问对应 HTTP 端点。
- 隧道流量经过可抓包的链路，或已有 HTTP 代理/访问日志；若全程 TLS 且无解密手段，只能看到加密的 POST 序列。
- 需要能解密控制通道（如哥斯拉 EKP 马）才能看到注入字段；仅有隧道流量时只能基于路径、chunked、UA 变化做弱特征判断。
- 仅用于授权取证、应急响应和恶意流量分析；不要在未授权目标上复现隧道。

## 利用步骤

1. 在 HTTP 流量中筛选对同一 `.jsp`/`.jspx`/API 路径的连续 POST，重点看 `Transfer-Encoding: chunked`、`Content-Type: application/plain` 或无明显 Content-Type、请求体为长 Base64/二进制块。
2. 统计请求的 User-Agent：同一路径出现多个不同 UA（或 UA 带版本号递增，如 `Chrome/109`、`Chrome/109.1.2.3`）是 Suo5 类隧道的强特征；记录每个 UA 及其响应码。
3. 若同时捕获了控制通道（如哥斯拉 EKP 马），按对应密钥解密请求，查找 `evalClassName`、`methodName`、`urlPattern`、`userAgent` 等键；`urlPattern=/connect` 直接给出隧道端点。
4. 用 `md5(UA)` 验证是否为口令（文中 `md5("Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) ... Chrome/109.1.2.3") = e3c77fd790af8d25fe271cd275eb405e`）。
5. 解密隧道内的扫描/代理请求，还原目标 IP、端口、状态（0/1），结合时间线判断内网横向范围。
6. 在目标主机上检查 Tomcat 进程内的动态类/Filter/Valve，确认 Suo5 内存马的注册路径，并排查注入入口（如哥斯拉马、反序列化、文件上传）。

## PoC

流量筛选（Wireshark/tshark）：

```text
http.request.method == "POST" && http.request.uri contains "/connect"
```

UA 口令校验：

```python
import hashlib
ua = ("Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) "
      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.1.2.3")
print(hashlib.md5(ua.encode()).hexdigest())
# e3c77fd790af8d25fe271cd275eb405e（与文中答案一致）
```

说明：PoC 为流量筛选与口令校验命令，未在本地复现完整 Suo5 隧道；UA 是否为口令取决于服务端配置。

## 变体与关联

- 变体：Suo5 端点可伪装成任意路径（`/api`、`/static`、`/favicon.ico`），需结合 chunked + UA 变化 + 高频 POST 综合判断。
- 变体：用其他 HTTP 隧道工具（如 Neo-reGeorg、reGeorg、Chisel 的 HTTP 模式、frp 的 HTTP 代理）时，路径与头部特征不同，但“复用合法 Web 路径 + 分块传输 + 认证头”的思路相同。
- 关联：[[web-java-deserialization-finereport-channel-frchannel-memshell-suo5]]（Suo5 的注入与使用场景）、[[defense-forensics-godzilla-ekp-jsp-traffic-decode]]（同场景中用于注入 Suo5 的 EKP 马流量解密）、[[defense-detection-tomcat-memshell-scanner-arthas]]（内存马检测与清除）。
- 边界：TLS 未解密、隧道使用随机路径/随机 UA、服务端不返回可区分的状态码时，仅凭流量很难确认；需要主机侧内存马排查配合。

## 检测与防御

- 流量侧：对同一路径的高频 chunked POST、UA 频繁变化、请求/响应体高熵、无明显业务语义的 `/connect` 类端点建立检测规则；结合 JA3/JA4、请求时序和字节量做行为基线。
- 主机侧：用 arthas/java-memshell-scanner 枚举动态注册的 Servlet/Filter/Valve；检查 Tomcat 进程内 `urlPattern` 与业务无关的类；关注 WebShell 上传与反序列化入口。
- 日志：Web 访问日志中同一路径的大量 POST、不同 UA、异常响应码；结合上游 WAF 的 chunked 请求告警。
- 加固：及时修复上传/反序列化漏洞；限制出站与内网访问；对 Tomcat 使用最小权限；部署内存马检测与 WebShell 流量检测。
- 响应：隔离主机、保存 pcap 与内存证据；删除内存马并重启容器；排查攻击者通过隧道访问的内网资产并轮换凭据。
