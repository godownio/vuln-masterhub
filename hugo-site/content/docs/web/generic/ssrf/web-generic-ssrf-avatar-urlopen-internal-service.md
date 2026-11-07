---
id: web-generic-ssrf-avatar-urlopen-internal-service
title: 远程头像 URL 抓取未校验内网地址，SSRF 读取仅内网暴露的服务
type: scenario
domain: web
path: web/generic/ssrf
technique: ssrf-urlopen-no-internal-check
tags:
- web
- ssrf
- python
- urlopen
- internal-service
- avatar
- response-reflection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:29:46+08:00'
  notes: 已对照原文与图04/08/09核对：fetch_remote_avatar_info 仅校验 scheme 与 hostname 非空即 urlopen，并回显 content_snippet/status/content_type；图09 证实 http://127.0.0.1:80/shell.php?cmd=... 回显 flag。核对时删去卡中“判断写成 if not hostname or not _host_is_public”这一截图未支持的具体表达式，改为按图04 表述为抓取函数未调用 _host_is_public。原文未涉及版本区间。PoC 未在本机执行。
url: /docs/web/generic/ssrf/web-generic-ssrf-avatar-urlopen-internal-service/
draft: false
kb_aliases:
- 头像 URL SSRF
- urlopen SSRF
- 远程信息抓取 SSRF
- 内网服务读取
- SSRF 回显
---

## 一句话结论

应用提供“远程头像/远程 URL 抓取信息”功能并直接 `urllib.request.urlopen(url)`，即使代码里定义了内网地址校验函数但没有在抓取路径调用，攻击者传入 `http://127.0.0.1:<port>/...` 即可让服务器访问仅内网可达的服务，并把响应片段回显到页面。

## 原理

- 抓取函数只校验 `scheme in {http, https}` 与 hostname 非空；代码里虽然定义了 `_host_is_public`，但 `fetch_remote_avatar_info` 的抓取路径中并未调用它（图04 可见函数体内无该校验），随后直接 `urlopen`。
- 服务端发起请求，源地址是内网，能访问 127.0.0.1、容器网段、云元数据等外部攻击者不可达的目标。
- 响应中的 `content_snippet`、`status`、`content_type` 被返回并渲染，使 SSRF 从盲打升级为可回显读取。
- 之所以成立：URL 是攻击者可控输入，而“是否内网”这一安全判断没有与实际请求路径绑定（定义了但未调用，等价于没有防护）。

## 触发条件

- 存在接收 URL 并抓取的功能（头像、图片代理、网页预览、Webhook 测试等）；
- 抓取使用 `urlopen`/`requests` 等客户端且未禁用内网目标；
- 响应内容或状态被返回给用户（回显型 SSRF）；
- 内网目标无需认证或攻击者已知凭据/路径。

## 利用步骤

1. 找到接受 URL 的参数（如头像远程 URL、`/about` 的远程信息抓取）。
2. 先用 `http://127.0.0.1:<port>/` 探测本机端口与服务指纹。
3. 访问内网管理接口、仅内网暴露的应用路径或云元数据地址。
4. 从页面回显的 `content_snippet`/长度/状态码提取数据；若目标返回二进制或大响应，结合状态码、长度做盲测。
5. 与文件写入类漏洞组合：先通过 Zip Slip 等把 webshell 写到内网 Web 服务，再用 SSRF 请求该 webshell 执行命令。

## PoC

```http
POST /profile HTTP/1.1
Host: exposed-app
Content-Type: application/x-www-form-urlencoded

avatar_url=http%3A%2F%2F127.0.0.1%3A80%2Fshell.php%3Fcmd%3Dsystem%28%22cat%20%2Ftmp%2Fflag%22%29%3B
```

回显示例：

```text
远程信息: type=text/html; charset=UTF-8 len=16
len=b'flag{test_flag}\n'
```

最小复现逻辑：

```python
import urllib.request
url = request.form["avatar_url"]          # 攻击者可控
req = urllib.request.Request(url, headers={"User-Agent": "app/1.0"})
with urllib.request.urlopen(req, timeout=3) as resp:
    return {"snippet": resp.read(), "status": resp.status}   # 直接回显
```

## 变体与关联

- 变体：重定向到内网（先返回 302）、DNS rebinding、十进制/八进制 IP、IPv6 映射、`localhost` 大小写、URL 解析差异；盲 SSRF 用时间差/状态码判断。
- 关联：[[web-generic-ssrf-ip-notation-blacklist-bypass]]、[[web-generic-ssrf-url-parser-differential-allowlist-bypass]]（有校验时的绕过）；[[web-generic-file-upload-zip-slip-webshell-write]]（本链中先写 webshell 再用 SSRF 触发）。
- 影响边界：需要抓取功能与回显；若出站被网络策略限制、或目标需认证，读取范围受限。文章未展开 `_host_is_public` 的具体绕过，实际是抓取函数未调用校验。

## 检测与防御

- 检测：抓取目标为 `127.0.0.1`、私网段、`169.254.169.254`、容器网段或非常规端口；同一账号短时间内请求多个内网地址；响应长度/状态异常。
- 防御：解析 URL 后对 DNS 结果做私网/回环/链路本地/保留地址校验，并在连接时校验实际 IP（防 DNS rebinding）；只允许 http/https 与白名单域名；禁用或限制重定向；出站防火墙禁止访问内网与元数据；不要回显原始响应体，仅返回必要的状态。
