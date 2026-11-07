---
id: web-generic-auth-nginx-regex-deny-unicode-byte-bypass
title: Nginx 正则 deny 绕过：/secret 后插入原始 0x85/0xA0 字节，Nginx 不匹配而 Flask 规范化到 /secret
type: scenario
domain: web
path: web/generic/auth
technique: nginx-regex-deny-unicode-byte-path-bypass
tags:
- web
- auth
- nginx
- flask
- access-control
- bypass
- path-normalization
- unicode
- 403
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: Nginx 1.22.0/1.21.6：\x85、\xA0；Nginx 1.20.2/1.18.0/1.16.1：\x85、\xA0、\x1F、\x1E、\x1D、\x1C、\x0C、\x0B（原文 Nginx 版本/Flask 绕过字符对照表；后端 Flask）
verification:
  verified_by: verifier-V248
  verified_at: '2026-11-07T13:18:11+08:00'
  notes: 已对照原文与 6 张图核对：Nginx 正则 location deny /secret、Flask 后端、/secret 后插入原始 0x85 字节、Hex 视图、返回 200 与 LILCTF flag 均与图 1-6 一致；affected_versions 已按原文 Nginx 版本/Flask 绕过字符对照表设置（1.22.0/1.21.6：0x85/0xA0；1.20.2/1.18.0/1.16.1 另含 0x1F/0x1E/0x1D/0x1C/0x0C/0x0B）。未验证点：仅 CTF 环境，未在真实目标复现；不同后端/版本需重新枚举字节。
url: /docs/web/generic/auth/web-generic-auth-nginx-regex-deny-unicode-byte-bypass/
draft: false
kb_aliases:
- Nginx 路径绕过
- Nginx deny 绕过
- 0x85 绕过
- 0xA0 绕过
- Unicode 字节路径绕过
- Nginx 与 Flask 路径解析差异
- 正则 location 绕过
---

## 一句话结论

当 Nginx 用 `location ~* ^/secret/?$`、`location ~* ^/secret/` 这类正则 location 做 `deny all` 时，在 `/secret` 后直接插入一个原始高位/控制字节（如 `0x85`、`0xA0`，旧版本还包括 `0x1F/0x1E/0x1D/0x1C/0x0C/0x0B`）会让正则不匹配、请求落入 `location /` 被代理到后端；而 Flask/Werkzeug 等 Python 栈在路由前会忽略/剥离该字节，最终仍命中 `/secret` 路由，返回本应被 403 拦截的内容。

## 原理

- **两套路径语义**：Nginx 的 `location ~*` 正则匹配与后端的路由匹配不是同一套规范化流程。Nginx 在匹配 location 前会做常规 URI 规范化（百分号解码、`.`/`..` 折叠、连续斜杠合并等），但对某些高位/控制字节并不等同于后端框架的处理；正则 `^/secret/?$` 看到插入的字节后判定不匹配，请求落到 `location /` 的 `proxy_pass`。
- **后端规范化**：请求被原样转发给 Flask/WSGI 后，Python 路径处理会忽略/剥离这些异常字节（不同服务器/框架行为不同），最终路由到 `/secret`。于是出现“Nginx 认为不是 `/secret`、Flask 认为是 `/secret`”的差异，正是绕过所需的错位。
- **关键字节**：原文实测 Nginx 1.22.0 / 1.21.6 使用 `\x85`（U+0085 NEXT LINE）和 `\xa0`（U+00A0 NO-BREAK SPACE）；1.20.2 / 1.18.0 / 1.16.1 还可用 `\x1f`、`\x1e`、`\x1d`、`\x1c`、`\x0c`、`\x0b`。可用字节集合随 Nginx 版本和后端实现变化，需要逐个测试。
- **必须是原始字节**：原文强调要发送 `\x85` 这个字节本身，而不是 URL 编码的 `%85`；`%85` 会被 Nginx 先解码或在日志/代理层被转换，可能不再产生同样的差异。发送方式包括 Burp Repeater 的 Raw/Hex 视图、socket、pwntools 等。
- **为什么正则防护失效**：正则 `deny` 是“按原始/规范化后但仍含特殊字节的 URI 做前缀/全串匹配”，而后端鉴权/路由按自己解析出的路径执行；只要两者对某个字节的处理不一致，攻击者就能找到一条 Nginx 不拦、后端却命中的路径。类似的差异也适用于 WAF、反向代理与后端框架之间的路径规范化。
- **边界**：若 Nginx 返回 400/444 直接拒绝异常 URI、或使用 `location = /secret` 精确匹配、或后端也不忽略该字节，则绕过失败；若 Nginx 与后端使用同一套严格规范化并在规范化后统一鉴权，也会失效。

## 触发条件

- 目标使用 Nginx 作为反向代理/网关，并用正则 location（`~`/`~*`）配合 `deny all`/`return 403` 保护某个路径。
- 后端为 Flask/Werkzeug 或其他会忽略/剥离异常字节的框架，且受保护路由可被规范化后的路径命中。
- 攻击者能发送包含原始高位/控制字节的请求（不是浏览器地址栏或普通 `%85` 编码）。
- Nginx 版本与后端组合对至少一个候选字节存在差异；需先基线确认 403，再逐字节测试。

## 利用步骤

1. 基线：直接请求 `GET /secret` 或 `GET /secret/`，确认返回 403/401，记录响应头（是否暴露 Nginx 版本）与 body。
2. 构造候选字节列表：优先 `0x85`、`0xA0`；旧版 Nginx 再加 `0x1F`、`0x1E`、`0x1D`、`0x1C`、`0x0C`、`0x0B`。
3. 在 Burp Repeater 中切换到 Raw 或 Hex 视图，在 `/secret` 与空格之间插入原始字节（例如字节序列 `2f 73 65 63 72 65 74 85 20`），不要使用 `%85`。
4. 发送请求，比较状态码与响应体；成功时后端返回 200 与受保护内容。
5. 对同一站点其他被正则 deny 的路径重复测试（如 `/admin`、`/api`、`/flag`），并对不同字节组合做小字典枚举。
6. 记录成功的原始报文（含十六进制视图）作为证据；若目标有 WAF/日志，注意请求会被记录为异常 URI。

## PoC

Burp Raw 视图（`\x85` 是实际字节，不是四个字符）：

```http
GET /secret\x85 HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
Accept: */*
Connection: close
```

十六进制视图中的请求行应为：

```text
47 45 54 20 2f 73 65 63 72 65 74 85 20 48 54 54 50 2f 31 2e 31
G  E  T     /  s  e  c  r  e  t  \x85  H  T  T  P  /  1  .  1
```

Python socket 枚举候选字节：

```python
import socket

HOST, PORT = "target", 80
candidates = [0x85, 0xA0, 0x1F, 0x1E, 0x1D, 0x1C, 0x0C, 0x0B]

for b in candidates:
    req = (b"GET /secret" + bytes([b]) + b" HTTP/1.1\r\n"
           b"Host: " + HOST.encode() + b"\r\n"
           b"Connection: close\r\n\r\n")
    s = socket.create_connection((HOST, PORT), timeout=5)
    s.sendall(req)
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    status = data.split(b"\r\n", 1)[0]
    print(f"0x{b:02x}: {status!r}")
```

也可用 pwntools：

```python
from pwn import remote
r = remote("target", 80)
r.send(b"GET /secret\x85 HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
print(r.recvall(timeout=5))
```

说明：原文在 Burp 中插入 `0x85` 后请求返回 200，响应体为本应被 Nginx 拦截的 flag；不同 Nginx/后端组合需先枚举字节。PoC 未对真实目标执行。

## 变体与关联

- 变体：把同一字节用在其他被 `deny` 的路径（`/admin`、`/api/secret`）上；也可放在路径中间或末尾，取决于正则锚点与后端规范化。
- 变体：不同 Nginx 版本的可用字节集合不同（原文表格：1.22.0/1.21.6 为 `\x85`、`\xa0`；1.20.2/1.18.0/1.16.1 还包含 `\x1f`、`\x1e`、`\x1d`、`\x1c`、`\x0c`、`\x0b`）；升级/降级 Nginx 后需重新测试。
- 变体：除 Flask 外，其他后端（Django、FastAPI/Starlette、gunicorn/uwsgi）对异常字节的规范化行为不同；可把同一思路扩展到任何“代理/WAF 路径判断 vs 后端路由”的差异。
- 变体：与百分号编码、双重编码、Unicode 规范化（全角/兼容字符）、分号/斜杠折叠组合；某些组合可能被前端代理先解码而失效。
- 关联：[[web-generic-auth-403-resource-suffix-path-dictionary-bypass]]（静态资源后缀/路径穿越字典绕过 403）、[[web-generic-auth-interceptor-login-prefix-dotdot-bypass]]（前缀判断 + 路径规范化绕过）、[[web-generic-crlf-nginx-uri-location-set-cookie]]（Nginx URI/location 处理相关）。
- 边界：Nginx 对异常 URI 直接返回 400/444、使用精确 `location =`、后端同样拒绝异常字节、或代理层做了严格 URI 白名单时，本手法失败。

## 检测与防御

- 防御：不要用正则 location + `deny` 作为唯一访问控制；对敏感路径使用 `location = /secret` 精确匹配，或在后端统一做鉴权（对象级/角色级），代理层只做转发。
- 防御：对 URI 做严格字符集校验，拒绝高位/控制字节（如 0x00–0x1F、0x7F、0x80–0x9F），并在规范化后的路径上做统一匹配与鉴权；确保 Nginx 与后端使用一致的路径规范化规则。
- 防御：把静态资源/动态接口分域或分端口，避免用“路径前缀/正则”承载安全边界；对 403 后的异常请求做二次校验。
- 检测：URI 中出现 `0x85`、`0xA0` 或控制字节；同一路径先 403 后 200 且长度/内容变化；请求行含不可见字符、Burp/脚本化的字节枚举行为；Nginx access log 中异常转义或乱码路径。
- 响应：发现绕过成功后，检查该路径是否暴露敏感数据/操作，修复 location 规则并在后端补充鉴权，审计同时间段内的异常请求。
