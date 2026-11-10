---
id: web-generic-auth-nginx-exact-location-deny-trim-bypass
title: Nginx 精确 location deny 绕过：/admin/ 后插 \xA0 被 Node.js trim 后命中 /admin
type: scenario
domain: web
path: web/generic/auth
technique: nginx-exact-location-deny-backend-trim-bypass
aliases:
- nginx location = 绕过
- /admin/\xA0 绕过
- Node.js trim 路径绕过
- Django/Flask 路径规范化绕过
- 解析器差异 deny 绕过
- exact match deny bypass
- nginx 403 绕过
tags:
- web
- nginx
- auth
- access-control
- bypass
- path-normalization
- nodejs
- express
- django
- flask
- unicode
- 403
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: 原文 Nginx 版本/后端绕过字符对照表：Node.js 后端——Nginx 1.22.0/1.21.6 用 \xA0，Nginx 1.20.2/1.18.0/1.16.1 用 \xA0、\x09、\x0C；Flask/Python 后端——Nginx 1.22.0/1.21.6 用 \x85、\xA0，Nginx 1.20.2/1.18.0/1.16.1 另含 \x1F、\x1E、\x1D、\x1C、\x0C、\x0B。原文演示环境为 nginx/1.27.0；Demo 后端为 Node.js 与 Django 4.2.11，对照表标注为 Flask。
verification:
  verified_by: verifier-V303
  verified_at: '2026-11-08T12:03:19+08:00'
  notes: 已对照原文与图04-17核对：location = /admin 与 = /admin/ 403、Node.js trim 去 \xA0 保留 \x85、原始 0xA0 请求 200 ADMIN/X-Powered-By Express、两版绕过字符表、Django 4.2.11 DisallowedHost 与正则修复 403 均一致；Python 部分原文仅到 DisallowedHost，卡片已注明 ALLOWED_HOSTS 前提。dedup likely_duplicate(regex deny 卡,0.911) 经核对属 append_scenario：精确 location+Node.js 场景未被旧卡覆盖，且纠正旧卡『精确匹配则绕过失败』的边界结论，保留本卡；旧卡边界句已过时，建议后续修订。未复现
---

## 一句话结论

Nginx 用 `location = /admin { deny all; }` 和 `location = /admin/ { deny all; }` 做精确路径封禁时，请求 `/admin/` 后跟一个原始 `0xA0` 字节（不是 `%A0` 编码）不会命中这两个 location，而是落到 `location /` 被 `proxy_pass` 到后端；Node.js/Express 在路由前会对路径做 `trim()` 去掉 `\xA0`，于是请求最终命中后端 `/admin` 路由返回 200 ADMIN。Python 栈同理：`strip()` 会删除 `\x85`/`\xA0`，`/admin/\x85` 可绕过 Nginx 的精确 deny。

## 原理

- **Nginx 的 location 匹配是字符串/前缀匹配**：`location = /admin` 与 `location = /admin/` 是精确匹配，只有 URI 完全等于这两个字符串时才命中。`/admin/` 后多一个字节（`/admin/\xA0`）既不等于 `/admin` 也不等于 `/admin/`，因此不会被 deny；请求进入 `location /` 的 `proxy_pass`。
- **后端框架会再次解析路径**：请求被原样转发给 Node/Express 或 Python/Django/Flask 后，后端框架对路径做自己的解码/规范化。原文实测 Node.js 的 `trim()` 会删除 `\xA0`（U+00A0 NBSP）但不删除 `\x85`；Python 的 `strip()` 会同时删除 `\xA0` 与 `\x85`（U+0085 NEL）。因此带这些字节的路径在后端路由看来就是 `/admin`。
- **为什么这是解析差异**：Nginx 只按原始 URI 做 location 匹配，后端按 Unicode 字符串做 trim/路由；两者对同一个字节的处理不一致，导致“Nginx 认为不是 /admin、后端认为是 /admin”。这不是 Nginx 的 CVE，而是配置假设（精确匹配能保护路径）与后端解析行为冲突。
- **字节必须原样发送**：`%A0` 是 URL 编码后的文本，Nginx 可能先解码或把它当普通字符处理，无法稳定复现；需要像 Burp Repeater 的 Raw/Hex 视图那样在请求行里写入原始字节 `0xA0` 或 `0x85`。原文的 Hex 视图显示请求行为 `/admin/` + 单个字节。
- **版本差异**：原文对照表显示可用字节随 Nginx 版本变化：Node 后端在 1.22.0/1.21.6 用 `\xA0`，1.20.2/1.18.0/1.16.1 还可用 `\x09`、`\x0C`；Flask/Python 后端在 1.22.0/1.21.6 用 `\x85`/`\xA0`，1.20.2 及更早还可用 `\x1F`、`\x1E`、`\x1D`、`\x1C`、`\x0C`、`\x0B`。升级/更换 Nginx 或后端后需要重新枚举。
- **修复为什么用正则**：`location ~* ^/admin { deny all; }` 对任何以 `/admin` 开头的 URI 都匹配，因此 `/admin/\xA0` 也会被拦；代价是 `/admin_test` 等正常前缀路径也会被 403，属于有损修复。

## 触发条件

- Nginx 作为反向代理/网关，用 `location = /admin`、`location = /admin/` 加 `deny all`（或 `return 403`）保护敏感路径。
- 后端为 Node.js/Express（Node 会 trim `\xA0`）或 Python/Django/Flask/Werkzeug（会 strip `\x85`/`\xA0` 等），且受保护路由可被规范化后的路径命中。
- 攻击者能发送包含原始高位/控制字节的 HTTP 请求（Burp Raw/Hex、socket、脚本都可以；浏览器地址栏通常不行）。
- Nginx 版本与后端组合对至少一个候选字节存在解析差异；需要先确认基线 403。

## 利用步骤

1. 基线：访问 `http://target/admin` 与 `/admin/`，确认返回 403（Nginx 页面），记录 `Server` 头（本题 nginx/1.27.0）。
2. 确认后端类型：直接访问 Nginx 前面的其它路径，观察 `X-Powered-By: Express`、Django 错误页或 Flask 响应头；也可从报错/静态资源推断。
3. 在 Burp Repeater 中切换到 Hex 或 Raw 视图，把请求行改成 `/admin/` 后跟原始 `0xA0`（Node）或 `0x85`（Python），不要用 `%A0`/`%85` 文本。
4. 发送并比较：成功时 Nginx 不再 403，后端返回 200 与 ADMIN/受保护页面；本题 Node 端返回 body `ADMIN`，`X-Powered-By: Express`。
5. 若失败，按对照表枚举其它候选字节（`\x09`、`\x0C`、`\x1F`、`\x1E`、`\x1D`、`\x1C`、`\x0B`），并尝试把字节放在路径其它位置。
6. 对同站其它精确 deny 的路径（`/api`、`/flag`、`/actuator`）重复测试；记录成功报文与 Hex 作为证据。

## PoC

Burp Raw 视图中 `\xA0` 是单个原始字节（不是四个字符）：

```http
GET /admin/  HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
Connection: close
```

十六进制视图中的请求行应类似：

```text
47 45 54 20 2f 61 64 6d 69 6e 2f a0 20 48 54 54 50 2f 31 2e 31
G  E  T     /  a  d  m  i  n  /  \xA0  H  T  T  P  /  1  .  1
```

Python socket 枚举候选字节（Node 用 `\xA0`，Python 后端可加 `\x85`）：

```python
import socket

HOST, PORT = "target", 80
candidates = [0xA0, 0x85, 0x09, 0x0C, 0x1F, 0x1E, 0x1D, 0x1C, 0x0B]

for b in candidates:
    req = (b"GET /admin/" + bytes([b]) + b" HTTP/1.1\r\n"
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

本题 Node 后端成功响应示例：

```http
HTTP/1.1 200 OK
Server: nginx/1.27.0
Content-Type: text/html; charset=utf-8
Content-Length: 5
X-Powered-By: Express

ADMIN
```

## 变体与关联

- **Python 栈**：Django/Flask/Werkzeug 在路由前对路径做 Unicode strip，`/admin/\x85` 或 `/admin/\xA0` 可命中 `/admin`；Django 还会做 `ALLOWED_HOSTS` 校验，必要时同步构造 Host。
- **精确匹配的其它写法**：`location = /secret`、`location = /secret/`、`location /admin`（前缀匹配但无尾斜杠）都可能被同一字节绕过；前缀匹配时字节放末尾即可。
- **修复绕过**：`location ~* ^/admin` 会连带拦截 `/admin_test`，若业务依赖该前缀需改为后端鉴权或更精确的正则（如 `^/admin(/|$)`)；但正则仍可能被更复杂的编码差异绕过，最终应在后端做统一鉴权。
- **关联**：[[web-generic-auth-nginx-regex-deny-unicode-byte-bypass]]（正则 location + Flask 的同类字节差异；本卡补充精确 `location =` 与 Node.js `\xA0` 场景，并说明精确匹配并不安全）、[[web-generic-file-inclusion-nginx-alias-off-by-slash-traversal]]（另一种 Nginx location/路径拼接问题）。

## 检测与防御

- **防御**：不要用 Nginx `location =`/正则 + `deny` 作为唯一访问控制；敏感路径必须由后端做统一、规范化后的鉴权（对象级/角色级），Nginx 只做转发。
- **规范化**：代理层对 URI 做严格字符集校验，拒绝 `0x00–0x1F`、`0x7F`、`0x80–0x9F` 等控制/高位字节；确保 Nginx 与后端使用一致的路径规范化规则，并在规范化后的路径上匹配。
- **配置**：若必须在 Nginx 拦截，使用覆盖所有前缀的正则（接受 `/admin_test` 误伤）或同时在前端/后端做双重校验；把静态资源与动态接口分域/分端口，避免用路径承载安全边界。
- **检测**：URI 中出现 `0xA0`、`0x85` 或控制字节；同一路径 403 与 200 状态切换；请求行含不可见字符、脚本化字节枚举；Nginx access log 中的异常转义/乱码路径。
- **响应**：确认绕过成功后检查该路径暴露的数据/操作，修复 location 规则并在后端补鉴权，审计同时间段异常请求。
