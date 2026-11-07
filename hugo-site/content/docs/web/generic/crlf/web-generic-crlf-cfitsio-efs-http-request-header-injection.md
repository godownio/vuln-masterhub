---
id: web-generic-crlf-cfitsio-efs-http-request-header-injection
title: CFITSIO EFS URL Path 换行注入 HTTP 请求头
type: scenario
domain: web
path: web/generic/crlf
technique: cfitsio-efs-http-header-injection
tags:
- web
- crlf
- http
- cfitsio
- fits
- efs
- header-injection
- ssrf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V27
  verified_at: '2026-11-05T03:04:36+08:00'
  notes: 已对照原文与截图核对：Path 中换行注入、X-EFS-Lab 独立头、X-Pad 吸收 HTTP/1.0 均与原始请求捕获一致。未验证点：未复跑；原文仅证明任意请求头注入，未构造 Host/Authorization 绕过的端到端危害。
url: /docs/web/generic/crlf/web-generic-crlf-cfitsio-efs-http-request-header-injection/
draft: false
kb_aliases:
- CFITSIO CRLF 注入
- EFS HTTP Header 注入
- URL Path 换行
- X-Pad 吸收 HTTP 版本
- fits_open_file 请求头注入
---

## 一句话结论

当完整 EFS 字符串可控且使用 HTTP Driver 时，URL Path 中的换行符没有被拒绝；CFITSIO 用 `snprintf()` 把 Path 拼进请求行后，换行后的内容会被 HTTP 服务端解释为新的请求头，从而注入 `Host`、`Authorization`、`X-Forwarded-For` 等任意头。

## 原理

- HTTP Driver 先把 URL 拆成主机、端口和路径 `fn`，再用 `snprintf()` 拼接 `GET <fn> HTTP/1.0`，之后追加 `User-Agent` 和 `Host`。代码只检查最终字符串长度，没有在进入请求结构前拒绝 `\r`/`\n`。
- 这里发生跨解析器语义错位：第一层 EFS/URL 解析器把换行后的字节视为 Path 的一部分；第二层 HTTP 解析器把相同字节视为行分隔符，于是后续内容成为独立请求头。
- 攻击者通过提前写入 `HTTP/1.1` 结束请求行，再写自定义头，最后用一个占位头（如 `X-Pad:`）吸收 CFITSIO 自动追加的 `HTTP/1.0` 和后续内容，避免破坏请求结构。
- 危害不是简单的“未过滤换行”，而是 URL 字段跨越到 HTTP 协议结构，可改变虚拟主机路由、认证头和来源判断；与 SSRF 组合时可访问原本需要特定 Host/Authorization 的内部接口。

## 触发条件

- 应用把外部可控完整字符串传给 `fits_open_file()`，EFS 开启并使用 HTTP Driver。
- 换行字节能穿过上层参数传递（命令行、HTTP 参数、文件内容等）而不被规范化或拒绝。
- 攻击者能访问一个会解释注入头的服务端（内部虚拟主机、认证网关、日志/缓存等）。
- 实验环境为 CFITSIO 4.6.3；原文未给出明确的受影响版本区间。

## 利用步骤

1. 准备一个能打印原始请求的 TCP 服务，确认 CFITSIO 实际发出的字节。
2. 构造文件名：`http://<host>:<port>/<path> HTTP/1.1\n<Header>: <value>\n<Pad>:`。
3. 确保换行以真实字节传入，而不是字面量 `\n`（例如 shell 的 `$'...'`）。
4. 触发 `fits_open_file()`；CFITSIO 发出被拆分的请求，注入头出现在原始请求中。
5. 将注入头用于目标场景：改 `Host` 访问内部虚拟主机、加 `Authorization` 绕过认证、加 `X-Forwarded-For` 绕过 IP 白名单。

## PoC

```bash
# Bash 的 $'...' 会把 \n 转成真实换行字节
docker run --network=host --rm \
  -v "$(pwd)":/workspace cfitsio:4.6.3 \
  fits-sample-opener \
  $'http://127.0.0.1:18081/test HTTP/1.1\nX-EFS-Lab: injected\nX-Pad:'
```

捕获端可看到类似：

```http
GET /test HTTP/1.1
X-EFS-Lab: injected
X-Pad: HTTP/1.0
User-Agent: FITSIO/HEASARC/...
Host: 127.0.0.1:18081
```

`X-EFS-Lab` 成为独立请求头，证明 Path 内容已跨越到 HTTP 协议结构。占位头用于吸收驱动自动追加的版本串，实际后缀可能因驱动的压缩/扩展名重试而变化。

## 变体与关联

- 换行形式：除 `\n` 外可尝试 `\r\n`、编码后的 `%0d%0a`（取决于上层是否解码）。
- 组合 SSRF：先注入 `Host` 或认证头，再访问内网接口，见 [[web-generic-ssrf-cfitsio-efs-http-outfile-response]]。
- 关联：其他把 URL 字段直接拼进请求行/头的客户端也存在同类解析器错位；服务端若信任 `X-Forwarded-For`、`Host` 会导致认证或路由绕过。
- 边界：上层对文件名做严格字符白名单、拒绝控制字符或改用 `fits_open_diskfile()` 时不成立。

## 检测与防御

- **检测（输入）**：文件名/URL 中出现原始 `\r`、`\n`、`%0d`、`%0a`、`%250d` 等控制字符编码；出现 ` HTTP/1.1` 后接自定义头的模式。
- **检测（网络）**：CFITSIO 进程发出包含多个请求行或异常头顺序的 HTTP 请求；User-Agent 为 `FITSIO/HEASARC/...` 但 Host/来源与业务不符。
- **修复**：对传入 `fits_open_file()` 的字符串拒绝所有控制字符，或在业务层只接受规范化后的文件名；本地文件场景改用 `fits_open_diskfile()`。
- **加固**：内部服务不要仅依赖 `Host`、`X-Forwarded-For` 做认证或路由；对解析进程限制出网；在代理/网关层拒绝请求行中的裸换行和重复 Host。
