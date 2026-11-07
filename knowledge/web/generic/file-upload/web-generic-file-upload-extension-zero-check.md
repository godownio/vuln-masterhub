---
id: web-generic-file-upload-extension-zero-check
title: 上传扩展名零校验导致 webshell 落盘
type: scenario
domain: web
path: web/generic/file-upload
technique: unrestricted-file-upload
aliases:
- 任意文件上传
- 扩展名零校验
- webshell 上传
tags:
- web
- file-upload
- webshell
- iis
- aspx
cve: []
severity: critical
confidence: high
status: draft
created: '2026-11-04'
updated: '2026-11-04'
---

## 一句话结论

上传接口直接用用户文件名里的扩展名重命名并原样写盘，没有扩展名白名单、内容校验或落点限制时，攻击者可以上传 `.aspx`/`.jsp`/`.php` 等脚本并直接访问执行。

## 原理

服务端接收到上传文件后，用“时间戳 + 随机数 + 用户自带扩展名”生成新文件名，扩展名完全取自客户端；文件内容按字节流原样落盘，不检查文件头、不扫描危险内容、不校验实际类型。落点又由客户端参数映射到 Web 可访问目录时，上传即变成任意脚本写入。

## 触发条件

- 上传接口可被未授权或低权限用户访问；
- 扩展名取自客户端且无白名单；
- 文件内容不做类型/魔数校验；
- 落点位于 Web 根目录或可被 Web 服务器解析的目录；
- Web 服务器会执行上传目录中的脚本。

## 利用步骤

1. 找到上传入口与参数（目录参数、文件名、内容）；
2. 上传一个带脚本扩展名的测试文件；
3. 确认服务端返回的落盘路径或可预测的命名规则；
4. 访问该路径，确认脚本被解析；
5. 上传 webshell 并建立稳定访问。

## PoC

```http
POST /upload?cmd=upload&dir=default HTTP/1.1
Content-Type: multipart/form-data; boundary=----x

------x
Content-Disposition: form-data; name="file"; filename="shell.aspx"
Content-Type: image/png

<%@ Page Language="C#" %><% Response.Write("ok"); %>
------x--
```

## 变体与关联

- 变体：双扩展名、MIME 绕过、`.htaccess`/`web.config` 覆盖、解析漏洞、竞争上传；
- 关联：身份伪造、默认口令、目录穿越。

## 检测与防御

- 检测：上传目录中的脚本文件、异常扩展名、Web 访问日志中的新脚本路径；
- 防御：扩展名白名单、内容类型/魔数校验、上传目录禁止脚本执行、随机化文件名且不信任客户端路径、上传与 Web 根分离。
