---
id: upload-api-fileurl-ssrf-file-read
title: 远程文件上传接口 fileUrl 支持 file:// 实现 SSRF 任意文件读取
type: scenario
domain: web
path: web/generic/ssrf
technique: ssrf-file-read
tags:
- ssrf
- file-read
- file-upload
- api
severity: high
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
url: /docs/web/generic/ssrf/upload-api-fileurl-ssrf-file-read/
draft: false
kb_aliases:
- 远程文件上传接口任意文件读取
- fileUrl SSRF 文件读取
---

## 一句话结论

应用的"上传远程文件"接口允许通过 `fileUrl` 参数指定 `file:///etc/passwd` 等本地路径，服务端会抓取该地址内容并作为文件上传到对象存储，访问返回的文件 URL 即可读取任意本地文件内容。

## 原理

接口设计意图是让服务端从远程 URL 拉取文件再转存。实现上未限制 URL 的协议与目标，直接用抓取客户端请求该地址，`file://` 协议因此被透传到本地文件系统读取。读取到的字节流被当作普通图片上传到 MinIO 等对象存储并返回公网可访问的 URL，等于把任意文件内容"搬"到了攻击者可直接下载的位置，形成可稳定回读的任意文件读取原语。

## 触发条件

- 存在公开暴露的 API 文档（如 api-doc/swagger），且含"上传远程文件"类接口；
- 接口接受 `fileUrl`（远程地址）参数且未校验协议白名单；
- 服务端有网络出口执行抓取，且抓取内容被转存并返回可访问 URL。

## 利用步骤

1. 翻 JS 发现带 api 关键字的路径，扫描其中 api-doc/接口文档并导入 Apifox 等工具；
2. 找到远程文件上传接口，其参数为 `fileUrl`、`path`、`pathType`；
3. 发起请求，设置 `fileUrl=file:///etc/passwd`；
4. 响应返回 `url` 字段（对象存储上的文件地址，contentType 为 text/plain）；
5. 访问该 URL 即得到 `/etc/passwd` 内容；重复操作可读取任意文件。

## PoC

```
POST /uploadWebFileToPublic?fileUrl=file:///etc/passwd&path=&pathType=
# 响应: {"resultStatus":true,"result":{"url":"https://.../base/upload/pub/<id>.jpg",...}}
# GET 该 url -> root:x:0:0:root:/root:/bin/bash ...
```

## 变体与关联

- 同一接口还支持 `http://` 远程地址，可用于内网探测与云元数据访问（元数据可达时是完整 SSRF 原语）；
- 与传统 LFI 相比，该变体把读取结果转存到对象存储，绕开了"响应必须回显文件"的限制，非文本内容也可回读；
- 该原语可作为后续凭据收集链（读配置文件、数据库数据文件）的入口。

## 检测与防御

- 对远程抓取类接口做协议白名单（仅 http/https）并禁止内网/file 协议目标；
- 上传代理服务器出口访问控制，阻断 file:// 与内网网段；
- API 文档不应暴露公网；对对象存储转存文件做内容审计。
