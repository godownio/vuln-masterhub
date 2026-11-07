---
id: web-generic-ssrf-zentao-webhook-file-protocol-arbitrary-read
title: 禅道后台 Webhook 支持 file:// 协议导致服务端任意文件读取
type: scenario
domain: web
path: web/generic/ssrf
technique: zentao-webhook-file-protocol-ssrf-read
tags:
- php
- zentao
- ssrf
- file-protocol
- webhook
- arbitrary-file-read
- admin
cve: []
severity: high
confidence: high
status: verified
affected_versions: 禅道 PMS 21.7.8（原文标题；实验截图环境为开源版 21.7.6）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V37
  verified_at: '2026-11-05T06:00:03+08:00'
  notes: 已对照原文及2张截图核对：Hook 地址 file:///C:/shellcode.txt，触发创建产品/项目/执行后日志结果回显文件内容（111111...）；Linux 变体为原文未验证的合理延伸；截图环境为开源版 21.7.6、原文标题 21.7.8，卡内已注明；未在本机复现。
url: /docs/web/generic/ssrf/web-generic-ssrf-zentao-webhook-file-protocol-arbitrary-read/
draft: false
kb_aliases:
- 禅道 webhook 任意文件读取
- ZenTao webhook SSRF
- file:// webhook
- 禅道通知设置 SSRF
- Hook 地址 file 协议
---

## 一句话结论

禅道后台「通知设置 → Webhook」允许把 Hook 地址填成 `file:///C:/shellcode.txt` 这类本地文件 URL；保存后通过创建产品/项目/执行等动作触发 webhook，服务端的 HTTP 客户端直接读取本地文件并把内容写入 webhook 发送日志，攻击者随后在日志中查看文件内容，形成后台任意文件读取。

## 原理

- **入口**：后台「通知设置 → Webhook」新增 webhook 时，`Hook 地址` 字段由管理员填写，未限制协议为 `http/https`。
- **触发**：创建产品、项目、执行等动作会命中 webhook 的触发条件，禅道调用 webhook 发送逻辑，把请求发往配置的 Hook 地址。
- **协议处理**：底层 HTTP 客户端/文件读取逻辑接受 `file://` URL，于是“发送 webhook”变成“读取本地文件”；读取结果被记录到 webhook 发送日志的「结果」列（原文截图中显示文件内容 `111111...`）。
- **为什么是任意文件读取**：`file://` 后的路径完全由 Hook 地址控制，可指向 Web 配置、数据库配置、密钥、系统文件；不需要目标出网，也不需要额外的文件读取接口。
- **权限前提**：该功能位于后台，需要管理员/有通知设置权限的账号；但禅道历史上存在弱口令、默认口令、越权等入口，实际攻击面取决于目标的管理面暴露与口令强度。
- **版本**：原文标题为禅道 PMS 21.7.8（称最新版仍可利用），截图环境显示开源版 21.7.6；具体修复版本需按官方公告确认。

## 触发条件

- 目标为禅道 PMS 受影响版本（原文 21.7.8；截图 21.7.6）。
- 攻击者能进入后台「通知设置 → Webhook」并新增/编辑 webhook（管理员或具备相应权限）。
- 目标允许 webhook 地址使用 `file://` 协议，且 webhook 发送结果会记录到可查看的日志。
- 攻击者能触发 webhook（创建产品/项目/执行等）。
- 目标进程对目标文件有读权限。

## 利用步骤

1. 登录后台，进入「后台 → 通知设置 → Webhook → 添加 Webhook」。
2. 类型选择可用类型（如钉钉群通知机器人），名称任意；Hook 地址填 `file:///C:/shellcode.txt`（Windows）或 `file:///etc/passwd`（Linux）。
3. 关联产品/执行留空（表示所有动作都触发），保存。
4. 创建产品/项目/执行等动作触发 webhook。
5. 打开 webhook 日志，查看对应记录的「结果」列，文件内容会显示在结果中。
6. 按需读取配置文件、数据库连接串、密钥等；若文件较大，日志可能截断，可分段/换目标文件。

## PoC

原文为 UI 操作，关键配置与结果：

```text
后台 → 通知设置 → Webhook
类型: 钉钉群通知机器人
名称: 任意
Hook 地址: file:///C:/shellcode.txt
禅道域名: http://localhost
关联产品/关联执行: 留空
```

触发后 webhook 日志：

```text
ID   发送时间               Hook地址                 触发动作                 结果
62   2025-11-08 18:01:38   file:///C:/shellcode.txt  admin创建了执行 [#4::123]   success
32   2025-11-08 18:00:44   file:///C:/shellcode.txt  admin创建了项目 [#3::123]   111111111111111111111111111111111111111111111111111111111111111111111111
6    2025-11-08 18:00:43   file:///C:/shellcode.txt  admin创建了产品 [#2::123]   111111111111111111111111111111111111111111111111111111111111111111111111
```

Linux 变体：把 Hook 地址改为 `file:///etc/passwd`，触发后从日志读取。

## 变体与关联

- **其他协议**：若客户端还支持 `php://filter`、`file://` 大小写/编码变体，可读取更多文件或做编码转换；原文只验证了 `file://`。
- **其他触发动作**：任何会触发 webhook 的 CRUD 动作都可以；关联产品/执行留空可扩大触发范围。
- **日志位置**：不同版本 webhook 日志的入口/字段可能不同；核心是“结果”列回显读取内容。
- 关联卡片：[[web-generic-ssrf-wallos-testwebhook-notifications-private-ip]]（另一产品的 webhook SSRF）、[[web-php-file-inclusion]]（如已存在文件读取总览）。

## 检测与防御

- **配置**：webhook 地址只允许 `https://`（或白名单域名），显式拒绝 `file://`、`php://`、`gopher://` 等协议；对 URL 解析后的 scheme/host 做校验。
- **权限**：限制通知设置权限，强制管理员强口令/MFA；不要把后台暴露在公网。
- **日志/检测**：webhook 配置中出现 `file://`、`php://`；webhook 日志「结果」出现系统文件内容/大段非 JSON 文本；后台新增 webhook 后紧接创建产品/项目等触发动作。
- **应急**：检查 webhook 配置与日志，确认读取过哪些文件；轮换配置中泄露的数据库/接口凭据；升级到修复版本并移除恶意 webhook。
