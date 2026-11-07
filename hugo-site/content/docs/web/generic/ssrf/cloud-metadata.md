---
id: web-generic-ssrf-cloud-metadata
title: SSRF 读取云元数据获取临时凭证
type: scenario
domain: web
path: web/generic/ssrf
technique: ssrf
tags:
- ssrf
- cloud
- metadata
- credential
cve: []
severity: high
confidence: high
status: draft
created: '2026-11-04'
updated: '2026-11-04'
url: /docs/web/generic/ssrf/cloud-metadata/
draft: false
kb_aliases:
- 云元数据 SSRF
- 169.254.169.254
---

## 一句话结论

当服务端允许请求用户提供的 URL 且出网策略不严时，把目标指向云元数据地址即可读取实例角色临时凭证，进而接管云资源。

## 原理

多数云厂商在链路本地地址提供元数据服务（常见 `169.254.169.254`）。该服务通常无需认证，但只允许实例内部访问。SSRF 让服务器代替攻击者访问该地址，绕过网络边界。

## 触发条件

- 存在 URL 抓取、图片代理、Webhook、文件导入等 SSRF 入口；
- 服务端可访问元数据地址；
- 元数据服务未强制 IMDSv2/Token 或 Token 可被绕过。

## 利用步骤

1. 确认 SSRF 入口与回显方式（直接回显/盲打/时间侧信道）；
2. 读取元数据根路径，枚举实例角色；
3. 获取角色临时凭证；
4. 使用凭证调用云 API，评估权限范围。

## PoC

```text
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
```

## 变体与关联

- 变体：GCP `metadata.google.internal`、Azure `169.254.169.254/metadata`；
- 关联：SSRF 绕过（DNS rebinding、重定向、IP 变形）。

## 检测与防御

- 检测：出站请求中的链路本地地址与元数据路径；
- 防御：禁用不必要的 URL 抓取、出站白名单、强制 IMDSv2、最小权限角色。
