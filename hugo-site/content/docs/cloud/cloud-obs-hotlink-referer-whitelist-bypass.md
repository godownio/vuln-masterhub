---
id: cloud-obs-hotlink-referer-whitelist-bypass
title: 华为云 OBS 防盗链 Referer 白名单绕过：请求头补白名单 Referer 即可下载受保护对象
type: scenario
domain: cloud
path: cloud
technique: obs-hotlink-referer-header-bypass
tags:
- cloud
- object-storage
- obs
- huawei-cloud
- referer
- referer-bypass
- hotlink
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V634
  verified_at: '2026-11-13T01:08:55+08:00'
  notes: '对照原文 img12-16：防盗链配置白名单 Referer=https://www.example.com 且允许空 Referer 关闭（img12/13）；分享 al1ex.txt 签名 URL 不带 Referer 返回 403 AccessDenied（img14/15）；补 Referer: https://www.example.com 后 200 并返回对象内容 Al1ex（img16）。卡片的黑白名单语义、通配符、协议要求均与原文表格一致。原文未标版本，affected_versions 为空正确。与 CSRF/Referer 校验类既有卡不同场景，dedup 报告 new，保留。'
url: /docs/cloud/cloud-obs-hotlink-referer-whitelist-bypass/
draft: false
kb_aliases:
- OBS 防盗链绕过
- Referer 白名单绕过
- 华为云对象存储盗链
- 签名 URL 防盗链
- Referer 头伪造
---

## 一句话结论

华为云 OBS 的防盗链在四种访问权限（桶/对象读、写、ACL 读写）判定之前先检查 `Referer`，白名单命中才继续；由于 `Referer` 是客户端完全可控的请求头，直接访问签名 URL 得到 403 `AccessDenied` 时，只要在请求里补上白名单中的 `Referer`（如 `Referer: https://www.example.com`）即可正常下载对象。

## 原理

- **防盗链的检查顺序**：OBS 文档明确“判断用户是否有对桶及其内容访问的四种权限之前，需要首先检查是否符合 referer 字段的防盗链规则”，因此一旦绕过 Referer 检查，后续对象读权限（公共读/签名 URL）照常生效。
- **白/黑名单语义**：白名单为空、黑名单非空时允许黑名单外所有站点；白名单非空时只允许白名单站点；两者都空则允许所有站点。支持通配符 `*`、`?`；Referer 含 http/https 时配置也需带协议；还有一个“允许空 Referer”开关——关闭时无 Referer 请求会被拒。
- **为什么可绕过**：服务端只比对 HTTP 头 `Referer` 字符串，而该头由客户端（curl/Burp/脚本）任意设置；攻击者从页面、分享链接或公开配置中拿到白名单域名后，直接伪造即可，不依赖真实来源页面。
- **前提**：对象本身可被访问（公共读或持有签名 URL）；防盗链只是额外一层基于头的访问控制，不是身份认证。
- **边界**：若白名单域名本身无法获知，需要从页面引用、JS、分享链接或报错信息推断；若对象完全私有且无签名 URL，则绕过 Referer 也不能读。

## 触发条件

- 桶开启防盗链且配置了白名单 Referer（或“允许空 Referer”关闭）。
- 攻击者持有可访问对象的 URL（含签名 URL）或对象为公共读。
- 请求工具可自定义 `Referer` 头。

## 利用步骤

1. 访问分享/对象 URL，观察是否返回 403 `AccessDenied`；对比无 Referer 与带任意 Referer 的响应。
2. 从页面源码、分享链接、JS 引用、响应头或公开配置中寻找白名单域名（常见为公司主站/静态站）。
3. 在请求中加 `Referer: <白名单域名>`（协议、路径按配置匹配，必要时试通配符），重新发送。
4. 返回 200 并拿到对象内容；对多个对象复用同一 Referer。
5. 若无白名单线索，可对常见头（Referer/Origin/User-Agent）做简单 fuzzing，观察是否有其它头被用于访问控制。

## PoC

```http
GET /al1ex.txt?AccessKeyId=...&Expires=...&Signature=... HTTP/1.1
Host: al1ex.com.obs.cn-north-4.myhuaweicloud.com
```

```text
# 无 Referer / 非白名单 Referer：HTTP/1.1 403 Forbidden
# <Code>AccessDenied</Code>
```

```http
GET /al1ex.txt?AccessKeyId=...&Expires=...&Signature=... HTTP/1.1
Host: al1ex.com.obs.cn-north-4.myhuaweicloud.com
Referer: https://www.example.com
```

```text
# 白名单 Referer：HTTP/1.1 200 OK，返回对象内容
```

## 变体与关联

- 变体：白名单含通配符时可用 `https://www.example.com.attacker.tld` 之类前缀/后缀匹配（取决于匹配实现）绕过。
- 变体：开启“允许空 Referer”时直接不带 Referer 即可；关闭时需伪造。
- 关联：[[cloud-object-storage-bucket-acl-misconfig]]（对象公共读/读写）、[[cloud-s3-presigned-url-vpce-bypass]]（签名 URL 的网络条件绕过）、[[cloud-obs-bucket-policy-sourceip-xff-spoof-bypass]]（同类“客户端可控条件”绕过）。
- 边界：防盗链不是认证；对象私有且无签名 URL 时该方法无效。

## 检测与防御

- 检测：同一对象 URL 出现 403 后紧跟 200 且 Referer 与来源页面不一致；大量不同来源使用同一白名单 Referer 下载。
- 防御：不要把防盗链当访问控制；敏感对象保持私有并使用短期签名 URL + IP/账号绑定；开启访问日志并监控异常 Referer；对白名单使用精确匹配而非宽泛通配。
