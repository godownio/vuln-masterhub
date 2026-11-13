---
id: defense-detection-ja4h-http-client-fingerprint
title: JA4H HTTP 客户端指纹：方法/版本/Cookie/Referer/头数/语言 + 请求头序哈希 + Cookie 名/值哈希
type: scenario
domain: defense
path: defense/detection
technique: ja4h-http-client-fingerprint
tags:
- defense
- detection
- http
- ja4
- fingerprint
- traffic-analysis
- cookie
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V501
  verified_at: '2026-11-11T02:38:57+08:00'
  notes: 已对照原文与图24-28核对：JA4H_a 六段（方法前两位/版本/c-n/r-n/头数排除Cookie与Referer/Accept-Language前四位）、JA4H_b 请求头名按序哈希、JA4H_c Cookie 字段名排序哈希、JA4H_d 字段名+值排序哈希（无 Cookie 用 12 个 0）均与原文代码与幻灯片一致；示例 ge20cr13enus_974ebe531c03_b66fa821d02c_e97928733c74 取自截图未本地复算。
url: /docs/defense/detection/defense-detection-ja4h-http-client-fingerprint/
draft: false
kb_aliases:
- JA4H 指纹
- HTTP Client 指纹
- JA4H_a JA4H_b JA4H_c JA4H_d
- 请求头顺序指纹
- Cookie 指纹
---

## 一句话结论

JA4H 是 HTTP 客户端指纹：`JA4H_a` 记录请求方法、HTTP 版本、Cookie/Referer 有无、头数量、Accept-Language 前四位；`JA4H_b` 是请求头名称按出现顺序的哈希；`JA4H_c`/`JA4H_d` 分别是排序后 Cookie 字段名、Cookie 字段名+值的哈希。四段组合可在明文或 TLS 解密流量中识别 HTTP 客户端/工具/恶意样本，并检测会话劫持与客户端伪装。

## 原理

- HTTP 请求头由客户端库/框架生成：请求方法、版本、头顺序、默认头集合、Cookie 组织方式、Accept-Language 都带有实现特征；同一工具/样本版本通常稳定。
- **JA4H_a**：
  - 方法前两位：GET=`ge`、PUT=`pu`、POST=`po`，其他方法同样取前两个字母；
  - HTTP 版本：HTTP/2.0=`20`、HTTP/1.1=`11`；
  - Cookie：有 Cookie 为 `c`，无 Cookie 为 `n`；
  - Referer：有 Referer 为 `r`，无 Referer 为 `n`；
  - 头数量：两位十进制，**忽略 Cookie 与 Referer**；
  - Accept-Language：取主语言前四个字符（如 `enus`），不存在则 `0000`。
  例：`ge20cr13enus` = GET + HTTP/2 + 有 Cookie + 有 Referer + 13 个头 + en-US。
- **JA4H_b**：取请求头名称（不含 Cookie/Referer），按报文中出现顺序用 `,` 连接，SHA256 取小写前 12 位。头顺序是客户端实现的重要特征。
- **JA4H_c**：解析 Cookie：列表形式或 `k=v; k2=v2` 字符串形式，取字段名，排序后 SHA256 前 12 位；无 Cookie 时用 12 个 `0` 占位。它反映“这个站点设置了哪些 Cookie 名”。
- **JA4H_d**：在字段名基础上带上 Cookie 值（不含敏感个人信息），排序后 SHA256 前 12 位；无 Cookie 同样用 12 个 `0`。它更接近“用户/会话指纹”，可用于同一用户跨会话关联。
- 与 JA4/JA4S 的分工：JA4 看 TLS 客户端实现，JA4H 看 HTTP 层客户端实现；两者组合可区分“同一 TLS 库但不同 HTTP 框架/工具”。
- 采集前提：JA4H 需要看到 HTTP 明文，因此只能在 TLS 解密后、明文 HTTP 或反向代理日志中使用；TLS 加密且无解密条件时不可用。

## 触发条件

- 能获取 HTTP 请求（明文、TLS 解密后的 pcap、代理/WAF/网关日志）。
- 采集工具支持 JA4H：Wireshark 4.2+ 原生或 ja4.dll 插件（自定义列 `ja4.ja4h`），或自写解析脚本。
- 有客户端/工具/恶意样本的 JA4H 基线或情报。

## 利用步骤

1. 获取请求头原文（包括顺序、Cookie、Referer、Accept-Language）。
2. 计算 JA4H_a：方法、版本、c/n、r/n、头数（排除 Cookie/Referer）、语言。
3. 计算 JA4H_b：排除 Cookie/Referer 后的头名称按顺序哈希。
4. 解析 Cookie，按字段名/字段名+值排序后分别哈希出 JA4H_c/JA4H_d；无 Cookie 用 `000000000000`。
5. 与基线比对：同一客户端应稳定；出现未知 JA4H 时结合 JA4、UA、SNI、行为判断。
6. 会话劫持检测：同一 JA4/JA4H 组合突然出现在不同地理位置的连接上，或 JA4H 与 UA 声明不符，需进一步核查。

## PoC

```text
# 示例（文章截图）
JA4H = ge20cr13enus_974ebe531c03_b66fa821d02c_e97928733c74
       └ a: GET,HTTP/2,cookie,referer,13 headers,en-US
                         └ b: 请求头顺序哈希
                                      └ c: Cookie 字段名哈希
                                                   └ d: Cookie 字段名+值哈希

# Wireshark 字段（版本/插件而定）
ja4.ja4h
```

说明：示例值取自文章截图，未在本地复算；实际头数量与 Cookie 解析需按目标报文核对。

## 变体与关联

- 变体：Cookie 为列表或字符串两种解析方式；无 Cookie 时 c/d 段为 12 个 0。
- 变体：HTTP/1.1 与 HTTP/2 的版本段不同（`11`/`20`），HTTP/3 需按工具实现确认版本段。
- 关联：[[defense-detection-ja4-tls-client-fingerprint-modular]]（TLS 层客户端 JA4）；[[defense-detection-ja4l-latency-distance-fingerprint]]（结合延迟/距离检测会话劫持）；[[defense-detection-ja4s-tls-server-fingerprint]]（服务端指纹）。
- 边界：TLS 未解密时不可用；客户端可修改头顺序/Cookie 伪装；代理、WAF、CDN 可能重写头；UA 与 JA4H 可能不一致。

## 检测与防御

- 检测：把 JA4H 与 JA4、UA、SNI、IP 信誉组合；对未知 JA4H、JA4H 与 UA 不符、同一 Cookie 指纹跨地域出现等告警。
- 基线：按业务客户端/浏览器版本建立 JA4H 白名单；前端/网关升级后更新。
- 对抗：攻击者可用 curl/自定义框架修改头顺序与 Cookie 伪装；JA4H 只能作为组合特征，不能单独定案。
- 隐私：JA4H_d 涉及 Cookie 值哈希，需按隐私合规要求处理，避免用于跨站追踪。
