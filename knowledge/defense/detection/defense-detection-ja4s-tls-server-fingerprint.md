---
id: defense-detection-ja4s-tls-server-fingerprint
title: JA4S 服务端指纹：协议版本_扩展数_选中ALPN + 选中套件 + 响应扩展序哈希
type: scenario
domain: defense
path: defense/detection
technique: ja4s-tls-server-fingerprint
aliases:
- JA4S 指纹
- JA4-Server
- TLS 服务端响应指纹
- Server Hello 指纹
- ja4.ja4s
tags:
- defense
- detection
- tls
- ja4
- fingerprint
- traffic-analysis
- server
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V501
  verified_at: '2026-11-11T02:38:56+08:00'
  notes: 已对照原文与图20-24核对：JA4S_a=协议+版本+扩展数+选中ALPN（t120400、t1203h1）、JA4S_b=选中套件（c030/c02f）、JA4S_c=响应扩展按出现顺序哈希且排除 ALPN（ff01,000b→344b4dce5a52）均与原文/幻灯片一致；示例值取自截图未本地复算。未实测抓包。
---

## 一句话结论

JA4S 对 ServerHello 做指纹：`JA4S_a` 记录协议、TLS 版本、扩展数量和选中 ALPN，`JA4S_b` 记录服务端选中的密码套件，`JA4S_c` 把响应扩展类型按出现顺序哈希取前 12 位；它能在不解密的情况下识别服务端 TLS 栈、CDN/WAF、C2 服务端或中间盒，但同一服务端面对不同客户端可能产生不同 JA4S（响应扩展是客户端提议的子集）。

## 原理

- ServerHello 是服务端对 ClientHello 的响应，字段由服务端 TLS 实现和配置决定：版本、选中的密码套件、扩展列表（服务端只会回客户端提议过的扩展）。
- **JA4S_a**：`协议`（`t`/`q`）+ `TLS 版本`（`13`/`12`/…）+ `扩展数量`（两位十进制，含 ALPN 等全部响应扩展）+ `选中 ALPN`（如 `h1`/`h2`，无则 `00`）。例：`t120400` = TCP + TLS1.2 + 4 个扩展 + 无 ALPN；`t1203h1` = TCP + TLS1.2 + 3 个扩展 + h1。
- **JA4S_b**：服务端选中的密码套件十六进制值（不含 `0x`），直接作为一段，如 `c030`、`c02f`。
- **JA4S_c**：取响应扩展类型（十六进制、不含 `0x`），**忽略 ALPN（0010）**（SNI 在 ServerHello 中不会出现，无需处理），按出现顺序用 `,` 连接，SHA256 取小写前 12 位。例：扩展 `ff01,000b` → `344b4dce5a52`。
- 与 JA4 的差异：服务端只选一个套件，所以没有套件数量/套件哈希；JA4S_a 保留扩展数量和选中 ALPN；JA4S_c 不对扩展排序（服务端扩展顺序通常稳定），直接按出现顺序哈希。
- **依赖客户端**：同一台服务器对 Windows/Linux/不同浏览器返回的扩展集合不同，JA4S 会变化；要获取服务器自身的稳定指纹，应使用主动探测（如 JA4TScan/JARM）或固定客户端配置。
- 与 JA4 组合：客户端 JA4 与服务端 JA4S 可以刻画一条完整 TLS 会话的两端；若同一 JA4 客户端在短时间内对同一目标出现异常 JA4S，可能是中间盒、代理或 C2 切换。

## 触发条件

- 能捕获 ServerHello（TCP TLS 或 QUIC），无需解密。
- 采集工具支持 JA4S：Wireshark 4.2+ 原生或 ja4.dll 插件（自定义列 `ja4.ja4s`）。
- 有已知服务端/CDN/WAF/C2 的 JA4S 基线或情报。

## 利用步骤

1. 抓取包含 ServerHello 的会话；TCP 看 `tls.handshake.type == 2`，QUIC 看相应握手包。
2. 提取协议、TLS 版本、响应扩展类型列表、选中套件、选中 ALPN。
3. 计算 JA4S_a/b/c；用 Wireshark `ja4.ja4s` 列或过滤验证。
4. 与 JA4 客户端指纹配对：记录 `JA4 -> JA4S` 组合，识别客户端/服务端栈与中间盒。
5. 对同一目标多次采样；若 JA4S 随客户端变化，说明它反映的是“服务端对该客户端的响应”，不是服务端全貌。
6. 需要服务端稳定指纹时改用主动扫描（JA4TScan）或 JARM，并与证书、JA4X 交叉。

## PoC

```text
# Wireshark 4.2+ 字段/过滤（示意）
ja4.ja4s
ja4.ja4s == "t120400_c030_4e8089b08790"

# 示例计算
Extensions: ff01,000b  -> SHA256 前 12 位 = 344b4dce5a52
JA4S = t1203h1_c02f_344b4dce5a52
```

说明：字段名与可用列随 Wireshark 版本/插件变化；示例值取自文章截图，未在本地复算。

## 变体与关联

- 变体：QUIC 服务端把协议位换成 `q`；无 ALPN 时 JA4S_a 末尾为 `00`。
- 变体：响应扩展数量包含 ALPN，但 JA4S_c 哈希排除 ALPN；两者不要混用。
- 关联：[[defense-detection-ja4-tls-client-fingerprint-modular]]（客户端 JA4）；[[defense-detection-ja3-tls-fingerprint-suricata]]（JA3/JA3S 旧体系）；[[defense-detection-ja4x-x509-cert-generation-fingerprint]]（证书生成方式指纹）；[[defense-detection-ja4t-ja4ts-ja4tscan-tcp-fingerprint]]（TCP 层服务端响应 JA4TS）。
- 边界：服务端可自定义扩展/套件、使用 CDN 统一终止 TLS；同一服务端对不同客户端产生不同 JA4S；中间盒会改变指纹。

## 检测与防御

- 检测：用 JA4S 识别服务端栈/CDN/WAF/C2；对同一目标出现异常 JA4S（如突然从常见 nginx 套件变为陌生组合）告警，结合证书与 JA4X 判断是否中间人/仿冒。
- 基线：按业务域名/服务端版本建立 JA4S 白名单；CDN 或负载均衡升级后更新。
- 对抗：攻击者可定制服务端 TLS 配置伪装常见服务端；JA4S 只能作为组合特征。
- 合规：仅使用握手明文元数据，不涉及解密。
