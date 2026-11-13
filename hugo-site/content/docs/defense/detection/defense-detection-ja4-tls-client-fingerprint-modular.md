---
id: defense-detection-ja4-tls-client-fingerprint-modular
title: JA4 TLS 客户端指纹：六段 JA4_a + 套件哈希 + 扩展哈希，GREASE 清零与排序降噪
type: scenario
domain: defense
path: defense/detection
technique: ja4-tls-client-fingerprint
tags:
- defense
- detection
- tls
- ja4
- fingerprint
- traffic-analysis
- network
- quic
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V501
  verified_at: '2026-11-11T02:38:54+08:00'
  notes: 已对照原文与全部 37 张图片核对：JA4_a 六段（协议/最高版本/SNI/套件数/扩展数/ALPN，图08/09 幻灯片含扩展数 16）、JA4_b 排序套件 SHA256 前 12 位、JA4_c 排序扩展+原始序 signature_algorithms、忽略 GREASE 与 0000/0010 均一致；修正了关联 wiki 链接 ja4h-...-modular 指向不存在的 id，改为 defense-detection-ja4h-http-client-fingerprint。未实测抓包。
url: /docs/defense/detection/defense-detection-ja4-tls-client-fingerprint-modular/
draft: false
kb_aliases:
- JA4 指纹
- JA4_a JA4_b JA4_c
- JA4+ TLS Client
- TLS 客户端指纹
- GREASE 忽略
- ja4.ja4
---

## 一句话结论

JA4 是 JA3 的升级替代：对 ClientHello 计算 `JA4_a_JA4_b_JA4_c`——JA4_a 是可读的六段元信息（协议、最高 TLS 版本、SNI 有无、密码套件数、扩展数、首个 ALPN），JA4_b 是排序后密码套件列表的 SHA256 前 12 位，JA4_c 是排序后扩展类型列表拼接原始顺序 signature_algorithms 的 SHA256 前 12 位；全程忽略 GREASE，既能识别 TCP/QUIC 客户端实现，又通过排序抵抗套件/扩展顺序随机化。

## 原理

- ClientHello 的字段取值由客户端 TLS 库和配置决定；JA4 把这些字段分成三段，既保留人类可读信息，又用哈希抹平长列表。
- **JA4_a（六段）**：
  - 协议：`t`=TCP，`q`=QUIC；
  - 最高 TLS 版本：读 `supported_versions` 等扩展中的最高版本，`13`/`12`/`11`/`10`/`s3`/`s2`/`s1`/`00`。Wireshark 常把记录层显示为 TLS 1.2，但 ClientHello 的 supported_versions 含 TLS 1.3 时 JA4 取 `13`；
  - SNI：有 SNI 为 `d`（访问域名），无 SNI 为 `i`（访问 IP）；
  - 密码套件数：两位十进制（如 15 → `15`，最大 `99`），忽略 GREASE；
  - 扩展数：两位十进制，同样忽略 GREASE；
  - 首个 ALPN：如 `h2`、`h1`；无 ALPN 为 `00`。
  例：`t13d1516h2` = TCP + TLS1.3 + 有 SNI + 15 个套件 + 16 个扩展 + h2。
- **JA4_b**：取出全部密码套件十六进制值（不含 `0x`），忽略 GREASE 后按数值从小到大排序，用 `,` 连接，SHA256 后取小写前 12 位。排序是为了降低“Cipher Stunting”（插入噪声套件/改变顺序）的影响，同时保留“套件集合”本身的区分度。
- **JA4_c**：取扩展类型十六进制值，忽略 GREASE、SNI（`0000`）与 ALPN（`0010`），按数值排序；再取 `signature_algorithms` 扩展中的签名算法列表（保持原始顺序），两串用 `_` 连接，SHA256 后取小写前 12 位。排序主要对抗 Chrome 等客户端对扩展顺序的随机化。
- **GREASE**：Chrome 等会插入 `0x0a0a`、`0x1a1a`、…、`0xfafa` 这类保留值，JA4 全部剔除后再计算，避免同一客户端因 GREASE 值变化产生不同指纹。
- 与 JA3 的差异：JA4 增加可读段与扩展数量、支持 QUIC、对套件/扩展排序、忽略 GREASE；JA3 直接按原始顺序拼接后 MD5，容易被顺序随机化破坏。

## 触发条件

- 能在流量路径上捕获完整 TLS ClientHello（TCP 或 QUIC），不需要解密。
- 采集/解析工具支持 JA4：Wireshark 4.2+ 已原生支持；旧版本可把 `ja4.dll` 放到 `Wireshark\plugins\<版本>\epan` 并在首选项“列”中添加 `ja4.ja4` 自定义列（文章提到插件计算版本号有误会导致 JA4_a 不同，优先用原生实现）。
- 有正常客户端/已知软件/恶意家族的 JA4 基线或情报库，用于比对。

## 利用步骤

1. 抓取包含 ClientHello 的 pcap；TCP 看 `tls.handshake.type == 1`，QUIC 看相应 Initial 包。
2. 提取字段：协议、最高支持版本、SNI、密码套件列表、扩展类型列表、signature_algorithms、首个 ALPN。
3. 剔除 GREASE 值；按上述规则拼接 JA4_a、排序后哈希出 JA4_b/JA4_c，得到完整 `JA4`。
4. 用 Wireshark 列/过滤器 `ja4.ja4 == "<指纹>"` 验证计算结果；对比 `JA4_r` 原始串排查差异。
5. 与基线/情报比对：同一软件版本应稳定；出现未知 JA4 时结合 SNI、IP 信誉、证书、JA4S/JA4H 进一步研判。
6. 对可疑客户端可追踪其同一 JA4 的历史会话，做资产与攻击面刻画。

## PoC

```python
import hashlib

def h12(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]

def ja4(protocol, version, sni, ciphers, exts, alpn, sigalgs):
    # ciphers/exts/sigalgs 为不带 0x 的小写十六进制字符串列表；调用方需先剔除 GREASE
    a = f"{protocol}{version}{'d' if sni else 'i'}{len(ciphers):02d}{len(exts):02d}{alpn or '00'}"
    b = h12(",".join(sorted(ciphers, key=lambda x: int(x, 16))))
    exts_wo = sorted([e for e in exts if e not in ("0000", "0010")], key=lambda x: int(x, 16))
    c = h12(",".join(exts_wo) + "_" + ",".join(sigalgs))
    return f"{a}_{b}_{c}"

# 示例（值需按实际 ClientHello 填入）
# print(ja4("t", "13", True, ["1301","1302","c02b"], ["0000","0010","000d","002b"], "h2", ["0403","0804"]))
```

```text
# Wireshark 4.2+ 原生 JA4 字段/过滤
ja4.ja4 == "t13d1516h2_8daaf6152771_02713d6af862"
```

## 变体与关联

- 变体：QUIC 客户端把协议位换成 `q`；无 SNI 的客户端为 `i`；无 ALPN 为 `00`。
- 变体：只取 JA4_a（如 `t13d1516h2`）做粗筛，再结合 JA4_b/JA4_c 精确比对；文章示例中同一 JA4_a 对应多个不同完整指纹。
- 关联：[[defense-detection-ja3-tls-fingerprint-suricata]]（上一代 JA3 的原理与局限）；[[defense-detection-ja4s-tls-server-fingerprint]]（服务端响应指纹）；[[defense-detection-ja4t-ja4ts-ja4tscan-tcp-fingerprint]]（TCP 层 JA4T）；[[defense-detection-ja4h-http-client-fingerprint]]（HTTP 层 JA4H）。
- 边界：客户端可修改 TLS 库或使用 uTLS 等工具伪装常见 JA4；GREASE/扩展随机化被正确忽略后，JA4 仍可能在大版本间变化；Wireshark 插件与原生实现的版本号处理差异会导致 JA4_a 不同。

## 检测与防御

- 检测：把 JA4 作为加密流量侧写的一部分，与 SNI、证书、JA4S、JA4H、JA4T、IP 信誉组合；对未知或与声明客户端不符的 JA4 告警。
- 基线：按业务/客户端版本建立 JA4 白名单；新版本发布后更新基线，避免把正常升级当异常。
- 对抗：攻击者可用 uTLS 等伪装浏览器 JA4，单靠 JA4 不能定案；应结合行为、证书与主机侧证据。
- 隐私/合规：JA4 来自握手明文元数据，不需要解密；采集与留存需符合组织的数据治理要求。
