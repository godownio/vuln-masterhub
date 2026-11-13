---
id: defense-forensics-quasar-protobuf-tls-payload-decode
title: Quasar RAT 解密载荷的无 schema protobuf 解码：From Hex + Protobuf Decode 还原进程与连接消息
type: scenario
domain: defense
path: defense/forensics
technique: quasar-protobuf-tls-payload-schema-less-decode
tags:
- forensics
- traffic-analysis
- protobuf
- quasar-rat
- cyberchef
- malware-analysis
- c2
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V501
  verified_at: '2026-11-11T02:16:00+08:00'
  notes: 已对照原文核对：TLS 解密后载荷按 hex 用 CyberChef From Hex + Protobuf Decode（Schema 留空）还原字段号 JSON，并与服务端连接/进程列表对照语义，与原文及图 17-19 一致；文中 v1.4.0 起 protobuf-net 版本结论为原文未逐字给出的补充（文中仅见 protobuf-net.dll 与客户端 1.4.1），卡内已注明以样本版本为准；未实测。
url: /docs/defense/forensics/defense-forensics-quasar-protobuf-tls-payload-decode/
draft: false
kb_aliases:
- Protobuf Decode
- 无 schema protobuf 解码
- Quasar 通讯解码
- CyberChef protobuf
- TLS 载荷反序列化
---

## 一句话结论

Quasar RAT v1.4.0 起的 C2 消息先用 protobuf 序列化、再经 TLS 1.2 传输；TLS 解密后把应用层字节按 hex 交给 CyberChef 的 `From Hex` + `Protobuf Decode`（Schema 留空），即可在没有 .proto 的情况下按字段号还原嵌套结构（示例解出进程名、地址、端口列表），再与服务端反序列化结果或 Quasar.Common 消息定义对照即可恢复字段语义。

## 原理

- protobuf wire format 是自描述结构：每个字段由 varint tag 开头，tag = `(field_number << 3) | wire_type`；length-delimited 字段（wire type 2）后跟长度与字节。解析器即使没有 .proto，也能按规则读出字段号、wire type 和值，只是不知道字段名、枚举和具体语义。
- CyberChef 的 `Protobuf Decode` 在 Schema 为空时按上述规则解析，输出以字段号为键的 JSON；嵌套消息会递归展开。Quasar 的进程列表类消息即在字段 1 中嵌套多个对象，每个对象含进程名、本地地址、端口等值。
- Quasar v1.4.0 起使用 protobuf-net 序列化消息（程序目录可见 `protobuf-net.dll`、`Quasar.Common.dll`），TLS 只提供传输加密，不改变载荷格式；因此 TLS 解密后的字节可直接按 protobuf 解析。
- 可复用的原因：schema-less 解析把「结构」和「语义」分开——先无条件恢复结构与值，再借助服务端 GUI/源码对照得到字段含义。即使样本没有 .proto，也能在几分钟内看出消息类型与关键字段。
- 边界：无 schema 时无法确定字段名、枚举含义、oneof 分支；字符串/bytes 字段可能显示为乱码；字段号随版本可能变化，映射需要按版本核对。

## 触发条件

- 已获得 Quasar RAT 的明文应用层载荷（先完成 TLS 解密，见关联卡）。
- 载荷为 protobuf wire format（常见以 `0a`、`08` 等 tag 开头，可先用 From Hex 观察）。
- 有 CyberChef（可离线使用）或等价的 schema-less protobuf 解析工具。
- 仅用于授权恶意样本分析与取证。

## 利用步骤

1. 在 Wireshark 中对解密后的会话 Follow TCP Stream，以 Hex Dump 复制应用层数据（或导出 raw bytes）。
2. CyberChef 依次添加 `From Hex`（Delimiter: Auto）与 `Protobuf Decode`（Schema 留空，可选 Show Unknown Fields）。
3. 查看输出 JSON：以字段号为键，嵌套结构对应 message；记录字段号、wire type、值与长度。
4. 对照 Quasar 服务端 GUI（连接列表、进程列表、文件管理）与 `Quasar.Common` 消息类，建立字段号到语义的映射（如进程名、本地地址、端口）。
5. 对多条消息重复解码，归纳消息类型（进程列表、连接列表、心跳等），整理成字段号映射表。
6. 需要批量处理时，用支持未知字段的 protobuf 解析库按同样规则解析，并与手工解码结果交叉验证。

## PoC

```text
CyberChef Recipe:
  From Hex (Delimiter: Auto)
  Protobuf Decode (Schema: 空，Show Unknown Fields 可选)

示例输出（字段号 JSON，已截断）:
{
  "37": {
    "1": [
      {"1": "svchost", "2": "0.0.0.0", "3": 135, "4": "0.0.0.0", "6": 2},
      {"1": "System",  "2": "0.0.0.0", "3": 445, ...},
      {"1": "lsass",   "2": "0.0.0.0", "3": 49664, ...}
    ]
  }
}
```

说明：字段号对应的语义需结合服务端代码或 `Quasar.Common` 定义确认；示例值仅用于说明解码形态，实际以样本版本为准。

## 变体与关联

- 变体：有 .proto 时直接按 schema 解码，字段名与枚举完整；无 .proto 时先用本方法恢复结构，再通过反编译 `Quasar.Common` 或二进制中的 descriptor 恢复正式定义。
- 变体：其他 protobuf-over-TLS 的 RAT/C2（尤其 protobuf-net 的 .NET 家族）同样适用，只需换字段号映射。
- 关联：[[defense-forensics-schannel-cipher-order-downgrade-rsa-tls-decrypt]]（前置步骤：用私钥解密 TLS 1.2）；[[defense-detection-quasar-rat-tls-traffic-fingerprint]]（Quasar 的 TLS 1.2 + Protobuf 流量特征）；[[code-analysis-reverse-linux-protobuf-c-descriptor-recovery]]（从二进制恢复 protobuf 描述符的另一条路）。
- 边界：无 schema 时字段名/枚举/oneof 不确定；Quasar 版本变化可能调整字段号；载荷若压缩或二次加密，需先解压/解密。

## 检测与防御

- 防守方：TLS 加密使内容不可见，必须先通过私钥/keylog 解密才能进行 protobuf 解析；生产环境保持 ECDHE 前向保密可让被动方即使拿到私钥也无法解码。
- 检测：Quasar 的 protobuf 消息 tag 序列在解密后有明显特征，可对明文变体或已解密的取证流量建立匹配规则；结合 TLS 证书、心跳周期与 JA3S 做家族识别。
- 分析侧：整理字段号映射表后可批量解析历史 pcap，把进程、连接、文件操作等消息与主机侧日志交叉验证，形成完整证据链。
- 合规：仅在授权取证或自有样本分析中使用，保存原始流量与解析结果以备复核。
