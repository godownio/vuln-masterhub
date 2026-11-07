---
id: web-java-deserialization-nifi-getasanaobject-cache-state-deser
title: Apache NiFi GetAsanaObject 缓存状态反序列化（CVE-2025-66524）：可写 MapCache 即触发 ObjectInputStream.readObject
type: scenario
domain: web
path: web/java/deserialization
technique: nifi-getasanaobject-cache-state-deserialization
aliases:
- CVE-2025-66524
- NiFi GetAsanaObject 反序列化
- GenericObjectSerDe 反序列化
- MapCacheClientService 缓存投毒
- NiFi 分布式缓存状态反序列化
tags:
- java
- deserialization
- apache-nifi
- cve-2025-66524
- distributed-cache
- objectinputstream
- rce
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Apache NiFi 1.20.0 - 2.6.0
cve:
- CVE-2025-66524
verification:
  verified_by: verifier-V55
  verified_at: '2026-11-05T09:02:25+08:00'
  notes: 已对照原文与28张图核对：GetAsanaObject recoverState→MapCacheClientService.get→ValueInboundAdapter→GenericObjectSerDe.deserialize→ObjectInputStream.readObject、key/value 均用 GenericObjectSerDe、NettyMapCacheClient 写入 HashMap、HashMap.readObject 断点看到攻击者键值，均与图10-25一致；CVE-2025-66524、1.20.0-2.6.0、2.7.0 改 StringSerDe/MapStringSerDe 与图01/26-28一致。原文未提供 gadget 链、未演示 RCE，卡内已标 confidence medium 并注明 RCE 取决于 classpath gadget；本次按'可控原生反序列化'通过。PoC 未在本机执行；frontmatter 无 sources/source_url。
---

## 一句话结论

Apache NiFi 1.20.0–2.6.0 的 GetAsanaObject 处理器用 `GenericObjectSerDe`（内部就是 `ObjectInputStream.readObject()`）读取分布式 MapCache 中的状态 key/value；能访问并写入该缓存服务器的攻击者，把一个恶意序列化对象写到处理器标识对应的键上，处理器重启/恢复状态时就会反序列化该对象，配合 classpath 上的 gadget 可导致 RCE。

## 原理

- **状态存储在外部缓存**：GetAsanaObject 依赖可配置的 `DistributedMapCacheClientService` 保存/读取状态。`recoverState()` 调用 `client.get(this.getIdentifier(), STATE_MAP_KEY_SERIALIZER, STATE_MAP_VALUE_SERIALIZER)`，其中两个序列化器都是 `GenericObjectSerDe`（1.20.0–2.6.0）。
- **get 路径**：`MapCacheClientService.get()` 把 key 序列化后创建 `ValueInboundAdapter(valueDeserializer)` 发往缓存服务器；`ValueInboundAdapter` 收到字节后调用 `deserializer.deserialize(bytes)`；`GenericObjectSerDe.deserialize()` 直接 `new ObjectInputStream(new ByteArrayInputStream(value)).readObject()`，没有任何 `ObjectInputFilter`/类白名单。
- **主动权在缓存服务器**：缓存里的值是攻击者可写的字节，readObject 又是全功能原生反序列化；因此不需要经过 NiFi 的 HTTP 接口，只要能连到 `MapCacheServer`（原文示例端口 4558，未启用 SSL）并写入对应 key，就能把任意序列化对象喂给处理器的反序列化点。
- **key 也要序列化**：`client.get` 会先对传入的 key 做 `GenericObjectSerDe.serialize`，缓存服务端按字节匹配；因此攻击者写缓存时必须用同一个 `GenericObjectSerDe` 序列化 key 和 value，否则处理器读不到。key 就是处理器标识（Status History 里的 Id，如 `ad56afa5-019b-1000-9f90-68375856e9b7`）。
- **为什么是漏洞**：NiFi 对“缓存服务器内容”给予了与自身进程同等的 Java 反序列化信任，而缓存服务器是独立网络服务、默认无认证（原文示例），违反“不可信数据不可原生反序列化”的边界。修复（2.7.0）把 `GenericObjectSerDe` 替换为 `StringSerDe`/`MapStringSerDe`，序列化内容改为 JSON/字符串，readObject 路径消失。
- **原文验证边界**：作者用 Java 脚本通过 `NettyMapCacheClient` 写入一个 `HashMap`（键 `status/author/from`），重启处理器后断点在 `HashMap.readObject()` 看到自己写入的值，证明“攻击者控制的字节进入 readObject”。原文**没有**提供 gadget 链，未演示命令执行；本卡按“可控原生反序列化”定级，RCE 取决于目标 classpath 是否存在可用 gadget（NiFi 自带组件多，风险高但需按环境验证）。

## 触发条件

- 目标为 Apache NiFi 1.20.0–2.6.0，且部署/启用了 GetAsanaObject 处理器与 `DistributedMapCacheClientService`（MapCacheClientService）。
- 攻击者可网络访问对应的 `MapCacheServer`（原文示例 `localhost:4558`，未配置 SSL），并能向缓存写入 key/value；缓存服务无认证或凭据可获取。
- 攻击者知道处理器标识（可从 UI/Status History、日志或缓存枚举获得），或能枚举/猜测对应 key。
- 目标 classpath 存在可用的 Java 反序列化 gadget（原文未验证；无 gadget 时只能造成对象构造与拒绝服务类影响）。
- 处理器会执行 `recoverState`（处理器启动/重启、状态恢复时）。

## 利用步骤

1. 确认 NiFi 版本在 1.20.0–2.6.0，目标存在 GetAsanaObject 处理器；在 UI 中记录其标识（Status History 的 Id）。
2. 确认 MapCacheServer 地址/端口（原文 4558）可访问，且未启用 SSL/认证。
3. 用与目标一致的 `GenericObjectSerDe` 序列化 key（处理器标识）和 value（恶意序列化对象），通过 `NettyMapCacheClient.put(keyBytes, valueBytes)` 写入缓存。
4. 重启/重新启动 GetAsanaObject 处理器，触发 `recoverState()` → `client.get()` → `GenericObjectSerDe.deserialize()` → `readObject()`。
5. 若 value 是 gadget 链，则在其 readObject 过程中执行命令；否则可在调试器/日志中确认反序列化到了攻击者对象。

## PoC

原文写入脚本的核心逻辑（以 HashMap 演示，未含 RCE gadget）：

```java
GenericObjectSerDe serde = new GenericObjectSerDe();
Serializer<Object> genericSerializer = (value, out) -> serde.serialize(value, out);

String key = "ad56afa5-019b-1000-9f90-68375856e9b7"; // GetAsanaObject 的 Id
Map<String, String> value = new HashMap<>();
value.put("status", "test_success");

byte[] keyBytes = CacheClientSerde.serialize(key, genericSerializer);
byte[] valueBytes = CacheClientSerde.serialize(value, genericSerializer);
client.put(keyBytes, valueBytes); // client = NettyMapCacheClient(host, 4558, ...)
```

验证：重启处理器后，在 `GenericObjectSerDe.deserialize` → `ObjectInputStream.readObject` → `HashMap.readObject` 处可看到 `status=test_success` 等攻击者写入的键值，说明缓存内容被原样反序列化。将 `value` 替换为 ysoserial 等工具生成的 gadget 序列化字节即可尝试 RCE（原文未做，需自行验证 gadget 与目标依赖）。

## 变体与关联

- **利用面不限于 value**：`client.get` 同时反序列化 key（`STATE_MAP_KEY_SERIALIZER`），若能控制 key 字节也可触发；但需要先知道/枚举处理器标识。
- **缓存服务器暴露面**：MapCacheServer 常部署在内网、默认无 TLS/认证；拿到内网立足点或 SSRF/端口转发后即可写缓存。也可通过污染持久化目录（原文 `Persistence Directory`）间接写入。
- **同类模式**：其他使用 `GenericObjectSerDe`/原生 Java 序列化读写外部缓存/消息的处理器，同样属于“外部数据进入 readObject”的信任边界错误；审计时可全局搜 `GenericObjectSerDe`、`ObjectInputStream`、`readObject`。
- **关联链**：反序列化 gadget 卡（CC/CB/URLDNS 等）、JNDI 注入卡；本卡只负责“触发点/入口”，gadget 选择按目标 classpath 决定。
- **修复对照**：NiFi 2.7.0 的 PR #10599 将 `GenericObjectSerDe` 改为 `StringSerDe`/`MapStringSerDe`（JSON/字符串），并在 2.7.0 移除该处理器所在 nar 的旧实现；升级后缓存中的旧 Java 序列化数据不再被 readObject。

## 检测与防御

- **升级**：升级到 Apache NiFi 2.7.0 及以上（组件 `org.apache.nifi:nifi-asana-processors`），或移除 `nifi-asana-processors-nar` 中的 GetAsanaObject 处理器。
- **网络隔离**：MapCacheServer 端口（默认/示例 4558）只对可信 NiFi 节点开放，禁止从用户网段/办公网直连；启用 SSL Context Service 与认证，限制可写客户端。
- **运行时检测**：监控对 MapCacheServer 的非 NiFi 客户端连接与 put 操作；NiFi 日志/调试中出现 `GenericObjectSerDe.deserialize` 处理异常、未知类加载、`ObjectInputStream` 相关告警；处理器重启后短时间内出现异常子进程/网络外连。
- **加固**：在无法升级时给反序列化加 `ObjectInputFilter` 类白名单（仅允许状态所需的 Map/String 等），禁用不需要的 GetAsanaObject 处理器；缓存目录与进程权限最小化；对缓存内容做完整性校验/来源签名。
- **排查**：检查 MapCacheServer 的持久化目录与访问日志，寻找非预期客户端写入；核对 GetAsanaObject 状态中是否出现非预期键值/类名；升级后清理旧格式缓存。
