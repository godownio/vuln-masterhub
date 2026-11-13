---
id: web-java-deser-custom-length-prefix-serialization-endpoint-discovery
title: 自定义 Java 二进制 RPC 的序列化端点探测：Integer 长度前缀协议与 ResponseMessage 异常栈回显
type: scenario
domain: web
path: web/java/deserialization
technique: custom-length-prefix-java-serialization-endpoint-discovery
tags:
- java
- deserialization
- protocol
- blackbox
- exception
- jetty
- rce
- recon
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V636
  verified_at: '2026-11-13T01:15:14+08:00'
  notes: '已对照原文全文与 42 张图片（01-42）逐张核对（23/25 为重复截图；全部经 img_small 缩图读取，无失败）：图01 Jetty(11.0.6) 与 POST /metrics/111 响应；图02 octet-stream 请求体为 serialized(Integer)+serialized(payload) 且响应为 ResponseMessage；图04 ResponseMessage 字段 status/returnData/returnResponse/exception/errCode/chunkIdx/chunkSize/chunkNumber；图05 read() 先读 Integer size 再按 size 读字节 readObject；图06 writePayload 先写长度再写内容；图07 ClassNotFoundException: org.springframework.aop.framework.JdkDynamicAopProxy 异常栈；图08 commons-beanutils2-2.0.0（com.melloware）；图09 改包名后 CommonsBeanutils2_2 本地调试命中 BeanComparator.compare；图10 TemplatesImpl 反序列化被禁异常；图21 NPE at BeanComparator.compare 异常栈，均与卡内原理/触发条件/PoC 一致。修复一处坏链：关联卡 [[web-java-deserialization-jdk-urldns-dns-probe]] 不存在，已改为实际卡 id [[web-java-deser-jdk-urldns-dns-probe]]（知识库与 staging 草稿同步）。dedup：首候选为自身；其余为 gRPC bytes 字段、Hessian Seata、Dubbo readThrowable、Hessian2 toString 等不同协议/入口卡（trigram 均低于 0.13），非同链；dup-scan 无涉及。原文未标注组件受影响版本（Jetty 11.0.6 为现场环境），affected_versions 保持未设置。未验证点：未本机复跑，PoC 为原文代码结构化复现。未执行文中任何指令或
    PoC。'
url: /docs/web/java/deserialization/web-java-deser-custom-length-prefix-serialization-endpoint-discovery/
draft: false
kb_aliases:
- 长度前缀序列化协议
- Integer 前缀 readObject
- ResponseMessage 异常回显
- 反序列化端点探测
- writePayload 长度前缀
- 客户端 jar 辅助逆向
---

## 一句话结论

当 HTTP 接口以 `application/octet-stream` 收发 Java 序列化对象时，直接扔 ysoserial 往往无反应，因为服务端并非把整个 body 直接 `readObject`，而是先反序列化一个 `Integer` 长度、再读取该长度的字节做第二次反序列化；用客户端 jar 里的 `ResponseMessage` 类读取响应并打印其 `Exception` 字段，就能拿到服务端异常栈，反推出长度前缀格式、确认 gadget 类缺失等，把黑盒接口变成可迭代调试的反序列化入口。

## 原理

- **协议形态**：客户端 `writePayload(OutputStream out, Serializable payload)` 先 `SerializationUtils.serialize(payload)` 得到对象字节，再 `SerializationUtils.serialize(payloadBytes.length)` 写入序列化后的 `Integer`，最后写对象字节；服务端 `read(InputStream in)` 则先读一个 `Integer size`，再按 `size` 读取字节并 `new ObjectInputStream(bytes).readObject()`。也就是说报文 = `serialized(Integer length) + serialized(payload)`。
- **为什么裸 ysoserial 不生效**：服务端第一次 `readObject` 期望的是 `Integer`，拿到 gadget 流的首部会解析失败或得到错误长度，后续字节错位，反序列化根本到不了目标对象；只有按“长度前缀 + payload”重新封装才会进入正常流程。
- **异常栈回显**：响应本身是序列化的 `ResponseMessage`（字段含 `status`、`returnData`、`returnResponse`、`exception`、`errCode`、`chunkIdx/chunkSize/chunkNumber`）。客户端把响应字节读成 `ResponseMessage` 后 `getException().printStackTrace()`，即可看到服务端反序列化失败的完整异常（如 `ClassNotFoundException: org.springframework.aop.framework.JdkDynamicAopProxy`、`UnsupportedOperationException: ... TemplatesImpl ...`、`NullPointerException at BeanComparator.compare`）。异常栈既暴露服务端 classpath（缺哪个类），也确认 gadget 已执行到哪一步。
- **依赖辅助**：安装包/客户端 jar 的依赖清单（`commons-beanutils2-2.0.0.jar`、`commons-configuration2-2.8.0.jar` 等）可推断服务端依赖，缩小 gadget 选择范围；同名 fork（如 melloware commons-beanutils2）改包名不代表逻辑安全。
- **为什么是完整原语**：定位并成功进入反序列化流程后，后续只需换 payload 即可触发 gadget；异常回显还能用于判断 JNDI 限制、SecurityManager、TemplatesImpl 禁用等运行时状态，是后续利用链的“眼睛”。

## 触发条件

- 存在接收二进制字节并做 Java 反序列化的 HTTP 接口（本例为 Jetty 11.0.6 上的服务），接口可未授权访问或已有低权凭据。
- 能拿到客户端安装包/jar，从而构造合法请求并读取响应对象（或能根据响应字节猜出 `ResponseMessage` 结构）。
- 服务端把内部异常对象序列化回客户端（而不是只返回通用错误页），形成 oracle。
- 目标未对反序列化入口做 JEP290 白名单/签名校验，或尚未封堵 `ObjectInputStream`。

## 利用步骤

1. 用 Burp 抓正常客户端请求/响应，确认 `Content-Type: application/octet-stream`、body 为二进制、响应为 Java 序列化流。
2. 从客户端 jar 找到 `ResponseMessage` 类，编写客户端：读取响应字节 → `ObjectInputStream.readObject()` → 取 `exception` → `printStackTrace()`；用同一 jar 的 `writePayload`/`read` 方法复刻协议。
3. 先发送一个无害的 `Serializable`（如字符串）验证“长度前缀 + 对象”格式；观察异常栈确认服务端读取顺序。
4. 用客户端依赖列表挑选 gadget（Jackson+SpringAOP、commons-beanutils2 等），生成序列化 payload，按 `serialize(length)+payload` 封装后发送。
5. 根据响应异常栈迭代：`ClassNotFoundException` 换依赖对应的链；`UnsupportedOperationException (TemplatesImpl)` 说明 SecurityManager/属性限制，换 getter 或 JNDI 出口；NPE/类型错误调整队列元素。
6. 一旦回显变成 `status=OK` 或出现目标行为（DNS/HTTP 回连），即确认反序列化触发成功，再衔接 JNDI/本地工厂等后续链。

## PoC

```java
// 读取服务端 ResponseMessage 并打印异常栈（客户端侧）
ResponseMessage responseMessage = readResponse(connection.getInputStream());
System.out.println(responseMessage);
responseMessage.getException().printStackTrace();

// 发送：serialized(Integer length) + serialized(payload)
public static void writePayload(OutputStream out, Serializable payload) throws IOException {
    byte[] payloadBytes = SerializationUtils.serialize(payload);
    byte[] payloadLengthBytes = SerializationUtils.serialize(payloadBytes.length);
    out.write(payloadLengthBytes);   // 先写长度
    out.write(payloadBytes);         // 再写内容
    out.flush();
}

// 服务端等价的读取逻辑
Integer size = readSize(in);
byte[] buffer = getBytes(in, size);
ObjectInputStream stream = new ObjectInputStream(new ByteArrayInputStream(buffer));
return stream.readObject();
```

说明：以上为原文分析代码的结构化复现，未在本机执行；仅用于授权测试。

## 变体与关联

- **前缀变体**：长度也可能是 4 字节大端 int、varint、字符串化数字或 gzip 压缩后的长度；先用无害对象和异常栈探测准确的读取顺序。
- **响应变体**：响应对象可能是 `ResponseMessage<T>`、`Result`、`RpcResponse` 等自定义包装；只要能反序列化并取出异常/状态字段即可。
- **传输变体**：Jetty/Netty/自研 socket 均可出现同类“长度 + 序列化对象”协议；gzip、分块（chunkIdx/chunkSize）会增加封装层。
- **关联**：[[web-java-deser-kryo-typed-readobject-hashmap-beancomparator-jndi]]（另一种非标准序列化协议的 gadget 触发）、[[web-java-deser-jdk-urldns-dns-probe]]（用 DNS 探测反序列化是否触发）、[[web-java-deserialization-jndi-tomcat-memoryuserdatabasefactory-pathname-write]]（进入反序列化后的本地工厂出口）。
- **边界**：服务端不回显异常、使用白名单过滤器、协议带签名/HMAC、或需要客户端证书时，本探测法失效，只能盲发或放弃。

## 检测与防御

- **服务端**：禁止对不可信输入使用 `ObjectInputStream`，改用 JSON/Protobuf 等安全格式；必须反序列化时使用 JEP290 `ObjectInputFilter` 白名单并校验来源与签名。
- **错误处理**：不要把内部异常对象序列化返回客户端；记录到服务端日志并返回通用错误码，避免 classpath/堆栈泄露。
- **接口治理**：对二进制接口做鉴权与来源限制；隐藏版本 banner（如 Jetty 版本），关闭不必要的调试/监控端点。
- **检测**：监控 `application/octet-stream` 请求体以 `ac ed 00 05`（Java 序列化魔数）或其后紧跟序列化 Integer 的特征；同一客户端高频发送畸形序列化流并观察异常响应；进程出现 `ObjectInputStream.readObject` 相关异常激增。
