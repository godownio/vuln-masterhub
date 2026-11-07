---
id: web-java-component-jboss-4-2-3-4446-deserialization
title: JBoss 4.2.3 端口 4446 反序列化：内置 CommonsCollections 3.1 链写文件读 flag
type: scenario
domain: web
path: web/java/component
technique: jboss-4-2-3-4446-deserialization
tags:
- web
- java
- jboss
- deserialization
- commons-collections
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
affected_versions: JBoss 4.2.3
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:02:49+08:00'
  notes: 已对照原文与图 26 核对：JBoss 4.2.3/4446、CC 3.1、magic 后插 77 01 16 79、nc 投递一致；已设 affected_versions；未复跑内网。
url: /docs/web/java/component/web-java-component-jboss-4-2-3-4446-deserialization/
draft: false
kb_aliases:
- JBoss 4.2.3
- 4446 端口
- HttpInvoker
- CommonsCollections 3.1
- CCK1
- yakit
---

## 一句话结论

JBoss 4.2.3 的 4446 端口暴露 Java 反序列化入口，且 `lib` 中自带 CommonsCollections 3.1；用 yakit/ysoserial 生成 CCK1 链的可序列化对象，按该端口的投递格式写入 `payload.ser`，通过内网代理 `nc` 发送，即可在目标 JVM 中触发 `Runtime.exec`，再写文件/读文件拿到 flag。

## 原理

- Java 原生反序列化在 `readObject` 时执行 gadget 链；CommonsCollections 3.1 的 `AnnotationInvocationHandler`/`LazyMap`/`InvokerTransformer` 组合可以在反序列化阶段反射调用任意方法，最终执行 `Runtime.exec`。
- JBoss 4.2.3 默认把 CommonsCollections 等库放在 `lib` 下，满足 gadget 依赖；其 4446 端口接受序列化对象并交由 `ObjectInputStream` 处理。
- 本题的投递格式：先用 yakit 生成 CCK1 的 `rO0AB...` base64，再在 Java 序列化 magic `AC ED 00 05` 之后插入 4 字节 `77 01 16 79`，其余字节原样拼接，写出 `payload.ser`。`77 01 16 79` 在 Java 序列化协议中可读作 `TC_BLOCKDATA`（长度 1、数据 0x16）+ `TC_RESET`，用于适配/穿透目标对该端口的检查；原文未解释该细节。
- 通过已拿下的 Web 服务器做 Suo5 HTTP 代理，用 `type payload.ser | nc <jboss_ip> 4446` 把原始字节送到内网 JBoss；命令执行后通过写文件/读文件确认回显。
- 本质是“内网暴露的 Java 反序列化服务 + 已知 gadget 依赖”，版本 4.2.3 是原文明确标记的受影响版本。

## 触发条件

- 目标为 JBoss 4.2.3（或同系列）且 4446 端口可从当前网络到达；`lib` 中存在 CommonsCollections 3.1。
- 攻击者已获得可出网/可代理的内网立足点（本题通过前一步 PHP webshell 获得）。
- 能生成与目标 JDK 匹配的 CCK1/CC1 gadget payload；JDK 版本过高时需换链或调整。
- 目标对序列化数据没有有效白名单/过滤器。

## 利用步骤

1. 从前一步的 Web 权限执行 `ps aux`/端口扫描，确认 JBoss 4.2.3 与 4446 端口，并读取其 `lib` 中的 commons-collections 版本（3.1）。
2. 用 yakit（或 ysoserial）生成 CCK1 payload（base64 的 `rO0AB...`）。
3. 按原文格式构造 `payload.ser`：保留前 4 字节 `AC ED 00 05`，插入 `77 01 16 79`，再拼接其余序列化字节。
4. 在 Web 服务器上起 Suo5 HTTP 代理（或其它内网隧道），把 payload.ser 通过 `nc` 发到 `<jboss_ip>:4446`。
5. 命令执行后写文件（如 `id > /tmp/x`）或直接读 flag，通过 Web 侧读取回显；用 `find / -name '*flag*'` 定位。
6. 若一次不成功，检查 JDK 版本、gadget 依赖、端口/协议格式与命令长度。

## PoC

```java
String payload = "rO0AB...";                       // yakit 生成的 CCK1 base64
byte[] serialize = Base64.getDecoder().decode(payload);
byte[] magic = Arrays.copyOfRange(serialize, 0, 4); // AC ED 00 05
byte[] body  = Arrays.copyOfRange(serialize, 4, serialize.length);
byte[] mark  = new byte[]{0x77, 0x01, 0x16, 0x79};
byte[] out   = ArrayUtils.addAll(ArrayUtils.addAll(magic, mark), body);
Files.write(out, new File("./payload.ser"));
```

```bash
# 通过 Suo5/其它 HTTP 代理进入内网后
type payload.ser | nc 10.22.11.97 4446
```

说明：`77 01 16 79` 的作用原文未展开，可能是该端口协议/过滤适配所需；不同 JBoss 版本/端口（8080 的 JMXInvokerServlet 等）投递方式不同，需按目标实测。

## 变体与关联

- **JMXInvokerServlet/HTTP 入口**：JBoss 4.x/5.x 另有 8080 端口的反序列化入口，可用 HTTP POST 直接投递；与本卡 4446 原始 TCP 入口不同。
- **gadget 链**：CC1/CCK1、CommonsBeanutils、Jdk7u21 等按依赖选择；见 [[web-java-deser-commonscollections-cc1-transformedmap]]、[[web-java-deser-commonscollections-cc1-lazymap-proxy]]。
- **内网代理**：Suo5、frp、reGeorg 等把 payload 送进不可直达的网段；见 [[ctf-misc-proxy-half-close-gost-frp-fingerprint]]。
- **版本差异**：JBoss 4.2.3 的 lib 依赖固定；更高版本可能无 CC 3.1 或已打补丁。

## 检测与防御

- 升级 JBoss 并移除不必要的 commons-collections 3.1；对 `ObjectInputStream` 使用白名单（`ObjectInputFilter`）。
- 4446 等管理/消息端口只监听内网并做认证，禁止从 Web 服务器任意访问；用网络分段限制横向。
- 检测：向 4446 端口发送 `AC ED 00 05` 开头的字节、异常 `nc` 连接、JBoss 进程拉起 `bash/sh`、`/tmp` 出现命令输出文件。
- 应急：排查 Web 服务器上的 webshell 与 Suo5 代理进程，封禁内网横向路径。
