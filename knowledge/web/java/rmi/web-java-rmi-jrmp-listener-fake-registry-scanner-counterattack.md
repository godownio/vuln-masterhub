---
id: web-java-rmi-jrmp-listener-fake-registry-scanner-counterattack
title: 用 JRMPListener 冒充 1099 注册中心：扫描器一发 bind/list 就被「反向打回」，恶意 JRMP 端返回 gadget 反制
type: scenario
domain: web
path: web/java/rmi
technique: jrmp-listener-fake-registry-reverse-exploit
aliases:
- 注册中心打客户端
- RMI 蜜罐反制
- JRMPListener 伪装注册中心
- RMIRegistryExploit 被打回
- RMI 反制扫描器
- 服务端返回 Object 触发客户端 readObject
- DGC/JRMP 反序列化入口
tags:
- java
- rmi
- jrmp
- honeypot
- counterattack
- deserialization
- scanner
- rce
cve: []
severity: high
confidence: medium
affected_versions: JDK 6u45/7u21/8u121 之前默认 useCodebaseOnly=false 且无 JEP290 过滤（原文：更早版本动态类加载与反序列化均无默认限制）
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4
  verified_at: '2026-11-08T20:50:56+08:00'
  notes: 已对照原文核对；本次核对未读取图片；JRMPListener 1099 冒充注册中心、RMIRegistryExploit 的 list() 试探触发反序列化、注册中心打客户端/服务端返回 Object/codebase 三种场景与正文一致；affected_versions 依据正文「useCodebaseOnly 自 6u45/7u21/8u121 起默认为 true」与「注册中心打客户端 利用条件 8u121 以下」保留不动。未验证点：正文未给出该手法的实测反制过程（仅演示 JRMPListener+RMIRegistryExploit 同机），受限版本细节仅来自版本对照表截图，未读图；未执行任何 PoC。
---

## 一句话结论

RMI 的「注册中心 ↔ 客户端」和「服务端 ↔ 客户端」两个方向都天然带 `readObject`：客户端 `lookup` 之后会反序列化注册中心返回的 Stub/对象，调用远程方法后也会反序列化服务端返回值。因此把 `ysoserial.exploit.JRMPListener` 摆在 1099（或任意被扫描的 RMI 端口）冒充注册中心，等扫描器/攻击工具连上来做 `list()`/`bind()`/远程调用时，直接回一个序列化 gadget，就能把「来打你的人」原地反打成命令执行——这是低成本、可长期挂着的反制手段。

## 原理

- **反序列化点在哪**：注册中心返回 lookup 结果时，客户端走 `UnicastRef.invoke` → `StreamRemoteCall.executeCall`，最后 `in.readObject()` 还原返回值；同理客户端调用远程方法后等待返回值时也会 `readObject`。这两处都不对「返回的对象类型」做白名单校验，只要有可用 gadget 就执行。
- **为什么伪造注册中心就够**：`LocateRegistry.getRegistry(host, port)` 拿到的是 `RegistryImpl_Stub`，它只按 JRMP 协议发包，不校验对端到底是不是真的 `RegistryImpl`。任何能按 JRMP 应答 `list`/`bind` 的服务都能骗过客户端。`JRMPListener` 正是这样一个「只讲协议、不讲业务」的恶意端点：收到请求就回托管好的序列化 payload。
- **为什么攻击者反而最容易被反制**：RMI 攻击工具（`RMIRegistryExploit`、各类 RMI 扫描器）在利用前都会先 `registry.list()` 试探连接并判断是否 SSL，这一步就会触发反序列化；而且攻击者为了打别人，自己的 classpath 里往往堆满 gadget（commons-collections 等），一旦被回传 payload 就必然命中。
- **为什么攻击者「来不及拒绝」**：`readObject` 发生在 `executeCall` 内部，与业务返回值的类型无关；即便后续强转失败抛异常，gadget 的 `readObject` 已经执行完毕。
- **另一方向的对称性**：伪装成「RMI 服务端」（用户可控 lookup URL 指向自己的 RMI Registry 并绑定恶意对象，或直接把 JRMPListener 放在被调用端口）效果相同；因为服务端和注册中心通常同机同 JVM，两条路最终都落在「客户端反序列化对方返回的数据」这一处。
- **版本边界**：JDK 8u121 起 JEP290 对注册中心 `bind`/`unbind`/`rebind` 加来源检查，8u231 起 `DGCImpl_Stub#dirty` 加 `ObjectInputFilter`，客户端侧的返回对象反序列化在更高版本上也会受限；因此本手法在「老 JDK + 有 gadget」的存量资产上成功率最高，对新版本要靠本地工厂型 gadget（不出网链）绕。

## 触发条件

- 攻击者/扫描器会主动连你的 1099 或任意伪装端口，并执行 `list()`/`bind()`/远程方法调用（主流 RMI 扫描与利用工具都会）。
- 对端 JDK 允许反序列化其 classpath 内的 gadget（通常只要 classpath 有 commons-collections、c3p0、groovy 等即可）。
- 你需要一个能托管 payload 的 JRMP 端点；网络双向可达（对端能连到你，你能回包）。
- 若要「骗过」自动化工具的存活判断，需让 JRMP 端点对 `list` 正常应答，否则工具可能提前放弃。

## 利用步骤

1. 选端口：`1099` 是 RMI Registry 默认端口，命中率最高；也可以对暴露的 JMX/RMI 高端口逐一伪装（扫描器常按端口段批量探测）。
2. 起恶意端点，指定一条可用 gadget 与命令：`java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 "<命令>"`。
3. 观察是否有连接进来（JRMPListener 会打印收到的调用与序列化交互）；一旦有工具执行 `list()`，payload 随即回传。
4. 大多数工具会在 `list()` 试探阶段被反制；若对方跳过试探直接 `bind()`，同样会在响应阶段反序列化。
5. 对「只探测端口不真正发包」的扫描器无效——它不触发反序列化，只能算存活探测，不能反制。
6. 反制成功后清理：记录对端 IP/时间（用于溯源与上报），不要在本机留 payload 文件与命令历史。

## PoC

```text
# 1) 在 1099 伪装成 RMI 注册中心，托管 CC6 链
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 "calc.exe"

# 2) 对方（扫描器/攻击者）执行任何 RMI 注册中心利用动作，例如：
java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit <你的IP> 1099 CommonsCollections6 whoami
#    第 2 步里的 list() 试探即会收到第 1 步的序列化 payload，命令在对方机器上执行
```

服务端侧只需要「按协议应答」，等价伪代码如下（示意，未在本机执行）：

```java
// 收到任意 JRMP 调用 → 直接写回序列化 gadget（不关心对方请求的方法名）
ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
out.writeObject(gadgetObject);   // 对方 executeCall 内 readObject 触发
out.flush();
```

## 变体与关联

- **变体一**：伪装成「远程服务端」而不是注册中心——诱导攻击者 `lookup` 到你的 Registry，返回 `ReferenceWrapper` 或恶意 Stub，让其在方法调用返回时命中。
- **变体二**：JDK 8u121+ 上 `bind` 被 `checkAccess` 拦住后，攻击链会转向 `lookup`（见关联卡），但「返回对象被反序列化」这一反制面在客户端侧不变。
- **变体三**：JDK 21 的 JNDI 过滤器会拦 `serializedData`，此时改用「异常对象 `ExceptionalReturn`」或本地工厂型 return object 继续反制。
- **关联**：[[web-java-rmi-registry-lookup-checkaccess-jrmp-bypass]]（绕过 checkAccess 打注册中心的正向链，本卡是它的镜像）、[[web-java-rmi-jrmp-exceptional-return-jndi-jdk21-bypass]]（高版本过滤器下的同类「恶意 JRMP 端」用法）、[[web-java-deserialization-jndi-low-version-rmi-ldap-remote-codebase]]（同版本窗内的远程 codebase 类加载）。

## 检测与防御

- **防守方（业务侧）**：不要把 RMI Registry/远程对象端口暴露到公网；对 1099、DGC 随机端口做统一入口 ACL，仅允许跳板机访问。
- **检测**：RMI 端口出现「短连接 + 立即返回大段序列化数据 + 客户端断开」的模式；对同一源 IP 在多个端口尝试 RMI 握手的行为做聚合告警（这类源通常就是扫描器）。
- **升级**：JDK 8u121+/8u231+ 并配置 `jdk.serialFilter` 白名单；移除 classpath 中不必要的 gadget 库。
- **自身安全（做反制时）**：反制端点自身就是高危服务，必须隔离在专用蜜罐网段，禁止挂载生产凭据；JRMPListener 只应监听在受控接口上，避免被反向利用。
