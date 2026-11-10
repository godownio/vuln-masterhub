---
id: web-java-rmi-registry-bind-rebind-deserialization
title: RMI Registry 的 bind/rebind 分支直接 readObject：用 ysoserial RMIRegistryExploit 打 1099 拿 RCE
type: scenario
domain: web
path: web/java/rmi
technique: rmi-registry-bind-rebind-deserialization
aliases:
- RMIRegistryExploit 打注册中心
- bind 反序列化
- rebind 反序列化
- RMI 1099 打点
- RegistryImpl_Skel 反序列化
tags:
- java
- rmi
- jrmp
- deserialization
- registry
- ysoserial
- rce
cve: []
severity: critical
confidence: medium
affected_versions: JDK 8u121 之前（JEP290 前 bind/rebind/unbind 无来源校验；原文明示该窗口可直接利用）
status: draft
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4
  verified_at: '2026-11-08T20:50:59+08:00'
  notes: 已对照原文核对；本次核对未读取图片；主要问题：版本边界与原文不符——卡片写「JDK 8u121 之前 / 8u121 起 JEP290 给 bind/rebind/unbind 加 checkAccess」，但本篇正文对 bind 链未给任何受影响版本，其出现的 8u121 只用于「useCodebaseOnly 自 6u45/7u21/8u121 起默认 true」与 dynamic-codebase 两条场景的利用条件；而同一系列另一篇原文明确写 checkAccess 自 8u141 才加入 RegistryImpl（8u121 只是 JEP290 序列化过滤上线）。请作者按原文改写 affected_versions 与「边界」段（去掉「原文明示」这类无正文支撑的表述），其余 bind/rebind 分支 readObject 原理、createMemoitizedProxy 包装、RMIRegistryExploit 用法与正文一致。
---

## 一句话结论

`RegistryImpl_Skel#dispatch` 的 `bind`(0)、`rebind`(3)、`unbind`(4) 三个分支都是「先从请求流 `readObject()`、再调用业务方法」，而 JEP290 之前的 JDK 对这些操作没有任何来源校验；因此只要能连上 1099，用 ysoserial 的 `RMIRegistryExploit` 把 gadget 包装成 `Remote` 实参 bind 上去，注册中心进程就会反序列化并执行命令——这是最常见、成本最低的 RMI 打点方式。

## 原理

- 注册中心本身是个 RMI 远程对象（`RegistryImpl`），客户端每次调用都走 `RegistryImpl_Stub` 的 JRMP 请求；服务端 `RegistryImpl_Skel.dispatch` 用 `var3`（方法号）分派：0 bind、1 list、2 lookup、3 rebind、4 unbind。
- `bind`/`rebind` 分支的代码是 `var7=(String)in.readObject(); var8=(Remote)in.readObject();`，第二个 `readObject` 直接还原攻击者提供的对象树。类型是 `Remote` 也没关系：gadget 的 `readObject` 在强转之前就执行了，即便随后抛异常，命令已经跑完。
- 为什么不需要知道任何凭据：RMI 注册中心默认无认证，只要 TCP 可达即可调用；`LocateRegistry.getRegistry(host, port)` 唯一需要的输入就是地址。
- 为什么要用 `Gadgets.createMemoitizedProxy(Gadgets.createMap(name,payload), Remote.class)` 包一层：注册中心签名要求第二个参数类型是 `Remote`，用动态代理把承载 payload 的 Map 包成 `Remote` 才能通过编译期/序列化期的类型检查，同时保证 payload 在服务端反序列化时才展开。
- 为什么先 `registry.list()`：攻击工具用它确认「目标确实是 RMI Registry 且能正常应答」，并在 `ConnectIOException` 时切换 SSL 传输；这一步还顺带确认了目标不是别的服务。
- 边界：JDK 8u121 起 JEP290 给 `bind`/`unbind`/`rebind` 加了 `checkAccess`（只允许本机来源），这条链在 8u121+ 直接失效，需要改用 `lookup` 分支的绕过手法或恶意 JRMP 端反制。

## 触发条件

- 目标暴露 RMI Registry 端口（默认 1099，或 JMX/RMI 自定义端口）。
- JDK 为 8u121 之前的版本（无 JEP290 来源校验），且注册中心进程 classpath 存在可用 gadget（commons-collections 等）。
- 攻击机能直连该端口；若注册中心启用了 SSL 传输，工具需支持 TLS（`RMIRegistryExploit` 自带 trust-all 的 SSL socket factory）。

## 利用步骤

1. 端口探测确认 1099 开放，并识别服务（RMI 握手特征 `JRMI` 魔数）。
2. 选 gadget：先按目标可能存在的依赖选链（`CommonsCollections1`~`7`、`CommonsBeanutils1` 等），JDK 版本会影响可用性（原文提到 1.8 下 CC1 不可用、改用 CC5/CC6）。
3. 执行 `RMIRegistryExploit` 打点；工具内部先 `list()` 试探，再构造 `Remote` 代理并 `bind`。
4. 观察命令是否执行；若报 `ConnectIOException`，说明服务端用 SSL，工具会自动切换并重试。
5. 若 `bind` 失败但能 `list`，说明目标已在 8u121+（被 `checkAccess` 拦），转 `lookup` 绕过路线或改用伪造注册中心反制。

## PoC

```text
# 1) 确认端口与服务
nmap -p 1099 --script rmi-dumpregistry <target>

# 2) 直接打注册中心（bind 分支反序列化）
java -cp ysoserial.jar ysoserial.exploit.RMIRegistryExploit <target> 1099 CommonsCollections6 "<命令>"
```

工具关键逻辑（说明为什么能过类型检查）：

```java
Object payload = payloadObj.getObject(command);
String name = "pwned" + System.nanoTime();
Remote remote = Gadgets.createMemoitizedProxy(Gadgets.createMap(name, payload), Remote.class);
registry.bind(name, remote);   // 第二个实参在服务端 readObject 时展开
```

## 变体与关联

- **变体一**：`rebind` 分支与 `bind` 结构完全相同，`bind` 因重名失败时用 `rebind`。
- **变体二**：JDK 8u121+ 被 `checkAccess` 拦截后，改打 `lookup`（该分支不检查来源，但参数是 `String`，需要自实现调用，见关联卡）。
- **变体三**：`DGC`（`DGCImpl_Skel.dirty`）与 `Activation` 也能被直接反序列化，是 1099 之外的平行入口。
- **关联**：[[web-java-rmi-registry-lookup-checkaccess-jrmp-bypass]]（同一条注册中心攻击链，但走 `lookup` 分支绕 `checkAccess`，适用于 8u141~8u231）、[[web-java-rmi-jrmp-listener-fake-registry-scanner-counterattack]]（同样是 `list()`/`bind()` 交互，但角色对调成反制）、[[web-java-deserialization-jndi-low-version-rmi-ldap-remote-codebase]]（同版本窗内的另一条远程类加载路线）。

## 检测与防御

- **暴露面**：RMI Registry/DGC/Activation 端口一律不对外，仅跳板机可达；JMX 走认证 + SSL。
- **升级**：8u121+ 打开 JEP290，8u231+ 配合 `jdk.serialFilter` 白名单，可同时挡住 bind 与 JRMP 回连两条路。
- **检测**：单次连接内出现「`list()` 后紧接 `bind`/`rebind` 且参数为动态代理对象」的 JRMP 流量；注册中心进程内出现 `RegistryImpl_Skel.dispatch` → gadget 类 `readObject` 的调用栈。
- **加固**：移除 classpath 中的 commons-collections 等 gadget 库；对必须保留的 RMI 服务做接口白名单（只允许 `list`/`lookup`）。
