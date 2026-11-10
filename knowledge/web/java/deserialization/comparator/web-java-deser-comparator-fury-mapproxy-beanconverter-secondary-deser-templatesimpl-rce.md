---
id: web-java-deser-comparator-fury-mapproxy-beanconverter-secondary-deser-templatesimpl-rce
title: Fury 反序列化黑名单绕过：feilong PropertyComparator + PriorityQueue 触发 getter → Hutool MapProxy/BeanConverter 二次反序列化 → TemplatesImpl RCE
type: scenario
domain: web
path: web/java/deserialization/comparator
technique: fury-propertycomparator-mapproxy-secondary-deserialization-rce
aliases:
- Fury 二次反序列化 RCE
- PropertyComparator 触发 getter
- Hutool MapProxy 动态代理桥
- Dialect getWrapper
- BeanConverter ObjectUtil.deserialize
- 反序列化黑名单二次反序列化绕过
tags:
- java
- deserialization
- fury
- blacklist-bypass
- secondary-deserialization
- comparator
- priorityqueue
- hutool
- mapproxy
- beanconverter
- templatesimpl
- getter
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T1-1
  verified_at: '2026-11-07T21:36:24+08:00'
  notes: 已对照原文与 33 张图片逐张核对：Fury requireClassRegistration(false) 入口、PropertyComparator/PriorityQueue 触发 getter、MapProxy.invoke→Convert→BeanConverter→ObjectUtil.deserialize 二次反序列化、Dialect.getWrapper/BeanUtil.isBean 条件、spring 分支 BeanOperationException 坑、TemplatesImpl 二阶段、img32 弹计算器与 img33 /tmp/desc.txt 回显均与 content.md 一致；完整打通 RCE（有最终危害），不属 DoS/未打通/理论链；路径合法，dedup 非同链、dup-scan 无 pair；未验证点：未在本机编译运行 payload，该批次卡按 KB 现状不含 sources/source_url 溯源字段。
---

## 一句话结论

当应用用 Apache Fury 反序列化不可信数据、关闭类注册（`requireClassRegistration(false)`）并只做类名黑名单时，可用 `PriorityQueue` + feilong `PropertyComparator("wrapper")` 在反序列化重建队列阶段触发元素的 `getWrapper()` getter；元素换成 Hutool `MapProxy` 动态代理后，`MapProxy.invoke` 把 `HashMap` 里的 `byte[]` 交给 `Convert.convert`，因返回类型是 Bean 且不在默认 converter 表而落到 `BeanConverter.convertInternal`，其 `ObjectUtil.deserialize((byte[])value)` 对内层字节做第二次 Java 原生反序列化，从而绕过外层黑名单执行 `TemplatesImpl` 等任意原生 gadget 拿到 RCE。

## 原理

- **入口信任边界**：HTTP 服务接收 `data` 参数，Base64 解码后交给 `Fury.builder().withLanguage(Language.JAVA).requireClassRegistration(false).build().deserialize(...)`，随后调用 `deserialize.toString()`。关闭类注册后 Fury 可还原 classpath 内任意类，且未实现 `Serializable` 的类也能参与反序列化；服务端维护一份很长的类名黑名单（TemplatesImpl、TrAXFilter、CC 链、JNDI、javax 等常见 gadget 被禁），因此不能直接用经典 gadget。
- **绕过思路**：不碰被禁类，改用黑名单外的第三方库类搭桥（feilong、hutool）。一阶段对象图里只出现 PriorityQueue、PropertyComparator、动态代理接口、MapProxy、HashMap；真正有害的 gadget 放在二阶段字节里，二阶段走原生 `ObjectInputStream`，不再受 Fury 黑名单约束。
- **一阶段触发**：`PriorityQueue(2, new PropertyComparator("wrapper"))`。Fury 的 `CollectionSerializer` 重建队列时调用 comparator 的 `compare`；feilong `PropertyComparator.compare` 用 `PropertyUtil.getProperty(t1, propertyName)` 取属性，等价于对元素调用 `getWrapper()`（getter 触发）。坑点：feilong 的 `PropertyValueObtainer.obtain` 会经 `PropertyDescriptorUtil.isUseSpringOperate` 检查 spring 依赖——classpath 存在 SpringBeanUtils 时走 `getDataUseSpring`（易抛 `BeanOperationException`），无 spring 时走 `getDataUseApache`（与 commons-beanutils CB/Shiro 链同构）；payload 构造环境不能引入 spring 依赖。
- **动态代理桥**：元素不是普通 Bean，而是 `Proxy.newProxyInstance` 生成的黑名单外接口代理，`InvocationHandler` 是 Hutool `MapProxy`（包装一个 HashMap）。`MapProxy.invoke` 对「无参、返回类型非 void」的方法：从方法名截 `fieldName`（`get` 前缀去 3 并首字母小写、`is` 前缀去 2），`hashCode`/`toString` 直接返回；然后执行 `Convert.convert(method.getGenericReturnType(), get(fieldName))`——把 map 中 key=`fieldName` 的值（攻击者放的 `byte[]`）按接口方法的返回类型转换。
- **类型转换落到二次反序列化**：`Convert.convert` 先查 `ConverterRegistry.getConverter(type)`；若返回类型命中默认 converter（例：`ICaptcha.getCode()` 返回 `String` → `StringConverter`），不会进入 BeanConverter。必须选一个返回类型 `T` 满足：① 不在 `defaultConverterMap` 中（`getConverter` 返回 null）；② `BeanUtil.isBean(T)` 为真（`hasSetter || hasPublicField`）。此时走 `new BeanConverter<>(type).convert(value, defaultValue)`，`BeanConverter.convertInternal` 中 `if (value instanceof byte[]) return (T) ObjectUtil.deserialize((byte[]) value, new Class[0])` → `SerializeUtil.deserialize` → `ObjectInputStream.readObject`，对内层字节做二次反序列化。`cn.hutool.db.dialect.Dialect.getWrapper()`（`Wrapper getWrapper()` + `void setWrapper(Wrapper)`）正是满足条件的 getter，fieldName 为 `wrapper`。
- **二阶段 RCE**：内层字节是原生反序列化 gadget —— `TemplatesImpl`（`_bytecodes` 注入恶意类字节码、`_name`、`_tfactory`）+ `PropertyComparator("outputProperties")` + `PriorityQueue`（CB 链同构）→ `getOutputProperties()` → `newTransformer()` → 定义并执行恶意类字节码 → 任意命令执行。
- **为什么成立**：Fury 的过滤只作用于一阶段类解析；`MapProxy` 的类型转换把「受控 byte[]」变成「不受限的原生反序列化」，等价于把黑名单边界整个绕开，二阶段可复用全部经典 Java gadget。

## 触发条件

- 目标用 Fury 反序列化不可信数据且 `requireClassRegistration(false)`；存在类黑名单但未覆盖 feilong / hutool 桥接类。
- classpath 含 feilong（`PropertyComparator`/`PropertyUtil`/`PropertyValueObtainer`）、hutool（`MapProxy`/`Convert`/`ConverterRegistry`/`BeanConverter`/`ObjectUtil`）、JDK `TemplatesImpl`（或等价原生 gadget）。
- 黑名单外存在可用接口：其无参 getter 以 `get`/`is` 开头、返回非 void，返回类型是 Bean（有 setter 或 public 字段）且**不在** hutool 默认 `ConverterRegistry` 中（如 `Dialect.getWrapper()`）。
- 构造 payload 的环境 classpath 不含 spring（否则 PropertyComparator 走 spring 分支报错）。
- 内层 payload 未被 JEP 290 / 其它过滤器拦截；服务端能读取命令回显文件（如 `/tmp/desc.txt`）。

## 利用步骤

1. 构造二阶段原生 gadget：`TemplatesImpl` 注入 `_bytecodes`/`_name`/`_tfactory`，配 `PropertyComparator("outputProperties")` 与 `PriorityQueue(2, comparator)`，反射置 `size=2`、`queue=[t,t]`，`ObjectUtil.serialize` 成 `byte[] decode`。
2. `HashMap` 放 `("wrapper", decode)`，用 `MapProxy` 包装：`MapProxy mp = new MapProxy(map)`。
3. `Proxy.newProxyInstance` 生成两个 `Dialect` 接口代理，handler 都是该 `MapProxy`。
4. 构造一阶段 `PriorityQueue(2, new PropertyComparator("wrapper"))`，反射置 `size=2`、`queue=[proxy1, proxy2]`。
5. 用 `Fury.builder().withLanguage(Language.JAVA).requireClassRegistration(false).build().serialize(q)` 序列化，Base64 后作为 `data` 提交。
6. 服务端：`fury.deserialize` → 重建 PriorityQueue → `compare` → `getProperty("wrapper")` → `Dialect.getWrapper()` → `MapProxy.invoke` → `Convert.convert(Wrapper, byte[])` → `BeanConverter` → `ObjectUtil.deserialize` → 二阶段 `TemplatesImpl` RCE。
7. 把命令结果写入服务端可回显文件，再以不带 `data` 的请求读取结果。

## PoC

```java
// 二阶段：TemplatesImpl + PropertyComparator("outputProperties") + PriorityQueue
Object t = /* TemplatesImpl: _bytecodes=恶意类, _name="_", _tfactory=new TransformerFactoryImpl() */;
PriorityQueue inner = new PriorityQueue(2, new PropertyComparator("outputProperties"));
set(inner, "size", 2); set(inner, "queue", new Object[]{t, t});
byte[] decode = ObjectUtil.serialize(inner);

// 桥：HashMap(wrapper -> 二阶段字节) + MapProxy + Dialect 动态代理
HashMap map = new HashMap(); map.put("wrapper", decode);
MapProxy mp = new MapProxy(map);
Dialect d1 = (Dialect) Proxy.newProxyInstance(Dialect.class.getClassLoader(), new Class[]{Dialect.class}, mp);
Dialect d2 = (Dialect) Proxy.newProxyInstance(Dialect.class.getClassLoader(), new Class[]{Dialect.class}, mp);

// 一阶段：PriorityQueue + PropertyComparator("wrapper")
PriorityQueue q = new PriorityQueue(2, new PropertyComparator("wrapper"));
set(q, "size", 2); set(q, "queue", new Object[]{d1, d2});

Fury fury = Fury.builder().withLanguage(Language.JAVA).requireClassRegistration(false).build();
String poc = Base64.getEncoder().encodeToString(fury.serialize(q));  // 提交为 data
// set(...) 为反射写私有字段的辅助方法
```

（按文章 PoC 最小化整理，未在本机编译运行；`set` 为反射置字段。）

## 变体与关联

- 变体：任何「无参 getter、返回类型是 Bean 且不在默认 converter 表」的黑名单外接口都可替代 `Dialect.getWrapper()`；可用 CodeQL 查 `get%`/`is%` + 对应 setter/public field 批量筛选（见关联方法卡）。
- 变体：二阶段可换任意原生 gadget（CC 链、JNDI 等）；本题无 tomcat 依赖且 JDK 版本未知，故弃用 JNDI sink。`ReflectUtil.newInstance` 任意构造函数是另一候选 sink，但目标 `TrAXFilter` 在黑名单里。
- 变体：feilong `BasicDynaClass.newInstance`（CC3 式任意构造）路线同样因 TrAXFilter 被黑名单封锁而放弃。
- 关联：[[web-java-deser-resolveproxyclass-blacklist-hutool-mapproxy]]（同一 `MapProxy→Convert→BeanConverter→ObjectUtil.deserialize` 二次反序列化桥，但入口是 `ObjectInputStream` 的 `resolveProxyClass` 漏拦 + Guava/Vaadin 触发 `getBounds`）、[[web-java-deser-fury-priorityqueue-aspectj-jre-jar-write-rce]]、[[web-java-deser-fury-usingtostring-datastore-ioUtils-secondary-deser]]（同一 Fury 入口的另外两种解法：写 JRE jar、UsingToStringOrdering/DataStore 桥）、[[code-analysis-vuln-discovery-codeql-java-gadget-chain-mining]]（挖掘方法）。
- 坑：最初在 payload 里用了自带 spring 依赖的辅助 Util 类，触发 `PropertyValueObtainer` 的 spring 分支抛 `BeanOperationException: getProperty exception`；去掉该依赖、改用纯 Fury 序列化后打通（实测弹出计算器）。

## 检测与防御

- Fury 配置：不可信输入必须 `requireClassRegistration(true)` 并维护类白名单；黑名单要覆盖实际 classpath 中的第三方桥接类（feilong、hutool），不能只列常见 gadget。
- 序列化防护：对应用内所有 `ObjectInputStream.readObject` 入口（含 hutool `ObjectUtil.deserialize`/`SerializeUtil`/`IoUtil.readObj` 等二次反序列化点）部署 JEP 290 `ObjectInputFilter` 全图限制；监控同一请求链出现两次反序列化。
- 依赖治理：移除不必要的 feilong/hutool 反序列化可达类；审计 `MapProxy`、`Convert`、`BeanConverter` 的类型转换路径。
- 检测：Fury 请求中出现 `PriorityQueue`/`PropertyComparator`/`MapProxy`/动态代理接口/`BeanConverter` 类描述；反序列化后紧接 `ObjectInputStream.readObject` 或二次反序列化调用；`TemplatesImpl` 类加载与子进程/命令执行；写文件回显行为。
