---
id: web-java-deser-hessian-typed-map-jsonobject-wrap-tostring
title: Hessian2 类型化 Map 打 Hutool JSONObject：put→JSONUtil.wrap 对 JDK 类调 toString，AtomicReference 适配 POJONode 形成任意 getter 触发
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian2-typed-map-jsonobject-jsonutil-wrap-tostring
aliases:
- Hessian2 writeMapBegin JSONObject
- MapDeserializer 任意 Map 实例化
- Hutool JSONUtil.wrap JDK 类 toString
- AtomicReference toString 适配器
- Hessian 触发 POJONode
- JSONObject.put 触发 toString
tags:
- java
- hessian
- deserialization
- hutool
- jsonobject
- tostring
- gadget
- jackson
- pojonode
- getter
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V461
  verified_at: '2026-11-10T14:16:01+08:00'
  notes: 已对照原文与 37 张图片核对：writeMapBegin(type) tag=77+writeType 编码、MapDeserializer 按类型名 newInstance 后 doReadMap 调用 map.put、JSONObject.put→set→JSONUtil.wrap 的 JDK 类 toString 分支、AtomicReference.toString→String.valueOf(get)→POJONode.toString→Jackson BeanPropertyWriter getter、JDK17 需 --add-opens java.base/java.util.concurrent.atomic 均与原文/截图一致；依赖版本 hessian-lite 3.2.13/hutool 5.8.16/h2 2.2.224 属题目构建环境，未填 affected_versions 正确。未验证点：未本地执行 payload。dup-scan.json 早于建卡且无本篇 pair；dedup 判定 new（最高候选 ConcurrentHashMap/MapEntry 卡为不同触发路径），成立。
---

## 一句话结论

目标用 Hessian2（如 hessian-lite）反序列化攻击者可控数据、且 classpath 含 Hutool 与 Jackson 时，可把 Hessian2 map 的类型名写成 `cn.hutool.json.JSONObject`：`MapDeserializer` 会按该类型名用无参构造实例化 Map 并逐对 `map.put()`，`JSONObject.put→set→JSONUtil.wrap` 对 JDK 类直接调用 `toString()`；把 map value 设为 `AtomicReference<POJONode>`，即由 `AtomicReference.toString→String.valueOf(get())` 把调用引到 `POJONode.toString`，再进入 Jackson 的 Bean 序列化调用任意 getter，接 JDBC 等 sink 即可 RCE。

## 原理

- **Hessian2 的类型化 map 编码**：`Hessian2Output.writeMapBegin(type)` 在 type 非空时先写 tag `77`，再 `writeType(type)`——首次出现的类型名以字符串写入（长度字节 + 类名），重复出现的类型只写类型引用；`Hessian2Input.readObject` 遇到 `77` 时 `readType()` 取回类型名，交 `SerializerFactory.readMap(in, type)`。因此 map 的具体实现类由攻击者在字节流里指定。
- **任意 Map 类实例化 + put 触发**：`SerializerFactory.getDeserializer(type)` 按类名加载并返回 `MapDeserializer`；`MapDeserializer.readMap` 在 `_type` 为 `null` 或 `Map.class` 时用 `HashMap`、`SortedMap.class` 时用 `TreeMap`，其余情况直接 `(Map) this._ctor.newInstance()`——即用目标类的无参构造。随后 `doReadMap` 循环执行 `map.put(in.readObject(), in.readObject())`，触发的是攻击者选定 Map 类的 `put` 实现，而不是 `HashMap` 的哈希/比较逻辑。
- **Hutool JSONObject.put 的副作用**：`cn.hutool.json.JSONObject.put` 委托给 `set(key, value)`，后者调用 `JSONUtil.wrap(InternalJSONUtil.testValidity(value), config)`。`JSONUtil.wrap` 对非 JSON/字符串/数字/容器对象走分支：若 `ClassUtil.isJdkClass(object.getClass())` 为真，直接 `object.toString()`；否则 `new JSONObject(object, config)`（按 getter 构建）。也就是说，把 value 设为 JDK 类即可让反序列化阶段的 `put` 调用其 `toString()`。
- **AtomicReference 作 toString 适配器**：`AtomicReference` 是 JDK 类，`toString()` 实现为 `String.valueOf(get())`；把要触发的对象（原文为 Jackson `POJONode`）放进 `AtomicReference`，`JSONUtil.wrap` 调用 `AtomicReference.toString()` 后会经 `String.valueOf` 反射到该对象的 `toString()`。这样即使目标对象不是 JDK 类，也能被 wrap 的 JDK 分支带进 toString。
- **POJONode.toString 到任意 getter**：Jackson 的 `POJONode.toString()` 会把内部对象当普通 Bean 交给序列化器，`BeanSerializerBase.serializeFields → BeanPropertyWriter.serializeAsField` 反射调用对象全部 public getter。等价于“以攻击者选定的对象为 this 调用任意无参 getter”；getter 里若存在 JDBC 建连、二次反序列化、模板/上下文加载等动作即落到 RCE。
- **与直接把 POJONode 作为 value 的差异**：`POJONode` 不是 JDK 类，`JSONUtil.wrap` 会走 `new JSONObject(object)` 分支并在这一步就按 getter 序列化，触发时机与字段状态都不可控；用 `AtomicReference` 包一层既满足 wrap 的 JDK 分支，又让 Hessian 按普通对象字段写入 POJONode。
- **版本与 JDK17 边界**：原文测试依赖 hessian-lite 3.2.13、hutool-all 5.8.16、jackson-databind（POJONode）。JDK17 下 hessian 反射读写 `AtomicReference.value` 需要 `--add-opens java.base/java.util.concurrent.atomic=ALL-UNNAMED`，原文实测只有加上该参数 payload 才能完成触发；目标若缺少该访问权限或 hessian 版本不依赖该反射，表现会不同。

## 触发条件

- 目标使用 Hessian2（hessian-lite/原生 hessian）反序列化攻击者可控数据（HessianServlet、Dubbo 等 RPC 入口），攻击者能构造带类型名的 map 字节流。
- classpath 含 `hutool-json`（`cn.hutool.json.JSONObject`/`JSONUtil`）与 `jackson-databind`（`com.fasterxml.jackson.databind.node.POJONode`），且存在可接的 getter sink（JDBC 建连、二次反序列化等）。
- Hessian 入口未启用类型白名单，或白名单未覆盖 JSONObject/AtomicReference/POJONode。
- JDK17 环境下需要对应的 `--add-opens java.base/java.util.concurrent.atomic=ALL-UNNAMED`（原文实测条件）；JDK8 环境无此限制。
- 仅限授权测试。

## 利用步骤

1. 准备 getter sink 对象与其触发对象图（如 Hutool `PooledDSFactory` + `Setting.url` 指向 H2 `init=runscript from 'http://...'`；或二次原生反序列化 payload）。
2. 用 Jackson `POJONode` 包裹该对象；如需在 getter 里完成二次原生反序列化，可把子 payload 序列化进业务 Bean 字段，让 Bean 的 getter 返回还原后的 sink 对象。
3. 组 Hessian2 流：`writeMapBegin(JSONObject.class.getName())`，写一个任意 key，再 `writeObject(new AtomicReference<>(pojoNode))`，最后 `writeMapEnd()`。
4. 发送字节流；服务端 `MapDeserializer` 实例化 `JSONObject`，`put` 触发 `JSONUtil.wrap → AtomicReference.toString → POJONode.toString → Jackson getter`。
5. getter 链触发 sink（如 H2 建连执行远程 SQL），完成命令执行；无回显时按 sink 选择外带或写文件。

## PoC

原文 PoC 的最小骨架（sink/Bean 构造略，完整链见关联卡）：

```java
ByteArrayOutputStream baos = new ByteArrayOutputStream();
Hessian2Output out = new Hessian2Output(baos);

out.writeMapBegin(JSONObject.class.getName());   // 类型名决定 MapDeserializer 实例化的 Map 类
out.writeObject("whatever");                     // key
POJONode node = new POJONode(bean);              // bean 的 getter 接 sink
out.writeObject(new AtomicReference<>(node));    // value：JDK 类，触发 JSONUtil.wrap 的 toString 分支
out.writeMapEnd();
out.close();

byte[] payload = baos.toByteArray();
// 服务端等价触发：
// new Hessian2Input(new ByteArrayInputStream(payload)).readObject();
```

原文在本地用该结构配合 Hutool PooledDSFactory/自定义 H2DataSource 成功弹出计算器；sink 侧细节见关联卡。

## 变体与关联

- **value 换形**：任何 JDK 类只要 `toString` 有可利用副作用都可直接作为 value；需要触发非 JDK 对象的 `toString` 时用 `AtomicReference`（或其它 JDK 容器）做适配层。
- **Map 类换形**：CodeQL 在 Hutool 中可枚举到 `JSONObject`、`MapWrapper`、`BiMap`、`MapProxy` 等 `put` 有额外逻辑的 Map 实现；只要有无参构造且 `put` 会走到可控逻辑即可替换。
- **与 map.put 哈希入口的区别**：[[web-java-deser-hessian-deserialization-entry-map-put]] 利用的是 `HashMap/TreeMap.put` 调 key 的 `hashCode/equals/compareTo`；本卡利用的是“类型化 map 的 `put` 方法本身”，触发点更靠前且不依赖 key 的行为。
- **与协议错误触发 toString 的区别**：[[web-java-deser-hessian2-protocol-error-tostring-trigger]] 用错位字节让 `expect()` 拼接异常信息时调 `toString`；本卡走正常反序列化路径，隐蔽性更好，但需要 Hutool/Jackson 依赖。
- **sink 关联**：[[web-java-deser-hutool-pooleddsfactory-getdatasource-h2-runscript]]（PooledDSFactory → H2 INIT RUNSCRIPT）、[[web-java-deser-any-getter-jooq-convert-newinstance-spring-xml]]（POJONode 任意 getter → jOOQ → ClassPathXmlApplicationContext 远程 XML）、[[jackson-native-deserialization-getter-tostring-templates-rce]]（POJONode → TemplatesImpl）、[[web-java-deserialization-jdk-eventlistenerlist-tostring]]（另一条 JDK17 toString 触发链）。

## 检测与防御

- **入口控制**：不要反序列化不可信 Hessian 数据；自定义 `SerializerFactory` 做类名允许列表，拒绝 `cn.hutool.*`、`com.fasterxml.jackson.databind.node.*`、`java.util.concurrent.atomic.AtomicReference` 等非业务类型；限制匿名访问 HessianServlet/RPC。
- **依赖治理**：移除不必要的 hutool-json/jackson 节点类；启用 JEP 290 全局过滤器；JDK17 最小化 `--add-opens`（但不能只依赖强封装，hessian 也可能走 Unsafe）。
- **流量检测**：Hessian 流中出现类型名 `cn.hutool.json.JSONObject`、`AtomicReference`、`POJONode`；`JSONObject.put → JSONUtil.wrap → toString` 的异常栈；随后 JVM 对外发起 JDBC/HTTP 连接或加载远程资源。
- **应急**：发现利用迹象时隔离实例，抓取线程栈与出站连接，排查 classpath 中 hutool/jackson 的使用面并升级/隔离。
