---
id: web-java-deser-fastjson-1249-jsonobject-readobject-checkautotype-reference-bypass
title: Fastjson ≥1.2.49 原生反序列化桥被 JSONObject.readObject→resolveClass 的 checkAutoType 拦截：外层 Map 引用包裹（TC_REFERENCE）与静态 mappings 缓存绕过
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-jsonobject-readobject-resolveclass-checkautotype-reference-bypass
aliases:
- fastjson 1.2.49 原生链拦截
- JSONObject.readObject checkAutoType
- TC_REFERENCE 绕过 resolveClass
- 引用包裹绕 fastjson 黑名单
- 引用类型绕过 resolveClass 安全检查
- 无默认构造方法 build 报错绕过
- TypeUtils.mappings 缓存预热
tags:
- java
- fastjson
- deserialization
- native-deserialization
- resolveclass
- checkautotype
- tcreference
- reference
- blacklist-bypass
- tostring
- templatesimpl
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: fastjson >= 1.2.49（JSONObject.readObject 在 resolveClass 中对目标类做 checkAutoType；引用包裹绕过针对该检查）
verification:
  verified_by: verifier-V676
  verified_at: '2026-11-13T11:58:36+08:00'
  notes: 已对照原文与全部12张截图核对：1.2.49后 JSONObject.readObject→SecureObjectInputStream.resolveClass→checkAutoType 拦截（img03 栈含 JSONObject.java:570、JavaBeanInfo.build 默认构造报错）、TC_REFERENCE/readHandle 不产生类描述符而绕过 resolveClass、外层 Map 先写目标类对象再让桥内以引用出现、静态 TypeUtils.mappings 缓存预热（build 前已入缓存，多次请求）均与原文一致；affected_versions fastjson >= 1.2.49 对应原文『到了1.2.49以后』。dedup：与 web-java-deser-fastjson-badattribute-jsonarray-templatesimpl-native-chain 相关但非同卡——该卡为 1.2.83 JSONArray 完整链，本卡聚焦 1.2.49+ 检查语义、无默认构造 build 报错与缓存预热，dedup_review 理由成立，其余候选仅共享引用绕过/mappings 机制。未验证点：未在本机复跑 PoC；原文未给出该拦截的上限版本与具体 fastjson 小版本差异。
---

## 一句话结论

目标使用 Java 原生反序列化且 classpath 有 fastjson ≥1.2.49 时，把 fastjson `JSONObject`/`JSONArray` 当 toString 桥的原生链（如 `BadAttributeValueExpException(val=JSONObject(TemplatesImpl))`）会先在 `JSONObject.readObject` 内部的 `resolveClass` 里被 `checkAutoType` 拦截（黑名单、无默认构造的 `JavaBeanInfo.build` 报错）；只要让桥内那个目标类对象先在序列化流的外层容器（Map/List/Set）里出现一次、在桥内以 `TC_REFERENCE` 引用出现，反序列化时引用走 `readHandle` 复用已有对象、不再产生类描述符，就完全不经过 `resolveClass`，从而跳过检查。

## 原理

- **桥的位置**：本文所述攻击是原生反序列化链——入口类 `readObject` 触发 `toString()`，`toString()` 落在 fastjson `JSONObject`/`JSONArray` 上，其序列化逻辑（`JSON.toJSONString`）反射调用被包裹对象的 getter（如 `TemplatesImpl.getOutputProperties`、`LdapAttribute.getAttributeDefinition`），从而串到 sink。fastjson 在这里只是"getter 调用器"，不是 `@type` 入口。
- **1.2.49 起的拦截**：fastjson 1.2.49 以后 `JSONObject` 重写了 `readObject`，其内部使用的 `SecureObjectInputStream.resolveClass` 会对流中新出现的**目标类**执行 `ParserConfig.checkAutoType`。调试栈表现为 `ParserConfig.checkAutoType → JSONObject$SecureObjectInputStream.resolveClass(JSONObject.java:570) → ObjectInputStream.readNonProxyDesc/readClassDesc`，异常信息如 `JSONException: default constructor not found. class javax.management.remote.rmi.RMIConnector`。也就是说，即使目标类不在 fastjson 内置黑名单，只要它没有无参构造，`checkAutoType` 内对通过检查的类调用的 `JavaBeanInfo.build(clazz, clazz, ...)` 也会直接抛错，链在解析阶段就断。
- **TC_REFERENCE 为什么能绕过**：`ObjectInputStream.readObject0` 按类型码分派：`TC_OBJECT`/`TC_ARRAY`/`TC_CLASS` 等走 `checkResolve(...)` 最终进入 `resolveClass`；而 `TC_REFERENCE` 直接 `return readHandle(unshared)`，复用句柄表中已恢复的对象，**不产生新的类描述符、不调用 `resolveClass`**。序列化时同一个对象第二次出现会自动写成引用，因此：外层容器里的目标类对象先被恢复（由标准 `ObjectInputStream` 解析，fastjson 的检查看不到它），桥对象内部第二次出现时只是引用，`checkAutoType` 完全没有机会执行。
- **推广**：任何在 `readObject`/`resolveClass` 里加安全检查的类，都可以尝试"先让它以正常类描述符出现一次、后续以引用复用"来跳过检查；前提是**入口 `readObject` 本身**能通过。若入口 `readObject` 也做了黑名单，就要结合二次反序列化（`SignedObject`、`UnicastRef`、JNDI 回包等）把内层裸流送进去，再在内层流里做引用包裹。
- **无默认构造的两种破除**：其一同上，引用包裹直接跳过 `resolveClass`/`build`；其二是利用缓存——`checkAutoType` 开头会先查静态 `TypeUtils.mappings`，命中即直接返回类、不再执行 `build`。类在首次通过黑名单后、`build` 抛错前已经被写入 `mappings`（`TypeUtils.loadClass(..., cache=true)`），所以同一 JVM 内"第一次发 payload 触发 `build` 报错 → 类进入静态缓存 → 第二次发 payload 走缓存提前返回"可以成功。这依赖 `mappings` 是静态变量且服务进程不因单次反序列化异常退出；本地"报错即终止"的单进程 `serialize & unserialize` 测试做不到，多请求的服务器环境"多试几次"即可。

## 触发条件

- 存在可控的 Java 原生反序列化入口，攻击者可控制序列化流。
- classpath 存在 fastjson ≥1.2.49，且链上会反序列化到 `com.alibaba.fastjson.JSONObject`/`JSONArray`（作为入口对象的字段或容器元素）。
- 被包裹的目标类在 fastjson 黑名单中（如 `TemplatesImpl`），或没有无参构造（如 `RMIConnector` 一类），会被 `checkAutoType` 拦下。
- 入口 `readObject` 未拦截所用入口类与桥类；攻击者能把目标类对象放进一个先于桥被恢复的外层容器。
- 纯 JEP 290 的按类名过滤器注意点：引用复用的第二次出现不产生类描述符，按类名的检查同样看不到它；但第一次出现仍会经过过滤器，需要入口侧未拦截该目标类或过滤器不作用于外层容器。

## 利用步骤

1. 选定入口（如 `BadAttributeValueExpException`）、桥（`JSONObject` 或 `JSONArray`）、sink（如 `TemplatesImpl.getOutputProperties`）。
2. 构造对象图：`bridge.put("g", tpl)`；把 `bridge` 设进入口对象（如反射写 `BadAttributeValueExpException.val`）。
3. 关键一步：把同一个 `tpl` 对象先放进外层 `HashMap` 的 key（或 List/Set 等），value 放入入口对象；序列化时 `tpl` 第一次出现写完整类描述符，桥内第二次出现自动写 `TC_REFERENCE`。
4. 发送序列化流：外层 `HashMap.readObject` 先用标准 `resolveClass` 恢复 `tpl`，随后入口 `readObject→toString→JSONObject` 时引用直接命中缓存对象。
5. 桥的 `toString` 反射调用 `tpl.getOutputProperties()`，加载 `_bytecodes` 执行；无默认构造的目标类同样因引用包裹跳过 `build`，或改用两次请求的静态缓存预热法。

## PoC

```java
Object tpl = ...; // 目标类对象，如填好 _bytecodes 的 TemplatesImpl
JSONObject bridge = new JSONObject();
bridge.put("g", tpl);

BadAttributeValueExpException poc = new BadAttributeValueExpException(null);
Field val = BadAttributeValueExpException.class.getDeclaredField("val");
val.setAccessible(true);
val.set(poc, bridge);

HashMap<Object, Object> outer = new HashMap<>();
outer.put(tpl, poc); // tpl 先出现；桥内的同一对象被写成 TC_REFERENCE
serialize(outer);
// 原文测试模板，未在本机复跑
```

## 变体与关联

- [[web-java-deser-fastjson-badattribute-jsonarray-templatesimpl-native-chain]]：`JSONArray` 桥 + BAVE + `TemplatesImpl` 的完整原生链，已验证该链必须把 Template 放在 HashMap key 先出现才有 TC_REFERENCE 复用；本卡补的是 1.2.49 检查语义、无默认构造限制与通用绕过边界。
- [[web-java-deser-fastjson-xstring-hotswappable-tostring-waf-bypass]]：HSTS+`XString.equals` 入口 + JSONArray 引用包裹穿自定义 `resolveClass` 黑名单，与本卡同属"引用复用不触发 resolveClass"的手法，但对抗的是业务 WAF 名单而非 fastjson 自身检查。
- 变体：外层容器可为 `Map`/`List`/`Set`；目标类对象放在任何先于桥恢复的位置均可；入口 readObject 自身也做黑名单时，叠加 `SignedObject` 等二次反序列化。
- 边界：fastjson 开启 SafeMode、目标类既不在白名单也不在缓存且引用包裹未生效时链断；引用包裹只能救"桥内目标类"的检查，救不了入口类被黑名单拦截。

## 检测与防御

- 检测：序列化流中同时出现 `com.alibaba.fastjson.JSONObject`/`JSONArray` 与 `TemplatesImpl`/`JdbcRowSetImpl`/`LdapAttribute` 等组合；流中同一对象重复出现（引用写回）；`checkAutoType` 告警后紧接 `readHandle` 复用对象的行为；异常日志中的 `default constructor not found` 与 `JSONObject.java:570` 附近栈帧。
- 防御：JEP 290 对象图白名单（不要只按类名过滤，引用复用可绕过"新类描述符"检查）；移除不需要的 fastjson 或升级并保持 SafeMode；限制 `JSONObject` 出现在原生序列化流中的可能；对 `TemplatesImpl`/`JdbcRowSetImpl`/`LdapAttribute` 等 sink 类单独封禁；关注反序列化异常日志中的 build/checkAutoType 报错（它可能是攻击者的第一发缓存预热）。
