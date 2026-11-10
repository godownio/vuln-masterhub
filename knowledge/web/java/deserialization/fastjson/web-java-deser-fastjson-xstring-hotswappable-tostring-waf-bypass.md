---
id: web-java-deser-fastjson-xstring-hotswappable-tostring-waf-bypass
title: Fastjson 高版本原生链被 resolveClass 黑名单封掉 BadAttributeValueExpException 后，改用 HashMap+HotSwappableTargetSource→XString.equals 触发 toString，并用 JSONArray 引用包裹穿过类名检查
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-native-deser-xstring-hotswappable-tostring-resolveclass-blacklist
aliases:
- HotSwappableTargetSource XString 触发 toString
- 替换 BadAttributeValueExpException 的触发链
- 高版本 fastjson 原生反序列化绕过
- resolveClass 黑名单绕过 JSONArray 引用
- HashMap equals 触发 JSONArray.toString
tags:
- java
- fastjson
- deserialization
- gadget
- tostring
- xstring
- spring-aop
- hotswappabletargetsource
- resolveclass
- waf-bypass
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:35:24+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。resolveClass 双重限制(User 子类+禁 BAVE)、User.info 承载 gadget、HashMap→HotSwappableTargetSource.equals→XString.equals→JSONArray.toString→TemplatesImpl 与 javassist 降版本 49 PoC 均与正文一致；dedup 最高外部候选为通用 XString 触发原语卡，非同链。未验证点：引用包裹说明源自作者注释(绕过 fastjson 高版本 resolveClass 黑名单)，卡片表述为包名黑名单略宽泛；PoC 未执行。
---

## 一句话结论

当目标（或题目 WAF）在自定义 `ObjectInputStream.resolveClass` 里直接 ban 掉 `BadAttributeValueExpException`、并要求第一个反序列化的类必须是某个业务类（如 `User`）的子类时，fastjson 的原生链仍有替代触发点：用 `HashMap` 反序列化时的 key 相等性比较走 `HotSwappableTargetSource.equals → XString.equals(恶意对象) → obj.toString()`，把 `JSONArray` 作为被比较对象即可进入 `JSONArray.toJSONString` 的 getter 调用，最终落到 `TemplatesImpl`；`JSONArray` 成员与 `HashMap` key 通过序列化引用（TC_REFERENCE）复用同一对象，从而只让 WAF 看到被允许的类名。

## 原理

- **原生链的公共骨架**：任意 `readObject` 触发点 → 某对象的 `toString()` → fastjson `JSONArray/JSON.toJSONString(对象)` → 反射调用其 getter（`getOutputProperties`）→ `TemplatesImpl.defineTransletClasses` 加载 `_bytecodes` 执行任意字节码。触发点只是链条最前一环，可以被替换。
- **`HotSwappableTargetSource.equals` 的中转作用**（spring-aop）：该类的 `equals` 实现为 `this.target.equals(other.target)`，而 `target` 是构造时注入的任意对象。把两个 `HotSwappableTargetSource` 实例分别包住 `XString` 与恶意对象、放进同一个 `HashMap` 作为 key，反序列化 `HashMap` 重建哈希桶并比较 key 时会进入 `equals`，从而调用到 `XString.equals`。
- **`XString.equals` 的跳板作用**（JDK 自带，`com.sun.org.apache.xpath.internal.objects.XString`）：它对非 `XString` 参数会把对方转成字符串，内部调用 `obj.toString()`。因此它把“equals 比较”转换成“任意对象 toString”。
- **为什么要绕 `resolveClass`**：题目 WAF 在 `resolveClass` 里做两件事——(1) 第一层类必须是 `User` 的子类，否则抛 `HackerClass`；(2) 命中 `BadAttributeValueExpException` 直接拒绝。所以 (a) 根对象改成 `User`，把恶意 `HashMap` 塞进 `user.info`（`Map` 字段）；(b) 触发链不能再引用被 ban 的类，只能用 `HashMap`/`HotSwappableTargetSource`/`XString` 这些不在名单里的类。
- **引用包裹（TC_REFERENCE）**：`TemplatesImpl` 的包名（`com.sun.org.apache.xalan.internal.xsltc.trax`）常被黑名单前缀拦截。做法是先把 `TemplatesImpl` 放进 `JSONArray`，再把这个 `JSONArray` 也作为某个 `HashMap` 的 key 提前写出；后续流里对它的引用只写 `TC_REFERENCE`（指向已反序列化的句柄），解析时复用同一个实例，不再触发 `resolveClass` 对该类名的检查。
- **为什么成立**：`resolveClass` 是逐个 `ObjectStreamClass` 描述符调用的，黑名单只能拦“新出现的类名”；序列化引用复用的对象不产生新的类描述符，链上的 `HashMap.equals` 又只依赖 JDK/Spring 的通用类，因此过滤名单再严也无从下手。

## 触发条件

- 存在可控的 Java 原生反序列化入口（`ObjectInputStream.readObject`），且 fastjson（或任意会 `toString` 成 JSON 的库）在 classpath 上。
- classpath 有 `spring-aop`（`org.springframework.aop.target.HotSwappableTargetSource`）；无 spring-aop 时用两个 `HashMap` 做哈希碰撞的纯 JDK 版本（`yy`/`zZ` 键碰撞）。
- 目标 JDK 提供 `com.sun.org.apache.xpath.internal.objects.XString`（JDK8/JDK17 均有，`TemplatesImpl` 在 JDK8 最直接）。
- 入口允许根对象为该业务类（如 `User`），且该类有可写入的 `Map` 字段承载 gadget。
- 未被拦截的类里存在可用的 `toString` 下游（`JSONArray`/`JSONObject` 或等价序列化器）。

## 利用步骤

1. 生成恶意 translet 字节码（`AbstractTranslet` 子类，构造函数里执行命令，class 版本降到 49）。
2. 反射构造 `TemplatesImpl`，设置 `_bytecodes`、`_name`，`_tfactory` 置 `null`。
3. 反射构造 `XString`（`m_obj` 设为任意字符串），构造 `JSONArray` 并 `add(templates)`。
4. 建两个 `HotSwappableTargetSource`：一个包 `XString`，一个包 `JSONArray`；把二者作为 key 放入 `HashMap`（值随意）。由于 `HashMap` 在 `put` 阶段就会调 `equals`，构造时需先用占位对象，序列化前再反射改写 `target` 指向真实恶意对象，避免本地提前触发。
5. 把该 `HashMap` 放进 `User.info`；为穿过 `resolveClass`，先把 `TemplatesImpl` 与 `JSONArray` 用引用形式预先写出（`HashMap.put(templates, map)` 一类写法或用 `JSONObject`/`JSONArray` 包一层），使后续引用变成 `TC_REFERENCE`。
6. 序列化 `User` → Base64 → 提交到反序列化接口；目标 `User.readObject` 还原 `info` 时，`HashMap` 重建触发 `equals` → `XString.equals` → `JSONArray.toString` → `getOutputProperties` → 字节码执行。

## PoC

关键构造（省略 `setFieldValue`/`serialize` 工具方法）：

```java
TemplatesImpl tpl = TemplatesImpl.class.newInstance();
setFieldValue(tpl, "_bytecodes", new byte[][]{genTranslet("calc")});
setFieldValue(tpl, "_name", "xxx");
setFieldValue(tpl, "_tfactory", null);

JSONArray arr = new JSONArray();
arr.add(tpl);

HotSwappableTargetSource a = new HotSwappableTargetSource(new XString(""));
HotSwappableTargetSource b = new HotSwappableTargetSource(new JSONObject());
HashMap<Object,Object> hp = new HashMap<>();
hp.put(a, a);
hp.put(b, b);
setFieldValue(a, "target", new XString(""));   // 序列化前才指向真对象
setFieldValue(b, "target", arr);

// 让 TemplatesImpl 以引用形式出现，规避 resolveClass 对包名的检查
HashMap<Object,Object> wrapper = new HashMap<>();
wrapper.put(tpl, hp);

User user = new User();
user.setInfo(wrapper);
byte[] payload = serialize(user);   // 交给 Base64 后打到接口
```

原文的完整 PoC 走 `User.info = map`（`map.put("yy", Arrays.asList(templates, getXString(jsonArray)))`），`getXString` 内用 `HashMap("yy"→XString,"zZ"→obj)` 的键碰撞版本 + 外层 `HashMap` 二次碰撞；该纯 JDK 变体不需要 spring-aop。

## 变体与关联

- **纯 JDK 变体**：去掉 `HotSwappableTargetSource`，改用 `"yy"`/`"zZ"` 这类哈希相同的键构造 `HashMap`，让 `HashMap` 在桶内比较时直接进入 `XString.equals`；原文 `getXString()` 就是这个写法，两层 `HashMap` 嵌套扩大命中率。
- **引用包裹的其它写法**：把 `TemplatesImpl` 放进 `JSONArray`/`JSONObject`（fastjson 容器）再引用，或用 `HashMap` 的 key 先写出；本质都是让目标类名只出现一次。
- **关联**：`web-java-deser-fastjson-badattribute-jsonarray-templatesimpl-native-chain`（同一条下游链，触发点是被 ban 的 `BadAttributeValueExpException`）、`web-java-deserialization-jdk-xstring-equals-tostring`（`XString.equals` 通用原理）、`web-java-deserialization-jdk-eventlistenerlist-tostring`（另一个可用触发点）。
- **边界**：没有 `spring-aop` 又没有可用的哈希碰撞构造、`XString` 被移除（非 Oracle/OpenJDK 发行版）、根对象不能是业务类、或目标在 `resolveClass` 里对 `TC_REFERENCE` 复用的类名再做二次归属校验时，该链不成立。

## 检测与防御

- **检测**：序列化流里 `User`（业务类）后紧跟 `java.util.HashMap`、`org.springframework.aop.target.HotSwappableTargetSource`、`com.sun.org.apache.xpath.internal.objects.XString`、`com.fasterxml.jackson`/`com.alibaba.fastjson.JSONArray` 等组合；流中出现大量 `TC_REFERENCE` 复用同一类实例；`ObjectInputStream` 抛出的黑名单告警与后续 getter 反射调用日志同时出现。
- **防御**：不要用 `resolveClass` 类名字符串黑名单做唯一防线，改用 `ObjectInputFilter`（JEP 290）按“允许的类白名单 + 引用深度 + 数组长度”限制，并注册 `SerialFilterFactory`（JEP 415）让嵌套流继承同一策略；彻底方案是不接受外部 Java 序列化数据，改用 JSON/Protobuf 等无 gadget 的格式。
- **加固**：移除 `spring-aop` 中不必要的 `HotSwappableTargetSource` 使用面，升级 JDK 并开启 `jdk.serialFilter` 全局策略；对反序列化入口做签名校验，禁止 Base64 序列化流直接入站。
