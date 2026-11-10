---
id: web-java-deser-rome-spring-hotswappable-xstring-tostringbean-templatesimpl
title: Spring+Rome 原生链：HashMap.putVal→HotSwappableTargetSource.equals→XString.equals→ToStringBean.toString→TemplatesImpl 加载字节码
type: scenario
domain: web
path: web/java/deserialization
technique: rome-spring-hotswappable-xstring-tostringbean-templatesimpl
tags:
- java
- deserialization
- gadget
- rome
- spring-aop
- hotswappabletargetsource
- xstring
- hashmap
- putval
- tostringbean
- templatesimpl
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V454
  verified_at: '2026-11-10T02:15:16+08:00'
  notes: 已对照原文核对：HashMap.readObject→putVal 桶内比较（HSTS.hashCode 恒为类哈希，天然同桶）→第二个 key 的 HotSwappableTargetSource.equals→this.target.equals(other.target)→XString.equals→obj2.toString()→ToStringBean.toString→TemplatesImpl.getOutputProperties；图 07/08/09/10/11/12/13 与卡一致；XString 必须后放的顺序约束、putVal 而非 hash() 触发均与原文总结一致；占位 target 规避构造期触发为原文 payload 的修正说明；与 jdk-xstring-equals-tostring(0.915 原语卡)/blacklist-hotswappable-pojonode、fastjson-xstring 等非同链（dedup 盘中 duplicate 为卡片自身）。未在本机复跑 PoC。
url: /docs/web/java/deserialization/web-java-deser-rome-spring-hotswappable-xstring-tostringbean-templatesimpl/
draft: false
kb_aliases:
- Rome Spring 链
- HotSwappableTargetSource XString Rome
- HashMap putVal 触发 toString
- Spring AOP 反序列化 Rome
- XString equals ToStringBean
- rome spring templatesimpl
---

## 一句话结论

classpath 同时有 rome 与 spring-aop 时，用两个 `HotSwappableTargetSource` 作为 `HashMap` 的 key：它的 `hashCode()` 恒为 `HotSwappableTargetSource.class.hashCode()`，两个 key 必然落在同一哈希桶；`HashMap.readObject→putVal` 比较第二个 key 时调用 `HotSwappableTargetSource.equals`，其实现 `this.target.equals(other.target)` 把比较转给 `XString.equals(ToStringBean)`，`XString.equals` 又调用对方 `toString()`，最终进入 `ToStringBean.toString` 的反射 getter 逻辑并触发 `TemplatesImpl.getOutputProperties()` 加载恶意 translet 字节码。

## 原理

- **为什么用 putVal 而不是 hashCode**：常见 HashMap 链靠两个 key 的 `hashCode` 相同触发 `equals`，本条链不依赖 key 的哈希碰撞，而是利用 `putVal` 的桶内比较分支：`if (p.hash == hash && ((k = p.key) == key || (key != null && key.equals(k))))`。`HotSwappableTargetSource.hashCode()` 返回固定的类哈希值，天然让所有实例同桶，因此第二次 put 必然进入 equals 分支。
- **HotSwappableTargetSource.equals 的中转**：`return this == other || other instanceof HotSwappableTargetSource && this.target.equals(((HotSwappableTargetSource) other).target);`——把“两个包装器比较”转发为“两个 target 直接比较”，target 由构造参数决定，可分别放入 `XString` 与 `ToStringBean`。
- **顺序约束**：HashMap 中先放入的是 `HotSwappableTargetSource(ToStringBean)`，后放入的是 `HotSwappableTargetSource(new XString("xxx"))`。第二次 `putVal` 调用的是“后放入 key 的 equals”，即 `XString.equals(ToStringBean)`；`XString.equals` 在非 XNodeSet/XNumber 分支执行 `str().equals(obj2.toString())`，于是调用 `ToStringBean.toString()`。如果反过来让 `ToStringBean` 包装器后放，equals 走 Object 默认实现，链断。
- **ToStringBean 下游**：`toString()` 无参版本先从 ThreadLocal/类名算出 prefix，再调用 `toString(prefix)`；后者用 `BeanIntrospector.getPropertyDescriptors(_beanClass)` 取 getter 并在 `_obj` 上 `invoke`。把 `_beanClass` 设为 `TemplatesImpl.class`（或只含 `getOutputProperties` 的 `Templates` 接口）、`_obj` 设为填好 `_bytecodes` 的 `TemplatesImpl`，即触发 `getOutputProperties → newTransformer → defineTransletClasses → defineClass`。
- **构造期的坑**：`HashMap.put` 会立即执行桶内 equals，如果构造时就放真实 target，payload 会在本地构建阶段提前执行。稳妥做法是先用无害 target（或无参 `Object`）占位 put，序列化前再反射把第一个包装器的 target 改成 `ToStringBean`、第二个保持 `XString`；原文 payload 未处理这一点，实际打点时应按占位法构造。
- **为什么成立**：链的每一环都是通用语义——固定 hashCode 制造同桶、equals 转发、XString 把 equals 转成 toString、Rome 把 toString 转成任意 getter 调用；不需要任何漏洞补丁缺失，只要这些类在 classpath 且反序列化入口可控。

## 触发条件

- Java 原生反序列化入口，攻击者可控序列化流。
- classpath 含 `rome`（`ToStringBean`）与 `spring-aop`（`HotSwappableTargetSource`）；JDK 含可写的 `TemplatesImpl`（JDK8 最直接）。
- `XString`（`com.sun.org.apache.xpath.internal.objects.XString`）在 JDK 内可用。
- 过滤器未拦截 `HotSwappableTargetSource`/`XString`/`ToStringBean`/`TemplatesImpl` 中的任一环。

## 利用步骤

1. 生成 `AbstractTranslet` 子类字节码（静态初始化块执行命令），构造 `TemplatesImpl` 并设置 `_bytecodes`、`_name`。
2. 构造 `ToStringBean(TemplatesImpl.class, templates)`（或用 `Templates.class` 收窄 getter 集合）。
3. 构造两个 `HotSwappableTargetSource`：h1 先用无害占位 target，h2 包 `new XString("xxx")`。
4. 依次 `map.put(h1,"1")`、`map.put(h2,"1")`：第一次桶为空不触发 equals；第二次 h2.equals(h1) 因 h1 占位而无害。
5. 反射把 h1.target 设为第 2 步的 `ToStringBean`（h2 保持 XString）；序列化 `HashMap`。
6. 目标 `readObject` 重新 put 时，h2.equals(h1) → `XString.equals(ToStringBean)` → `ToStringBean.toString()` → `TemplatesImpl.getOutputProperties()` → 字节码执行。
7. 验证：本地反序列化弹计算器/执行命令；若失败，检查两个 key 的放入顺序（XString 必须后放）、`HotSwappableTargetSource` 是否存在、`TemplatesImpl` 字段可写性。

## PoC

```java
// 关键构造（省略 setFieldValue/translet 生成/序列化；未在本机执行）
TemplatesImpl templates = new TemplatesImpl();
setFieldValue(templates, "_bytecodes", new byte[][]{transletCode});
setFieldValue(templates, "_name", "fanxing");

ToStringBean toStringBean = new ToStringBean(TemplatesImpl.class, templates);

HotSwappableTargetSource h1 = new HotSwappableTargetSource(new Object());     // 先占位
HotSwappableTargetSource h2 = new HotSwappableTargetSource(new XString("xxx"));

HashMap<Object, Object> map = new HashMap<>();
map.put(h1, "1");        // 空桶，不触发
map.put(h2, "1");        // h2.equals(h1)：XString.equals(Object) 无害

setFieldValue(h1, "target", toStringBean);   // 序列化前换成真 payload

ByteArrayOutputStream barr = new ByteArrayOutputStream();
new ObjectOutputStream(barr).writeObject(map);
// 发送到目标反序列化入口
```

说明：原文 payload 直接 `new HotSwappableTargetSource(toStringBean)` 后 put，会在本地 put 阶段触发一次链；本 PoC 用占位 target 规避构造期触发，逻辑与 readObject 阶段一致。

## 变体与关联

- [[web-java-deser-rome-equalsbean-tostringbean-templatesimpl]]：同一下游 sink 的非 Spring 入口（EqualsBean.hashCode）。
- [[web-java-deserialization-jdk-xstring-equals-tostring]]：HashMap 哈希碰撞 + XString/HotSwappableTargetSource 触发任意 toString 的原语卡。
- [[web-java-deser-fastjson-xstring-hotswappable-tostring-waf-bypass]]：同触发原语配合 JSONArray 下游与 resolveClass 黑名单绕过。
- [[web-java-deser-hessian-signedobject-second-order-templates]]：ToStringBean 下游换 SignedObject 二次反序列化 TemplatesImpl。
- 变体：`_beanClass` 可换 `Templates.class` 收窄 getter；下游可换其他危险 getter（JNDI 等）；h2 的 target 也可换成其他会调用 toString 的类（如 `XString` 的替代物）。
- 边界：无 spring-aop 时退回 EqualsBean/哈希碰撞入口；过滤器拦截任一环节或 JDK 强封装 TemplatesImpl 时链断。

## 检测与防御

- 检测：序列化流中同时出现 `org.springframework.aop.target.HotSwappableTargetSource`、`com.sun.org.apache.xpath.internal.objects.XString`、`com.sun.syndication.feed.impl.ToStringBean`、`TemplatesImpl` 的组合；`HashMap.readObject→putVal→equals` 调用栈中出现上述类。
- 检测：反序列化过滤器对 `HotSwappableTargetSource`、`XString`、Rome Bean 类、`TemplatesImpl` 做拦截；JEP 290 全局过滤器按类名白名单限制。
- 防御：不必要地引入 spring-aop/rome 时移除依赖；升级 JDK 使 `TemplatesImpl` 模块强封装；对反序列化入口做认证与签名，禁止外部可控流。
- 响应：保留原始流证据，确认命令执行与外连；排查同入口的其他 gadget 尝试。
