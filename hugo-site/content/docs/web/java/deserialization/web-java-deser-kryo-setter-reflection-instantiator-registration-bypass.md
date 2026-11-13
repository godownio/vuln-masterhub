---
id: web-java-deser-kryo-setter-reflection-instantiator-registration-bypass
title: Kryo 配置反射滥用：JSON 键驱动 setter，关闭 RegistrationRequired 并设 StdInstantiatorStrategy 解锁 gadget
type: scenario
domain: web
path: web/java/deserialization
technique: kryo-setter-reflection-instantiator-registration-bypass
tags:
- java
- kryo
- deserialization
- configuration
- mass-assignment
- reflection
- objenesis
- bypass
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V501
  verified_at: '2026-11-11T02:44:18+08:00'
  notes: 已对照原文与图07-09/12-15核对：/coffee/demo 接收 JSON，polish 开关后遍历 Kryo setXxx 并按 JSON 键反射调用、非基本类型值 Class.forName(值).newInstance()、setRegistrationRequired(false) 跳过 Class is not registered、setInstantiatorStrategy(StdInstantiatorStrategy) 解除无参构造限制均与原文及 getRegistration/classToRegistration 截图一致；修正一处表述：TemplatesImpl 本身有无参构造，无参限制针对 EqualsBean/ToStringBean/SignedObject/HotSwappableTargetSource 等。文章 payload 用字符串写布尔值，卡内已注明按实现可能需布尔类型；未在目标环境复跑。
url: /docs/web/java/deserialization/web-java-deser-kryo-setter-reflection-instantiator-registration-bypass/
draft: false
kb_aliases:
- Kryo setter 反射
- setRegistrationRequired(false)
- StdInstantiatorStrategy
- Kryo 无参构造绕过
- Kryo Class is not registered
- 配置对象 mass assignment
---

## 一句话结论

当应用暴露一个“按 JSON 键反射调用 Kryo setter”的接口时，攻击者可以调用 `setRegistrationRequired(false)` 关闭类注册检查，并把 `InstantiatorStrategy` 设为 `org.objenesis.strategy.StdInstantiatorStrategy`，让 Kryo 能反序列化未注册、且没有无参构造函数的 gadget 类（如 `EqualsBean`/`ToStringBean`/`SignedObject`），从而把原本会报 `Class is not registered` / `Class cannot be created` 的反序列化入口变成可利用的 RCE。

## 原理

- Kryo 默认 `registrationRequired=true`：序列化/反序列化涉及的每个类都必须先 `register`，否则 `getRegistration` 拿不到注册信息并抛异常；同时默认实例化策略要求类有无参构造函数，`newInstance` 失败会报 “Class cannot be created (missing no-arg constructor)”。
- 这两个限制挡住的恰恰是常见 gadget 类：`EqualsBean`、`ToStringBean`、`SignedObject`、`HotSwappableTargetSource` 等构造器带参数；未注册的 gadget 类同样会被拒。（`TemplatesImpl` 本身有无参构造，但与之配套的 `EqualsBean`/`ToStringBean` 等仍需要该策略。）
- 如果应用把 Kryo 的配置对象暴露成“接收 JSON，遍历 `Kryo` 的所有 `setXxx` 方法，按 JSON 键 `Xxx` 取值并调用 setter”的形式，攻击者就能调用任意公开 setter：
  - `setRegistrationRequired(false)`：跳过注册检查；
  - `setInstantiatorStrategy(new StdInstantiatorStrategy())`：Objenesis 通过字节码/反射直接分配对象，不调用构造函数，从而能实例化没有无参构造的类（Spring Boot 通常自带 `objenesis` 依赖）。
- 该接口通常还有一个业务开关（如 `polish=true`）才进入 setter 反射逻辑；攻击者只需在 JSON 中带上开关、目标 setter 键和值。
- 对于非基本类型参数，代码往往做 `Class.forName(值).newInstance()` 再 `setMethod.invoke(kryo, 实例)`；这正好让攻击者用类名字符串构造 `StdInstantiatorStrategy`。基本类型参数（如 boolean）则直接把 JSON 值传给 setter，需提供正确的布尔值。
- 根因有两层：一是“通用 setter 反射分发”把配置对象的所有写入能力暴露给用户（mass assignment/属性注入）；二是 Kryo 的安全选项本身可被运行时修改，关闭后不影响已经存在的反序列化入口。

## 触发条件

- 应用提供一个接收 JSON、按 key 反射调用 Kryo `setXxx` 的配置接口（常见于“调试/演示/参数配置”接口）。
- 该接口没有对可调用的 setter 做白名单，攻击者可控制 key 与 value。
- 存在另一个使用同一 Kryo 实例（或同一配置）的 `readClassAndObject`/`readObject` 反序列化入口。
- classpath 有 `objenesis`（Spring Boot 默认常见）与可用的 gadget 依赖。
- 接口有开关门禁（如 `polish`），但开关值可由请求控制。

## 利用步骤

1. 审计/黑盒发现配置接口：JSON 键与 Kryo setter 名对应（如 `RegistrationRequired` → `setRegistrationRequired`），非基本类型值按类名实例化。
2. 先发 `{"polish":true,"RegistrationRequired":false}`，确认返回成功、后续反序列化不再报 “Class is not registered”。
3. 再发 `{"polish":true,"InstantiatorStrategy":"org.objenesis.strategy.StdInstantiatorStrategy"}`，确认无参构造限制被绕过。
4. 向反序列化入口提交构造好的 Kryo gadget payload（见关联卡），验证命令执行/回显。
5. 若接口对 setter 名做了过滤，尝试大小写、前缀、嵌套键或其它配置 setter（如 `setClassLoader`、`setDefaultSerializer`）改变行为。
6. 成功后清理/重启进程，排查是否写入持久化或内存马。

## PoC

```json
// 第一步：关闭注册检查、设置 Objenesis 实例化策略
{
  "polish": true,
  "RegistrationRequired": false,
  "InstantiatorStrategy": "org.objenesis.strategy.StdInstantiatorStrategy"
}
```

```java
// 接口端的等价逻辑（漏洞模式）
JSONObject cfg = new JSONObject(raw);
if (cfg.has("polish") && cfg.getBoolean("polish")) {
    for (Method setMethod : kryo.getClass().getDeclaredMethods()) {
        if (!setMethod.getName().startsWith("set")) continue;
        Object v = cfg.get(setMethod.getName().substring(3));
        if (!setMethod.getParameterTypes()[0].isPrimitive()) {
            v = Class.forName((String) v).newInstance();   // 攻击者控制类名
        }
        setMethod.invoke(kryo, v);                          // 任意 setter
    }
}
```

说明：PoC 依据文章接口逻辑整理；基本类型参数的 JSON 值需为对应类型（文章示例用字符串，是否被 JSON 库自动转换取决于实现），未在目标环境复跑。

## 变体与关联

- 变体：其它可被滥用的 Kryo setter，如 `setReferences(false)`、`setAutoReset`、`setDefaultSerializer`、`setClassLoader`；不同 setter 可改变序列化行为或加载路径。
- 变体：通用 setter 反射分发不止影响 Kryo，任何把配置对象暴露给 JSON 的实现都可能被 mass assignment（如设置 `classLoader`、`serializer`、`registrationRequired`）。
- 关联：[[web-java-deser-kryo-hashmap-hashcode-gadget-chain]]（被本卡解锁的 gadget 链）；[[web-java-deser-kryo-utf8-overlong-encoding-bypass]]（Kryo 流混淆的另一技术面）；[[web-java-deser-hessian-signedobject-second-order-templates]]（同源 gadget 链在 Hessian 下的形态）。
- 边界：配置接口对 setter 做白名单、Kryo 实例与反序列化入口不共享、`objenesis` 不在 classpath、gadget 类被黑名单/模块限制时，该链不成立或需要换其它配置。

## 检测与防御

- 修复：不要用“JSON 键 → 反射 setter”的通用分发处理用户输入；配置接口只接受显式定义的字段白名单，禁止 `RegistrationRequired`、`InstantiatorStrategy` 等安全相关选项。
- Kryo 加固：保持 `registrationRequired=true` 并使用严格类白名单；不要向用户暴露 Kryo 配置对象；在创建 Kryo 实例后立即冻结安全配置。
- 依赖治理：移除不必要的 `objenesis`/gadget 依赖，或限制其可用性；对反序列化入口做独立进程/低权限隔离。
- 检测：请求 JSON 中出现 `RegistrationRequired`、`InstantiatorStrategy`、`StdInstantiatorStrategy`、`Class.forName` 相关类名；Kryo 反序列化异常从 “not registered/no-arg constructor” 突然变为成功；反序列化进程异常定义类/执行命令。
- 响应：重启进程恢复默认配置，排查是否已利用 gadget 链执行命令或写入内存马。
