---
id: jackson-native-deserialization-getter-tostring-templates-rce
title: Jackson 原生反序列化链：JsonNode/POJONode toString 触发 TemplatesImpl#getOutputProperties 加载字节码 RCE（2.18.0 仍可用）
type: scenario
domain: web
path: web/java/deserialization/jackson
technique: jackson-native-getter-tostring-rce
tags:
- java
- jackson
- deserialization
- native-chain
- getter
- templatesimpl
- rce
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-30
  verified_at: '2026-11-08T15:48:03+08:00'
  notes: 已对照原文核对：原理（JsonNode/POJONode toString 触发 getOutputProperties）与触发条件、ysomap PoC 与原文一致，img03 在 jackson-databind 2.18.0 实测弹计算器成功；2.18.0 仅为测试环境版本，affected_versions 保持空正确；无 sources/source_url（全库现状），文中 getter 排序稳定性与 JdkDynamicAopProxy 稳定化建议已并入变体章节
url: /docs/web/java/deserialization/jackson/jackson-native-deserialization-getter-tostring-templates-rce/
draft: false
kb_aliases:
- Jackson 原生反序列化
- JsonNode toString gadget
- JacksonObject2
- POJONode toString TemplatesImpl
---

## 一句话结论

目标应用反序列化不可信 Java 序列化数据且 classpath 含 jackson-databind 时，可通过 Jackson 原生 gadget（序列化 JsonNode/POJONode，toString 时遍历并调用对象 getter）触发 TemplatesImpl#getOutputProperties 加载恶意字节码实现命令执行，最新版 jackson-databind 2.18.0 实测仍可打通。

## 原理

Jackson 的 ObjectMapper/JsonNode 体系在 `BaseJsonNode#toString`（或 POJONode 序列化）时会对内部包裹的对象调用 InternalNodeMapper/ObjectNode 序列化逻辑，该过程按 JavaBean 约定反射调用对象全部 getter。TemplatesImpl#getOutputProperties 正是标准 getter，调用后进入 newTransformer → defineClass 加载 _bytecodes 中的恶意类，静态初始化块执行任意命令。整条链只需 jackson-databind 与 JDK 内置类，无需其他第三方依赖；入口是原生 ObjectInputStream#readObject，例如借助 EventListenerList 等 JDK 自带可序列化类触发 toString。之所以高版本仍有效，是因为 Jackson 官方从未把"toString 触发 getter 调用"视为漏洞修复点（属于 JSON 库正常功能），因此不受版本升级影响。

## 触发条件

1. 应用对不可信数据执行 ObjectInputStream#readObject（或任何能触发 BaseJsonNode#toString 的入口）；
2. classpath 存在 jackson-databind（含 2.18.0 在内的当前版本）；
3. 可构造 TemplatesImpl 恶意字节码（com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl 可达）。

## 利用步骤

1. 构造恶意 TemplatesImpl（恶意类放 _bytecodes，_name/_tfactory 置值）；
2. 用 JsonNode/POJONode 包裹该对象（序列化生成时需绕过 ObjectOutputStream#writeObject0 对 writeReplace 的检查，如借助 ysomap 框架的 JacksonObject2 payload + TemplatesImplBullet）；
3. 通过 JDK 原生反序列化入口（EventListenerList 触发 toString 一类）让包裹节点执行 toString；
4. toString 内部调用 getOutputProperties → 加载字节码 → 命令执行。

## PoC

使用 ysomap：

```
use payload JacksonObject2
use bullet TemplatesImplBullet
set body calc
run
```

反序列化生成物后本地 readObject 即弹出计算器（原文在 jackson-databind 2.18.0 实测成功）。无独立最小 PoC 代码。

## 变体与关联

- 同类触发可换成 JSONArray/JSONObject toString 等其他 Jackson 序列化入口；
- Jackson 用 getDeclaredMethods 获取 getter 且官方文档明确顺序不确定，导致该链"有时通有时不通"；可用 Spring AOP 的 JdkDynamicAopProxy 代理目标接口，使序列化侧只见到目标 getter，实现稳定利用；
- fastjson2 自 2.0.27 起对同类链加了黑名单（见 fastjson 黑名单绕过卡），jackson 无此限制。

## 检测与防御

- 反序列化入口实施白名单过滤（ObjectInputFilter），杜绝不可信 ObjectInputStream#readObject；
- 监控反序列化后对 TemplatesImpl#getOutputProperties / newTransformer 的调用；
- Jackson 场景下避免让不可信对象进入 JsonNode/POJONode 的 toString 流程。
