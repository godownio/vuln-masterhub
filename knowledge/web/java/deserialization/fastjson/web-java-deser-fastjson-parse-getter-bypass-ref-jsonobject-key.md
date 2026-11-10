---
id: web-java-deser-fastjson-parse-getter-bypass-ref-jsonobject-key
title: 入口只用 JSON.parse 时 getter 调用受限：用 $ref 的 JSONPath 解析或把 JSONObject 当 key 走 toString，强行触发任意 getter
type: scenario
domain: web
path: web/java/deserialization/fastjson
technique: fastjson-parse-getter-restriction-bypass-ref-and-jsonobject-key
aliases:
- fastjson parse 与 parseObject 区别
- $ref 触发 getter
- JSONObject 作为 key 触发 toString
- handleResovleTask
- fastjson 任意 getter 触发
tags:
- java
- fastjson
- deserialization
- getter
- autotype
- jsonpath
- ref
- gadget
affected_versions: fastjson：$ref 触发 getter 需 >= 1.2.36；以 JSONObject 作为 key 经 toString 触发 getter 在 > 1.2.36 被堵
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:36:56+08:00'
  notes: 已对照原文核对（fastjson parse 与 parseObject 差异）：JavaBeanInfo.build 对 getter 返回值类型（Collection/Map/AtomicBoolean/AtomicInteger/AtomicLong）的限制、parseObject 额外 JSON.toJSON 走 JavaBeanSerializer.getFieldValuesMap、$ref 经 handleResovleTask→JSONPath.eval→PropertySegment/FieldInfo.get 调 getter、低版本因 refValue 必须为 JSONObject 不成立、JSONObject 作 key 走 DefaultJSONParser.parseObject 的 key.toString、大于 1.2.36 入口掐掉 toString 均与正文一致；本次核对未读取图片，仅依据正文；未验证点为正文的 sink 只是自建 demo2.User#getCmd 演示 getter 被调，未给出 TemplatesImpl/JDBC 端到端实测；affected_versions 沿用原文明确写出的版本边界
---

## 一句话结论

当目标反序列化点用的是 `JSON.parse(...)` 而不是 `parseObject(...)` 时，Fastjson 只会调用 setter 与「返回值继承 Collection/Map/AtomicBoolean/AtomicInteger/AtomicLong」的 getter，绝大多数依赖 getter 的 gadget 直接失效；此时可以用 `$ref` 让 `handleResovleTask` 里的 JSONPath 求值去 `get` 一个字段（触发任意 getter），或把 `JSONObject` 塞到 JSON 的 key 位置让 `DefaultJSONParser.parseObject` 调用 `key.toString()`，两条路都能在 `parse` 入口下把任意 getter 打出来。

## 原理

- **getter 白名单来自 JavaBeanInfo**：`parse` 反序列化 bean 时用 `JavaBeanDeserializer`，其 `JavaBeanInfo.build` 只把「返回值类型是 Collection/Map/AtomicBoolean/AtomicInteger/AtomicLong」的 `getXxx` 收进字段表；setter 则无类型限制。所以 `parse` 只调 setter 加这一类特殊 getter。
- **parseObject 多一步序列化**：`parseObject` 内部仍调 `parse`，之后额外执行 `JSON.toJSON(obj)`，由 `JavaBeanSerializer.getFieldValuesMap` 遍历字段、反射调用每个 getter。因此 `parseObject` 会调全部 getter，`parse` 不会——这是两条链可打性差异的根因。
- **`$ref` 走的是 JSONPath 取值**：解析时若遇到 `{"$ref":"$..."}`,解析器把引用登记成 ResolveTask，最后 `handleResovleTask` 对 `$` 开头的值实例化 `JSONPath` 并 `eval`；`PropertySegment.eval` 对目标对象调用 `getPropertyValue` → `FieldInfo.get` → `Method.invoke`，即**直接调用该字段的 getter**。因此只要能让 `$ref` 指向一个含危险 getter 的对象的字段，getter 就会被执行，与 `parse` 的 getter 白名单无关。
- **低版本为什么不行**：`handleResovleTask` 在取值前要求 `refValue != null` 且必须是 `JSONObject` 类型，老版本拿到的引用值类型不满足就跳过；`$ref` 触发 getter 需 fastjson >= 1.2.36 且开启 AutoType。
- **JSONObject 当 key 时触发 toString**：Fastjson 解析到 `{` 会新建 `JSONObject`；`DefaultJSONParser.parseObject` 处理键时会对非字符串键调用 `toString()`。`JSONObject` 继承 `JSON`，其 `toString()` 就是 `JSON.toJSONString(this)`，序列化过程中会反射调用成员对象的 getter。所以构造 `{"@type":"com.alibaba.fastjson.JSONObject","aaa":{"@type":"危险类",...}}` 这种「外层是 JSONObject、内层是目标 bean」的结构，键处理阶段就会把内层所有 getter 打一遍。该路径在 fastjson > 1.2.36 已在 `DefaultJSONParser#parse` 入口掐掉，不再调用 `toString`。
- **为什么这两条算完整链**：原理上 getter 就是 sink（`TemplatesImpl#getOutputProperties`、`JdbcDataSource#getConnection`、`Runtime.exec` 包装类等），一旦 getter 被调即等于命令执行/任意连接；两条路都不依赖 `parseObject` 的额外序列化步骤，因此能救「只调 `parse`」的入口。

## 触发条件

- 反序列化入口是 `JSON.parse(str)`（无期望类）或框架里等价的上层封装，AutoType 已开启或目标类型已进白名单/缓存。
- `$ref` 路线：fastjson >= 1.2.36；payload 内先构造一个含危险 getter 的对象，再用 `$ref` 指向其字段。
- JSONObject key 路线：fastjson <= 1.2.36（该版本之后入口即拦截）。
- classpath 上存在可用的 getter gadget（`TemplatesImpl`、JDBC DataSource、可 exec 的业务类等）。
- 目标 JDK 允许反射调用（模块化下 `setAccessible` 受限时 sink 选择要相应调整）。

## 利用步骤

1. 先指纹判定入口类型：提交 `{"@type":"java.lang.Class","val":"..."}`、`{{}:{}}`、畸形 JSON 等观察行为，区分是 `parse` 还是 `parseObject`（`parseObject` 会额外调 getter）。
2. `$ref` 路线：构造数组，第一个元素放危险类的 `@type` 实例（其危险 getter 由字段提供，如 `cmd`），第三个元素写 `{"$ref":"$[0].cmd"}`；`handleResovleTask` 求值时调用 `getCmd()` 触发 sink。
3. JSONObject key 路线（老版本）：构造 `{"@type":"com.alibaba.fastjson.JSONObject","<任意键>":{"@type":"危险类","id":"..."}}`，让内层实例成为 JSONObject 的成员，键处理阶段 `toString` → 序列化 → 全部 getter。
4. 把 sink 换成 `TemplatesImpl`（`getOutputProperties`）或 JDBC（`getConnection`）确认可执行；无回显时用 DNS/时间盲打。
5. 若 `parse` 下 setter 已被黑名单拦，优先用 `$ref` 直取 getter（绕过 `checkAutoType` 对 getter 触发路径的判断）。

## PoC

`$ref` 触发任意 getter（Demo 类 `User#getCmd` 内执行命令，仅用于说明触发点）：

```json
[
  {"@type":"demo2.User","cmd":"calc"},
  {"@type":"demo2.User","cmd":"notepad.exe","test":"test"},
  {"$ref":"$[0].cmd"}
]
```

调用栈：

```text
getCmd:20, User
  ... FieldInfo.get → FieldSerializer.getPropertyValue → JavaBeanSerializer.getFieldValue
    → JSONPath.getPropertyValue → JSONPath$PropertySegment.eval → JSONPath.eval
      → DefaultJSONParser.handleResovleTask → JSON.parse
```

JSONObject 作为 key 触发 toString（fastjson <= 1.2.36）：

```json
{"@type":"com.alibaba.fastjson.JSONObject","aaa":{"@type":"demo2.Test","id":"123"}}
```

## 变体与关联

- **`$ref` 的引用路径**：`$`、`$.a.b`、`$[0].x` 都可，越深越容易指向对象而非字符串；引用目标必须解析成对象，引用到字符串不会触发 getter。
- **期望类场景**：一旦入口带期望类，`$ref` 只能落到期望类成员上且类型不匹配会断链，改用 `java.util.Currency` 包装等手法（见同目录期望类卡）。
- **前置知识**：`parse` 只调特殊类型 getter 这一点是理解「为什么某条链在 A 站能打、B 站不能打」的关键；反之 `parseObject` 入口可直接用 `TemplatesImpl` 的 `getOutputProperties`，见同目录 `parseObject`/AutoType 卡。
- **注意**：把结果在客户端 `System.out.println(arrayObj)` 时也会触发 getter，但那是攻击者本地行为，不算目标侧 sink，不能作为利用依据。

## 检测与防御

- 统一升级到关闭 AutoType 的版本（1.2.83+ 且 `safeMode`），或迁移到 Jackson/Gson 并禁用 `enableDefaultTyping`。
- 禁止生产代码使用 `JSON.parse` 处理外部输入；必须解析时绑定明确 DTO（`parseObject(str, Dto.class)`）并校验字段。
- 开启 `ParserConfig.getGlobalInstance().setSafeMode(true)`，并开启 `checkAutoType` 默认拦截；对 `$ref` 做显式禁用（自定义 `JSONReader.Feature`/重写 `parse` 预检查含 `$ref` 的字段）。
- 检测：请求体中出现 `"$ref"`、`"@type":"com.alibaba.fastjson.JSONObject"`、异常嵌套的 `{}` 作为键；JVM 侧监控 `JSONPath.eval`、`handleResovleTask` 在反序列化路径被调用，以及动态定义 `AbstractTranslet`、`getConnection` 在反序列化栈中出现。
