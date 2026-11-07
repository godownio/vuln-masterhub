---
id: web-java-deser-hessian2-protocol-error-tostring-trigger
title: Hessian2 前置 C 字节制造协议错误，在 expect 拼接中隐式调用 toString
type: scenario
domain: web
path: web/java/deserialization/hessian
technique: hessian2-protocol-error-tostring-trigger
aliases:
- Hessian2 toString 触发
- Hessian 前置 C 触发 toString
- readObjectDefinition 长度错乱
- expect 字符串拼接 toString
- Hessian2Serialize_3
tags:
- java
- hessian
- deserialization
- gadget
- tostring
- protocol-parsing
- trigger
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-42
  verified_at: '2026-11-05T06:38:49+08:00'
  notes: 已对照原文与35张截图核对：Hessian2Input.readObject 的 case 'C'(0x43) 进入 readObjectDefinition→readString（img/08/09）、readString 内 expect 调用 valueOf→StringBuilder.append→obj.toString（img/09/10）、调试栈 test.toString→String.valueOf→StringBuilder.append→Hessian2Input.expect→readString→readObjectDefinition→readObject 与卡片完全一致；Hessian2Serialize_3 先 write(67) 再 setAllowNonSerializable(true)+writeObject 与原文代码一致（img/01 亦证明 allowNonSerializable 可序列化任意类）。该卡是 toString 触发原语（本身只证明 toString 被调用），最终危害由同文 aspectj LazyMethodGen 二次反序列化卡承接并已有调试栈证明，作为可复用入口卡保留合理。无 CVE/版本区间。未在本机复现。
---

## 一句话结论

Hessian2 的 `readObjectDefinition()` 先 `readString()` 读类名，长度解析错误时进入 `expect()` 构造异常信息，用 `StringBuilder.append(valueOf(obj))` 把已部分实例化的对象拼进字符串，从而隐式调用其 `toString()`；攻击者在正常 Hessian2 流前再插入一个 `C`（0x43）即可制造这种长度错乱，把任意 `toString` gadget 变成 Hessian 反序列化的入口。

## 原理

- `Hessian2Input.readObject()` 遇到首字节 `C`（0x43）时进入 `readObjectDefinition(null)`，第一步是 `String type = readString()`（图 8/9）。
- `readString()` 内部调用 `expect(...)` 校验后续字节；当前面的字节被额外插入的 `C` 打乱后，类名长度与实际内容不一致，`expect()` 走到错误分支。
- 错误分支构造提示字符串，典型实现为 `throw error("expected ... at ... " + value)`，其中会走 `StringBuilder.append(Object)` → `String.valueOf(obj)` → `obj.toString()`。此时对象已经被 Hessian 反序列化流程部分创建，`toString()` 被真实调用（图 10 的调用栈）。
- 因此无需 HashMap/TreeMap 的 `hashCode`/`compareTo` 入口，只要目标 Hessian2 入口存在、且攻击者能构造带 `C` 前缀的字节流，就能触发任意类的 `toString`。
- 配合 `SerializerFactory.setAllowNonSerializable(true)`，未实现 `Serializable` 的类也能被 Hessian 序列化，扩大了可作为触发对象的类范围（图 1）。
- 原文实测调用栈：`test.toString → String.valueOf → StringBuilder.append → Hessian2Input.expect → Hessian2Input.readString → Hessian2Input.readObjectDefinition → Hessian2Input.readObject`。

## 触发条件

- 目标使用 Hessian2 协议反序列化攻击者可控数据（HessianServlet、Hessian RPC 等）。
- 目标 classpath 上存在具备可利用 `toString()` 的类；该类不必实现 `Serializable`（序列化端开启 `allowNonSerializable` 即可）。
- 攻击者能发送原始字节，而不是只能发送合法 Hessian 对象。
- 反序列化端未启用严格的类白名单或流格式校验。

## 利用步骤

1. 选定一个 `toString()` 会进入危险逻辑的 gadget 类，构造其实例。
2. 用 `Hessian2Output` 序列化该对象，并先把输出流写出一个字节 `'C'`（67），使流首字节变成伪造的类定义标记。
3. 将得到的字节发送到目标的 Hessian2 反序列化入口。
4. 服务端 `readObject()` 解析 `C` → `readObjectDefinition` → `readString` 时长度错乱 → `expect` 拼错误信息 → 调用 gadget 的 `toString()`。

## PoC

```java
public static byte[] Hessian2Serialize_3(Object o) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    baos.write(67);                       // 注入前置 'C'
    Hessian2Output hessian2Output = new Hessian2Output(baos);
    hessian2Output.getSerializerFactory().setAllowNonSerializable(true);
    hessian2Output.writeObject(o);
    hessian2Output.flushBuffer();
    return baos.toByteArray();
}
```

验证用类（`toString` 被调用即证明触发）：

```java
public class test {
    public String toString() {
        System.out.println("toString 被触发了");
        return "triggered";
    }
}
```

触发端：

```java
byte[] bytes = Hessian2Serialize_3(new test());
new Hessian2Input(new ByteArrayInputStream(bytes)).readObject();
```

成功后控制台出现 `toString 被触发了`；原文调试栈确认调用来自 `Hessian2Input.expect → readString → readObjectDefinition`。

## 变体与关联

- 前缀字节不限于 `C`：任何能让 `readObjectDefinition`/`readString` 长度解析错位的标记都可能走到 `expect`；`C` 是原文验证过的稳定形式。
- 关联：[[web-java-deser-hessian-deserialization-entry-map-put]]（Hessian 的另一类入口：`MapDeserializer.map.put` 触发 hashCode/equals/compareTo）；本卡补足“对象已在流中被实例化但入口是 `toString`”的场景。
- 关联：[[web-java-deser-hessian-aspectj-lazymethodgen-second-order]]（用本触发方式把 aspectjweaver `LazyMethodGen.toString` 接成二次反序列化链）。
- 同类思路可见 Fastjson 的 `expectClass` 类型不匹配触发 `toString`/`getter`；本质上都是“解析错误路径把对象带进字符串拼接”。

## 检测与防御

- 检测：Hessian2 请求体首字节为 `C` 但后续长度字段与实际内容不一致、解析异常率异常升高；同一来源出现大量 `readObjectDefinition`/`readString` 异常。
- 检测：JVM 层监控 `toString` 中出现的危险调用（`Runtime.exec`、JNDI lookup、`Class.forName`）；在异常处理路径上尤其容易漏报。
- 防御：Hessian 入口做严格类允许列表，禁止 `setAllowNonSerializable(true)`；对反序列化流做格式校验并在解析错误时快速失败，不把对象拼进异常消息。
- 防御：不要对不可信数据使用 Hessian 原生反序列化；优先使用结构化、带 schema 的协议，并在网关层限制 Hessian 入口暴露面。
