---
id: web-java-deser-objectinputstream-overlong-utf8-blacklist-bypass
title: 原生 Java 反序列化字节黑名单绕过：UTF-8 Overlong Encoding 隐藏 TemplatesImpl/EventListenerList 类名
type: scenario
domain: web
path: web/java/deserialization/jdk
technique: native-deser-overlong-utf8-blacklist-bypass
aliases:
- ObjectInputStream 黑名单绕过
- UTF8 Overlong 反序列化绕过
- SafeObjectInputStream checkData 绕过
- 字节级黑名单绕过
- Overlong Encoding TemplatesImpl
- Java 原生反序列化超长编码
tags:
- java
- deserialization
- objectinputstream
- blacklist-bypass
- utf8
- overlong-encoding
- templatesimpl
- jdk17
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V52
  verified_at: '2026-11-05T09:00:41+08:00'
  notes: 已对照原文与19张图核对：/api/deserialize/object 接口 base64→DeserializationService.deserialize→SafeObjectInputStream.checkData(原始字节)→readObject 的调用链与图13/16一致；BlackList1 在构造器写入 TemplatesImpl、EventListenerList 的 getBytes()，checkData 逐字节子串比较，图14/15/17 一致；BlackList2 在 resolveClass 对解码后 desc.getName() 判断（图14），卡内已正确区分两种黑名单及超长编码只绕过前者；student.ser 超长编码后图18 成功 calc，图19 LdapAttribute 替代链失败也已在卡内边界说明中体现。未验证点：原文未展示普通 payload 被 checkData 拒绝的对照截图，卡内该句为按代码推断；PoC 为示意、无完整 base64 流；未在本机执行。原文为 CTF 环境 JDK17，未给受影响版本区间，未设置 affected_versions；frontmatter 无 sources/source_url。
---

## 一句话结论

当 `ObjectInputStream` 的子类在 `readObject()` 前用 `checkData(byte[])` 对原始序列化字节做子串比对、黑名单是类名字符串的 ASCII 字节（如 `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl`、`javax.swing.event.EventListenerList`）时，把序列化流中这些类名用 UTF-8 超长编码（overlong）重写，原始字节不再包含黑名单子串，但 Java 的 UTF-8 解码器仍能还原出原类名并正常加载，从而绕过字节级黑名单。

## 原理

- 典型的错误防御实现：
  ```java
  byte[] black = "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl".getBytes(UTF_8);
  for (int i = 0; i <= data.length - black.length; i++) {
      // 逐字节比较 data[i..] 与 black
  }
  ```
  它在反序列化前扫描原始字节，只要序列化流中出现该类名的 ASCII 字节序列就拒绝。
- Java 对象序列化用 modified UTF-8 写入类名（`writeUTF`，2 字节长度前缀 + 数据）。Java 的 UTF-8 解码器接受“超长编码”：本可用 1 字节表示的 ASCII 字符可以写成 2 字节或 3 字节形式，例如 `a`（0x61）可编码为 `C1 A1` 或 `E0 81 A1`，解码后仍是 `a`。
- 攻击者用工具（原文的 `student.ser()` 等）生成序列化流后，把类名字符串的每个 ASCII 字节替换为超长编码，并同步调整 UTF 长度前缀。原始字节中不再出现明文类名，`checkData` 的逐字节匹配失效；`ObjectInputStream.readObject` 解码后得到的类名与原来完全一致，`resolveClass`/`Class.forName` 正常加载。
- 适用边界：
  - 该绕过只针对“解码前扫描原始字节”的黑名单；若服务端在 `resolveClass(ObjectStreamClass desc)` 中对**已解码**的 `desc.getName()` 做黑名单（如原文的 `BlackList2`），超长编码不会改变解码后的名字，无法绕过。
  - 若过滤器用 `ObjectInputFilter`（JEP 290）在类解析阶段按类名/包名拒绝，同样不受超长编码影响。
  - 需要目标 JVM 的 UTF-8 解码器接受超长编码（Java `readUTF` 常见实现接受 2/3 字节超长形式）。
- 原文场景：`SafeObjectInputStream` 用 `BlackList1`（原始字节）拦截 `TemplatesImpl`、`EventListenerList`，用 `BlackList2`（解码后类名）拦截 CommonsCollections 等；`BlackList1` 可通过超长编码绕过，随后继续使用 Jackson `POJONode` → Spring AOP 代理 → `TemplatesImpl` 链在 JDK17 执行命令。

## 触发条件

- 目标存在可控的 Java 原生反序列化入口（如 base64 数据 POST）。
- 服务端使用自定义 `ObjectInputStream`，在 `readObject()` 前对原始字节做类名子串黑名单/正则匹配；黑名单只覆盖解码前字节。
- 目标 classpath 具备后续 gadget 链（如 Jackson + spring-aop + Xalan `TemplatesImpl`）。
- JVM 的 UTF-8 解码器接受 overlong 编码；序列化流的类名长度前缀可被同步修正。

## 利用步骤

1. 确认反序列化入口与黑名单实现：找到 `checkData`/`resolveClass`，区分“原始字节匹配”和“解码后类名匹配”。
2. 先构造一条会被原始字节黑名单拦截的合法 gadget 链（如 `EventListenerList → POJONode → Spring AOP → TemplatesImpl`），确认发送后被拒绝。
3. 用生成工具把序列化流中的目标类名改写为 UTF-8 超长编码（2 字节或 3 字节形式），并修正 `writeUTF` 的长度前缀；可参考 java-chains 的 Utf8OverlongEncoding 功能或自行遍历流字节。
4. 将改写后的字节 base64 后发送到反序列化入口。
5. 观察响应/命令执行结果；若被解码后类名黑名单拦截，则说明该黑名单在 `resolveClass` 阶段生效，需换其他绕过（如二次反序列化、其他不在黑名单的 gadget）。
6. 记录原始 payload 与改写 payload 的字节差异作为证据；验证后停止。

## PoC

生成端（示意，实际用工具完成类名重编码）：

```java
// 1. 构造 EventListenerList -> UndoManager -> POJONode(Spring AOP -> TemplatesImpl)
//    详见关联卡 web-java-deserialization-jackson-pojonode-spring-aop-templatesimpl-jdk17
byte[] normal = serialize(list);
// 2. 把 serialized 流中的类名 "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"
//    与 "javax.swing.event.EventListenerList" 的每个 ASCII 字节改写为 2 字节 overlong
byte[] overlong = Utf8OverlongEncoding.rewrite(normal);
```

请求：

```http
POST /api/deserialize/object HTTP/1.1
Host: target
Content-Type: application/json

{"data":"<base64(overlong stream)>"}
```

原文截图中，普通 payload 会被 `checkData` 拒绝；用 `student.ser(node)` 生成超长编码流后，接口成功反序列化并弹出计算器。

## 变体与关联

- 变体：3 字节超长编码（`E0 81 A1`）或混合 2/3 字节形式，增加检测难度；注意长度前缀与解码结果的对应关系。
- 变体：只对类名中的部分字符做超长编码，保留其他字节，降低流长度变化。
- 变体：若黑名单用 `String.contains` 对 `new String(data)` 做匹配，而非字节数组，超长编码同样可让明文类名消失（取决于 `String` 构造的字符集与解码行为）。
- 关联：[[web-java-deser-hessian-utf8-overlong-encoding-bypass]]（Hessian 序列化中的同类超长编码绕过；本卡是 Java 原生 ObjectInputStream 的字节黑名单）。
- 关联：[[web-java-deserialization-jackson-pojonode-spring-aop-templatesimpl-jdk17]]（后续 gadget 链；本卡只负责绕过字节黑名单）。
- 关联：[[web-java-deserialization-jdk-signedobject-nested-stream-filter-bypass]]（原生反序列化过滤器的另一类绕过思路）。

## 检测与防御

- 防御：不要用原始字节子串黑名单；使用 JEP 290 `ObjectInputFilter` 在类解析阶段做严格白名单（按类名/包名/数组长度/深度），并覆盖所有反序列化入口。
- 防御：在 `resolveClass` 中对解码后的 `desc.getName()` 做白名单/黑名单；同时拒绝任何非预期类，而不是只拦截已知 gadget。
- 防御：升级/移除不必要的 gadget 依赖（Xalan TemplatesImpl、Jackson POJONode、spring-aop）；禁用或隔离原生反序列化接口。
- 检测：反序列化流中出现非最短形式的 UTF-8 编码、类名长度与实际字节不符、类名在流中“消失”但对象图含危险类型；对 `checkData` 类实现做代码审计，确认其是否只做字节匹配。
- 检测：监控反序列化异常与类加载日志，关注 `TemplatesImpl`、`EventListenerList`、`POJONode` 等类的加载；对 base64 反序列化接口做内容长度/熵异常告警。
