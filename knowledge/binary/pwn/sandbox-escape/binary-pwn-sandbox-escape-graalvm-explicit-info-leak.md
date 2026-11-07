---
id: binary-pwn-sandbox-escape-graalvm-explicit-info-leak
title: GraalVM HostAccess.EXPLICIT 下 toString 与异常堆栈泄露宿主类名和源路径
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: graalvm-explicit-info-disclosure
aliases:
- GraalVM 信息泄露
- HostAccess.EXPLICIT toString
- 沙箱异常堆栈泄露
- GraalJS 类名泄露
- PolyglotException 堆栈
tags:
- graalvm
- polyglot
- sandbox
- information-disclosure
- exception
- javascript
- java
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V6
  verified_at: '2026-11-05T00:54:39+08:00'
  notes: 已对照原文与20张图核对：EXPLICIT 下 getClass/hashCode 为 undefined 而 toString 可调用，输出 com.security.research.ScriptHelper@293bb8a5；类型错误异常泄露 long 参数类型与 "key" 变量名，e.stack 泄露 SandboxedScriptEngine.java:24/36 行号，均与卡片一致。卡片明确边界为信息泄露、不证明直接RCE。未验证点：未在本机复现；无受影响版本区间，未设versions。
---

## 一句话结论

即使使用 `HostAccess.EXPLICIT`，GraalVM 在字符串拼接时仍会隐式调用宿主对象的 `toString()`，异常对象也会带回 Java 调用栈；脚本可获得完整类名、包路径、参数类型、源码文件名与行号，为进一步逃逸提供精确情报。

## 原理

- `HostAccess.EXPLICIT` 只允许访问标注 `@HostAccess.Export` 的 public 成员，`getClass()`、`hashCode()` 等 Object 方法不可见，直接反射链被阻断。
- 但 GraalVM 在 JS 字符串上下文中会把宿主对象转换为字符串，此时会调用其 `toString()`。默认 `Object.toString()` 返回 `类名@哈希`，因此 `'' + scriptHelper` 会泄露 `com.security.research.ScriptHelper@...`。
- 当脚本以错误类型调用 `@Export` 方法时，GraalVM 抛出的 `PolyglotException` 包含 Java 侧的转换错误、参数类型、内部变量名，以及 `e.stack` 中的完整调用链（含框架类名、源码文件名和行号）。
- 这些信息本身不直接执行代码，但能把黑盒沙箱变成可定位的白盒目标：攻击者据此确认类加载路径、依赖版本、源码结构，进而选择对应的反射/反序列化/组件利用链。

## 触发条件

- 脚本在 `HostAccess.EXPLICIT`（或更严格）策略下执行，且能访问至少一个注入的宿主对象。
- 应用把 `PolyglotException` 的消息或堆栈回显给脚本/用户，或允许脚本捕获异常并读取 `message`/`stack`。
- 字符串拼接、日志输出等路径未对宿主对象做脱敏。

## 利用步骤

1. 对注入对象做字符串拼接或显式 `toString()`，获取完整类名与哈希。
2. 故意传入错误类型（如把字符串传给 `long` 参数）触发异常，读取异常消息中的参数类型与变量名。
3. 读取 `e.stack`，收集 Java 调用链、框架类名、源码文件与行号。
4. 用得到的包名/类名/版本信息缩小攻击面，再尝试 `HostAccess.ALL` 反射链或其他组件漏洞。

## PoC

```javascript
// 1. toString 泄露类名
var info = '' + scriptHelper;
scriptHelper.log('Object info: ' + info);
// 例: com.security.research.ScriptHelper@293bb8a5

// 2. 类型错误泄露参数类型与变量名
try {
    scriptHelper.formatDate("not_a_number");
} catch (e) {
    scriptHelper.log('Exception message: ' + e.message);
    // 例: Cannot convert 'not_a_number' (JavaScript, type: string) to Java type 'long'
}

// 3. 异常堆栈泄露源码路径与行号
try {
    scriptHelper.formatDate(undefined);
} catch (e) {
    scriptHelper.log('Stack trace:\n' + e.stack);
}
```

典型输出包含：

```text
com.security.research.ScriptHelper@293bb8a5
Cannot invoke "String.toString()" because "key" is null
at <js>.:program(Unnamed:5:1-28)
at org.graalvm.polyglot.Context.eval(Context.java:423)
at com.security.research.SandboxedScriptEngine.executeScript(SandboxedScriptEngine.java:24)
at com.security.research.SandboxedScriptEngine.main(SandboxedScriptEngine.java:36)
```

## 变体与关联

- 变体：`@Export` 方法返回 `Properties`/`Map`/`Runtime` 等复杂对象时，`toString()` 或集合遍历可能泄露系统属性、环境变量、类路径；若同时开启 `allowMapAccess(true)`，可枚举全部键值（原文仅提出设计风险，未给出完整利用）。
- 关联：[[binary-pwn-sandbox-escape-graalvm-hostaccess-all-getclass-rce]]（信息泄露后的下一步反射逃逸）；[[binary-pwn-sandbox-escape-groovy-reflection-blacklist-gaps]]（同类语言沙箱的信息收集）。
- 边界：本卡只证明信息泄露，不证明从 `EXPLICIT` 直接 RCE；若应用不回显异常/不记录脚本日志，泄露面会缩小。

## 检测与防御

- 检测：脚本中出现大量 `toString`、字符串拼接宿主对象、故意类型错误的调用；日志/响应中出现 `com.*` 类名、`java.*` 堆栈或源码路径。
- 防御：不要向不可信脚本暴露宿主对象，或只暴露基本类型/String；异常统一转换为固定错误码，不返回 `PolyglotException` 消息/堆栈；日志中脱敏类名与路径；使用 `SandboxPolicy.UNTRUSTED` 并对输出做过滤。
