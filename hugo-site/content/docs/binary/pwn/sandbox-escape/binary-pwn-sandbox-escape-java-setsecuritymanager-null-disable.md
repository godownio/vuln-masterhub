---
id: binary-pwn-sandbox-escape-java-setsecuritymanager-null-disable
title: 策略授予 setSecurityManager 时一行 System.setSecurityManager(null) 关停沙箱
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: java-securitymanager-setnull-disable
tags:
- java
- sandbox-escape
- securitymanager
- runtimepermission
- privilege-escalation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3
  verified_at: '2026-11-08T00:37:43+08:00'
  notes: 已对照原文核对：原文「策略授予 java.lang.RuntimePermission setSecurityManager 时可 System.setSecurityManager(null) 关停、随后 Runtime.exec 弹计算器」与卡内一句话结论/触发条件/PoC 一致；原理段 System.security 静态引用、checkPermission 门槛、与反射改域的区别均成立。已修 2 处：①关联里 [[binary-pwn-sandbox-escape-java-reflection-protectiondomain-hasallperm]] 为不存在的 id，改为 [[binary-pwn-sandbox-escape-protectiondomain-hasallperm-reflection]]，并补 [[binary-pwn-sandbox-escape-processbuilder-checkexec-reflection-skip]]；②原文口径为 SecurityManager「Java 1.0 - Java 16」，卡片原写「JDK 17+ 已移除、JDK 8–16 成立」表述不准，改为 JDK17/JEP411 deprecated、JDK18 动态安装默认需 allow、JDK24/JEP486 移除。未验证点：未在 JDK8 复跑 PoC、未验证 JDK18+ 的 allow 开关细节。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-java-setsecuritymanager-null-disable/
draft: false
kb_aliases:
- setSecurityManager(null)
- 关停安全管理器
- RuntimePermission setSecurityManager
- 一行绕过 Java 沙箱
- SecurityManager 置空
---

## 一句话结论

`System.setSecurityManager(null)` 本身也受 `RuntimePermission("setSecurityManager")` 保护；但如果自定义策略为了「方便」显式授予了这条权限（常见于要求脚本能自管安全上下文的场景），沙箱内的代码只需一行 `System.setSecurityManager(null)` 就把安全管理器整个卸掉，之后的 `Runtime.exec`、文件读写、套接字连接全部不再经过权限检查——沙箱从「细粒度限制」退化为「完全无限制」。

## 原理

- SecurityManager 不是内核能力，而是 JVM 内的一个可写静态引用（`System.security` 字段）。所有 `checkXxx` 调用都先取这个引用，为 `null` 时直接返回（`System.getSecurityManager()==null` 即放行）。
- `System.setSecurityManager` 的实现里，只有在「将要替换/清除已有管理器」时才调用 `checkPermission(new RuntimePermission("setSecurityManager"))`；因此这条权限是唯一的门槛。策略里出现 `permission java.lang.RuntimePermission "setSecurityManager";` 就等于把门槛拆掉。
- 这是「自指式缺陷」：授予该权限的初衷通常是让受信代码能安装/切换自己的安全管理器，但同一权限也允许卸载；授权模型没有区分「安装」与「卸载」，被约束代码一旦拿到它就完成了自我解放。
- 与反射改 `hasAllPerm` 的区别：改 ProtectionDomain 只让当前栈帧通过检查，后续仍受策略约束；置空 SecurityManager 是全局生效、对所有代码路径永久生效（直到进程结束或有人重新安装）。
- 该手法不依赖 JDK 漏洞，只在 JVM 仍支持 SecurityManager 时成立（原文口径：用于 Java 1.0–16；JDK 17/JEP 411 起该机制被 deprecated，JDK 18 起动态安装默认需 `-Djava.security.manager=allow`，JDK 24/JEP 486 已彻底移除该机制）；一旦生效，等同「沙箱不存在」。

## 触发条件

- 目标 JVM 启用了 SecurityManager（`-Djava.security.manager`）。
- 生效策略中显式授予了 `java.lang.RuntimePermission "setSecurityManager"`（自定义 `my.policy` 或 `grant { ... }` 通配授权里包含它）。
- 攻击者能在该 JVM 内执行任意 Java 代码（表达式注入、反序列化、脚本沙箱、插件机制等）。
- 进程在卸载后仍继续运行（同一请求/同一脚本会话内即可完成后续操作）。

## 利用步骤

1. 读策略：从启动参数拿到 `-Djava.security.policy` 指向的文件，或从 `$JAVA_HOME/lib/security/java.policy` 与 `~/.java.policy` 读出实际生效的授权列表。
2. 在列表中查找 `RuntimePermission "setSecurityManager"`（也检查是否有 `AllPermission` 或 `RuntimePermission "*"` 这类通配）。
3. 在沙箱内执行 `System.setSecurityManager(null)`；若抛 `SecurityException` 说明未授予，链断。
4. 成功后立刻执行原本被拒的操作（`Runtime.getRuntime().exec("...")`、读 `/etc/passwd`、外连）验证沙箱已失效。
5. 若需要在同一进程内「恢复」以降低异常（可选），可先保存原管理器引用再置空，操作完再装回。

## PoC

```java
public class Exp {
    public static void main(String[] args) throws Exception {
        // 策略授予 RuntimePermission("setSecurityManager") 时成功
        System.setSecurityManager(null);
        Runtime.getRuntime().exec("calc");
    }
}
```

```bash
# my.policy：唯一授予的就是这条「卸载权」
cat > my.policy <<'EOF'
grant {
    permission java.lang.RuntimePermission "setSecurityManager";
};
EOF

java -Djava.security.manager -Djava.security.policy="my.policy" Exp
```

```text
# 预期：沙箱内可执行任意命令；若策略未授予该权限则抛出
# java.security.AccessControlException: access denied ("java.lang.RuntimePermission" "setSecurityManager")
```

## 变体与关联

- 变体：策略用通配授予 `RuntimePermission "*"` 或 `AllPermission` 时同样包含该权限，效果一致。
- 变体：先 `System.getSecurityManager()` 存引用，置空执行操作后再 `setSecurityManager(old)` 装回，减少后续业务异常、便于在同一请求内「用完即恢复」。
- 变体：通过反射写 `System.security` 字段也能达到同样效果，但需要 `suppressAccessChecks`；本卡是不需要反射的直接路径。
- 关联：`[[binary-pwn-sandbox-escape-java-policy-single-equals-home-policy-self-grant]]` 是通过可写策略文件在下次启动时扩大权限；`[[binary-pwn-sandbox-escape-protectiondomain-hasallperm-reflection]]` 是运行期改当前域；`[[binary-pwn-sandbox-escape-processbuilder-checkexec-reflection-skip]]` 是运行期只跳过单条检查；本卡是运行期直接卸载。
- 边界：策略未授予该权限、目标 JDK 已不再支持 SecurityManager（JDK 17 起标记 deprecated、JDK 18 默认禁止动态安装、JDK 24 永久移除，原文口径为「适用于 Java 1.0–16」）、进程被外部监控在卸载后立即重启管理器、或后续操作依赖已被卸载的管理器状态导致业务校验异常时，利用受限。

## 检测与防御

- 检测：策略文件中出现 `RuntimePermission "setSecurityManager"`（应视为高危配置）；运行期 `System.setSecurityManager` 调用（可 hook 该方法或监控安全管理器从非 null 变为 null）。
- 修复：从策略中删除 `setSecurityManager` 授权，禁止 `RuntimePermission "*"`/`AllPermission` 的宽泛授予；需要切换管理器的受信代码用独立的 `doPrivileged` 段完成。
- 加固：以 `SecurityManager` 之外的隔离层（独立进程/容器/seccomp）承载不可信代码；对沙箱进程做系统调用级限制，避免「JVM 内安全管理器」成为唯一边界。
