---
id: binary-pwn-sandbox-escape-java-policy-single-equals-home-policy-self-grant
title: JVM 沙箱：单等号 policy 叠加 + 可写 user.home 下 .java.policy 自我授权
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: java-securitymanager-policy-merge-home-policy-self-grant
tags:
- java
- sandbox-escape
- securitymanager
- policy
- privilege-escalation
- filesystem
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3
  verified_at: '2026-11-08T00:37:29+08:00'
  notes: 已对照原文与 2 张图核对：原文「单等号 = 追加到默认策略链、双等号 = 仅用该文件」、java.security 中 policy.url.1/policy.url.2=file:${user.home}/.java.policy、默认 .java.policy 不存在、my.policy 仅授 C:\Users\Administrator\* 的 write、Exp 写 ~/.java.policy 后再次启动弹计算器——卡内数据流、触发条件与 PoC 与原文一致。已修一处：关联里 [[binary-pwn-sandbox-escape-java-reflection-protectiondomain-hasallperm]] 指向不存在的 id，改为 [[binary-pwn-sandbox-escape-protectiondomain-hasallperm-reflection]]（同批同 ID 的实际卡名）。未验证点：未在 JDK8 复跑该 PoC、未核实各发行版默认 java.security 是否都是 policy.url.2 指向 ~/.java.policy。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-java-policy-single-equals-home-policy-self-grant/
draft: false
kb_aliases:
- java.security.policy 单等号
- policy.url.2 .java.policy 自授权
- user.home 可写 逃逸沙箱
- 策略文件叠加绕过
- -Djava.security.policy 一个等号
---

## 一句话结论

`-Djava.security.policy=file`（**一个**等号）不是「替换策略」，而是「把该文件追加到 `java.security` 里 `policy.url.1`/`policy.url.2` 指定的默认策略集」；如果 `user.home` 可写、而默认的 `policy.url.2=file:${user.home}/.java.policy` 文件不存在，沙箱内的代码就能自己创建这个文件写入 `grant { permission ... }`，下一次启动时 JVM 把这份自造策略合并进权限集，从而给自己（或任意 codeBase）授予未在原始策略中允许的权限。

## 原理

- 策略加载遵循 `java.security` 中的 `policy.url.N` 列表；`-Djava.security.policy=<file>`（单等号）的语义是「添加到默认策略」，等价于在列表末尾追加一项；而 `-Djava.security.policy==<file>`（双等号）才是「仅使用该文件、忽略默认策略」。运维/示例脚本里写成单等号是很常见的写法差异，后果是默认两个文件仍然生效。
- `policy.url.2=file:${user.home}/.java.policy` 指向用户家目录；JDK 发行版只自带 `java.policy`，`.java.policy` 默认不存在。用户级策略文件「不存在时被跳过、存在时被合并」——这正是可利用点：攻击者只要能在 `user.home` 下创建该文件，就拥有一份会被 JVM 自动信任的权限来源。
- 策略合并语义是「授权取并集、未列出即拒绝」：追加的 `grant { permission java.io.FilePermission "<<ALL FILES>>", "execute"; }` 直接扩大可执行文件范围；也可以针对特定 `codeBase` 授权，把权限集中到自己加载的代码上。
- 该逃逸不需要任何 JVM 漏洞：它利用的是「默认策略链包含一个用户可写位置」这一部署缺陷，加上应用自己把单等号/双等号搞混，形成「沙箱内的代码能改写沙箱规则」的闭环。
- 生效时机：策略文件在 JVM 启动时读取，因此在同一进程内改写只影响下一次启动；如果外层有调度器/守护进程反复用相同参数拉起 JVM（Web 容器重启、定时任务），一次写入即可在下一轮生效。这也是为什么原文的利用是「先跑一次 Exp 写文件，再跑一次 Exp 弹计算器」。

## 触发条件

- 目标以 `-Djava.security.manager` 启用 SecurityManager，且用**单等号** `-Djava.security.policy=` 指定自定义策略（或未禁用默认策略链）。
- `java.security` 中 `policy.url.2` 指向的 `${user.home}/.java.policy` 不存在（默认常见），且 `user.home` 目录对当前进程可写。
- 原始策略至少授予了「在 `user.home` 下写文件」的权限（例如 `FilePermission "C:\\Users\\...\\*", "write"`），否则连写入这一步都过不去。
- 同一沙箱进程会被重复启动（重启/定时拉起），使写入的策略有机会被加载。

## 利用步骤

1. 确认沙箱启动参数：`ps`/容器配置里看是否 `-Djava.security.manager` 与 `-Djava.security.policy=`（单等号）。
2. 读 `$JAVA_HOME/lib/security/java.security`，确认 `policy.url.2` 指向 `${user.home}/.java.policy`，并确认该文件不存在。
3. 在沙箱内打印 `System.getProperty("user.home")`，确认目录可写（`File.canWrite()` 或直接创建测试文件）。
4. 写入 `~/.java.policy`，内容按需要授予以 `<<ALL FILES>>` 的 `execute`，或对特定 codeBase 授予 `AllPermission`。
5. 触发 JVM 重启（或等待外层守护进程重新拉起），新进程启动时合并该策略。
6. 再次执行同一段利用代码（`Runtime.exec`/`ProcessBuilder`），此时 `checkExec`/`checkRead` 已按合并后的策略放行，命令成功执行。
7. 清理自造的策略文件以降低被发现概率。

## PoC

```java
// 第一步：在沙箱内写 user.home 下的 .java.policy
public class Exp {
    public static void main(String[] args) throws Exception {
        String home = System.getProperty("user.home");
        System.out.println("user.home = " + home);
        String policy = "grant {\n"
                + "  permission java.io.FilePermission \"<<ALL FILES>>\", \"execute\";\n"
                + "};\n";
        java.io.FileWriter w = new java.io.FileWriter(home + "/.java.policy");
        w.write(policy);
        w.close();
    }
}
```

```java
// 第二步：重启后同一段代码即可执行命令（沙箱内原本被拒）
public class Exp2 {
    public static void main(String[] args) throws Exception {
        Runtime.getRuntime().exec("calc");
    }
}
```

```bash
# 单等号：自定义策略被「追加」到默认策略链（默认链仍生效）
java -Djava.security.manager -Djava.security.policy="/path/my.policy" Exp
# 对比：双等号才是「只用该文件」
java -Djava.security.manager -Djava.security.policy=="/path/my.policy" Exp2
```

## 变体与关联

- 变体：策略文件路径由 `policy.url.*` 之外的机制提供（`-Djava.security.properties` 追加配置文件）时，同样可以追加一条新的 `policy.url` 指向自己可写的位置。
- 变体：`user.home` 不可写但 `java.io.tmpdir` 或 `java.ext.dirs` 可写时，若策略里给了对应 codeBase 的 `AllPermission`（默认 `java.policy` 就为 `file:${java.ext.dirs}/*` 授予 AllPermission），把类/扩展放进该目录即可获得全权限。
- 关联：`[[binary-pwn-sandbox-escape-java-setsecuritymanager-null-disable]]`（策略直接授予 `setSecurityManager` 时的一行关停）；`[[binary-pwn-sandbox-escape-protectiondomain-hasallperm-reflection]]`（运行期改 ProtectionDomain，不需要重启）；`[[binary-pwn-sandbox-escape-processbuilder-checkexec-reflection-skip]]`（不重启、不改策略，直接绕过 `checkExec`）。
- 边界：使用双等号策略、`policy.allowSystemProperty=false`、`user.home` 只读、进程不重启、外层用固定只读家目录（容器只读根）时，链断。

## 检测与防御

- 检测：`user.home` 下出现 `.java.policy`；JVM 启动参数中出现单等号 `-Djava.security.policy=`（应与双等号基线比对）；沙箱进程在重启后突然能执行此前被拒的操作。
- 修复：统一使用双等号 `-Djava.security.policy==<file>` 或显式清空默认链；把 `policy.url.2` 指向只读路径或设置为不存在且不可创建。
- 加固：沙箱进程以只读家目录/只读根文件系统运行；对 `java.security` 与策略文件做完整性校验；启动时打印实际加载的 policy 列表并纳入基线。
