---
id: mirth-connect-channel-script-rce
title: Mirth Connect 后台通道脚本 JavaScript 命令执行（Postprocessor 回显 + parameters cmd 马）
type: scenario
domain: web
path: web/java/rce
technique: 后台通道 Deploy/Postprocessor 脚本调用 java.lang.Runtime/ProcessBuilder 执行命令，经 Response:Postprocessor 与 sourceMap parameters 实现 HTTP 回显
tags:
- mirth-connect
- java
- rce
- processbuilder
- webshell
- healthcare
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-32
  verified_at: '2026-11-08T16:13:07+08:00'
  notes: 已对照原文核对：通道脚本调 Java class 执行命令、Response:Postprocessor 回显、sourceMap parameters 参数化 cmd 马三段链与原文一致；运行证据核实（图10 calc、图13 ipconfig 回显、图16 ?abc=whoami 返回 desktop-hlif4ln 用户名）；Jetty 内存马失败实验已并入变体节（defineClass 可加载 class 但 WebAppClassLoader 位于脚本线程 URLClassLoader 子层级，arthas classloader -t 图32 佐证，父加载器无法加载子加载器类，agent/vagent 路线为补充说明）；4.5.1 为图05 管理界面标题栏的环境版本而非原文受影响版本标记，affected_versions 正确保持未设置；dedup 候选（Smartbi/Beetl/SpEL）均为不同链；未验证点：未在本地环境复现
url: /docs/web/java/rce/mirth-connect-channel-script-rce/
draft: false
kb_aliases:
- Mirth Connect RCE
- Mirth 通道脚本命令执行
---

## 一句话结论

获得 Mirth Connect 管理后台后，新建 HTTP Listener 通道并在其 JavaScript 脚本（Deploy/Postprocessor）中调用 `java.lang.Runtime.exec` 或 `ProcessBuilder` 即可命令执行，将 Source 的 Response 设为 Postprocessor 可把命令输出经 HTTP 回显，再从 `sourceMap.get("parameters")` 读取 URL 参数即得到参数化 cmd 马。

## 原理

Mirth Connect 通道的脚本编辑器（Deploy、Postprocessor 等位置）在服务端以 Rhino/Nashorn JS 引擎执行，脚本可直接访问当前 classpath 上任意 Java 类（编辑器自带「Use Java Class: Access any Java class in the current classpath」能力），因此 `java.lang.Runtime.getRuntime().exec(...)` 与 `new java.lang.ProcessBuilder(...).start()` 均可执行系统命令——这是产品赋予脚本的设计能力而非漏洞，前提是攻击者已取得管理员后台（弱口令、历史漏洞、凭证复用等）。回显链：通道 Source 连接器类型选 HTTP Listener 并监听端口，Source Settings 的 Response 下拉设为 Postprocessor 后，HTTP 请求的响应体就是 Postprocessor 脚本的 return 值，于是 `new java.util.Scanner(new ProcessBuilder(cmd).start().getInputStream()).useDelimiter("\\A").next()` 的输出直接随 HTTP 返回。参数化：请求的所有键值存于 sourceMap，查询串在 `sourceMap.get("parameters")`（如 `{abc=[whoami]}`），脚本取该值判断 `os.name` 后选择 `cmd.exe /c` 或 `/bin/sh -c` 执行并返回，形成「URL 参数即命令」的 cmd 马。

## 触发条件

- 已获得 Mirth Connect 管理后台权限（Administrator/REST API，常见入口为弱口令）；
- 可新建/修改通道并部署（Deploy）；
- 命令回显需能访问新通道监听的 HTTP 端口（原文实测：目标存在 NAT 时仅能访问登录页而无法触达新通道端口，此时为无回显执行）。

## 利用步骤

1. 登录后台，Channels 右键 New Channel；
2. Source 连接器类型选 HTTP Listener，设置监听端口（如 10086）与 Base Context Path（如 /getABC）；
3. Scripts 页的 Deploy 或 Postprocessor 脚本写 `java.lang.Runtime.getRuntime().exec("calc")` 验证执行；部署通道后触发；
4. 回显：Source Settings 的 Response 选 Postprocessor，脚本改为 `new java.util.Scanner(new java.lang.ProcessBuilder(["cmd.exe","/c","ipconfig"]).start().getInputStream()).useDelimiter("\\A").next()`，访问 `http://host:port/路径/` 即返回命令输出；
5. cmd 马：Postprocessor 中 `var p = sourceMap.get("parameters").get("abc")`，按 os.name 选 shell 后 ProcessBuilder 执行返回，访问 `http://host:port/路径/?abc=whoami` 即回显 whoami 结果。

## PoC

无 PoC（原文实测流程完整：exec("calc") 弹计算器、ProcessBuilder+Scanner 回显 ipconfig、`?abc=whoami` 回显用户名 desktop-hlif4ln\摆，均为 4.5.1 本地环境验证）。

## 变体与关联

- 内存马路线不可行：通道脚本能经 `Thread.currentThread().getContextClassLoader().defineClass` 成功加载任意 class（弹计算器验证），但 Mirth 各端口线程的 contextClassLoader 均为同一 URLClassLoader，Jetty 的 WebAppClassLoader 位于其**子**层级（arthas `classloader -t` 证实），父加载器无法加载子加载器类，常规脚本注入 Jetty 内存马失败；要打到 18080 管理端口需 Java agent 注入（agent 可经 getAllLoadedClasses 拿到子 loader 加载的类，原文用 vagent 成功上马）；
- 关联：所有「后台脚本引擎可直接调 Java class」的平台（Nifi、Kettle、Airlift 等）同理，后台权限≈RCE；
- 与「后台弱口令→功能滥用 RCE」类场景同型，可对比其他 Java 中间件后台命令执行卡。

## 检测与防御

- 审计通道脚本内容告警（出现 Runtime/ProcessBuilder/exec/defineClass 关键字即拦截）；
- 限制后台账户与 REST API 凭证强度，启用 MFA，避免弱口令；
- 通道监听端口不应暴露公网；对 mcserver 进程的子进程创建（cmd.exe/sh 由 java 派生）做 EDR 告警；
- 关注 Java agent attach 行为（vagent/JMG 类工具）。
