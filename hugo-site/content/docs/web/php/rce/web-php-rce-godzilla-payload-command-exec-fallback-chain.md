---
id: web-php-rce-godzilla-payload-command-exec-fallback-chain
title: 哥斯拉 PHP payload 命令执行降级链：system→passthru→shell_exec→exec→popen→proc_open→COM→pcntl_exec→Shellshock
type: scenario
domain: web
path: web/php/rce
technique: godzilla-payload-command-exec-fallback
tags:
- php
- webshell
- godzilla
- command-execution
- disable-functions
- bypass
- windows
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V442
  verified_at: '2026-11-09T22:41:12+08:00'
  notes: 已对照原文execCommand源码核对：降级顺序system→passthru→shell_exec→exec→popen→proc_open→COM→pcntl_fork/pcntl_exec→runshellshock与原文一致，path预处理与ob_start回显合并亦一致；原文未逐档实测，卡内已注明无独立PoC。未验证点：未在受限环境逐档验证各回退分支。
url: /docs/web/php/rce/web-php-rce-godzilla-payload-command-exec-fallback-chain/
draft: false
kb_aliases:
- 哥斯拉 execCommand
- Godzilla 命令执行函数降级
- system passthru shell_exec exec popen proc_open COM pcntl
- 哥斯拉 disabled_functions 兼容
- runshellshock 回退
---

## 一句话结论

哥斯拉 PHP payload 的 `execCommand` 模块不是直接调一个命令函数，而是按固定顺序探测可用能力降级执行：`system → passthru → shell_exec → exec → popen → proc_open → COM(WScript.Shell) → pcntl_fork+pcntl_exec → Shellshock`，全部不可用才返回错误；这使同一份马在禁用部分函数、仅有 COM 或仅剩 `putenv`/`error_log` 的受限环境里仍可能执行命令。

## 原理

- **为什么按序降级**：`disable_functions` 通常只禁用一部分函数，攻击者无法预知目标禁了哪些，于是用 `function_existsEx()` 逐个探测，取第一个可用的执行原语。顺序从最简单、回显最直接的 `system` 开始，到过程最复杂的 `pcntl`/Shellshock 结束。
- **各档位的取回显方式不同**：
  - `system`/`passthru` 直接输出到响应缓冲，函数开头的 `ob_start()` 负责捕获；
  - `shell_exec` 返回全部输出字符串；`exec` 只返回最后一行，因此把 `$o` 数组 `join("\n")` 拼回；
  - `popen` 逐行 `fgets` 读取管道；`proc_open` 同时建 stdout/stderr 两个管道分别读完再 `proc_close`；
  - Windows 档用 `COM('WScript.shell')->exec()`，再 `StdOut()->ReadAll()`/`StdErr()->ReadAll()`；
  - `pcntl` 档把命令写入临时文件，`pcntl_fork()` 子进程 `pcntl_exec("/bin/bash", ["-c", "$cmdLine > $resultFile"])`，父进程 `sleep(2)` 后读结果文件，最后删除临时文件；
  - Shellshock 档检查 `/bin/sh` 是否指向 bash，用 `putenv("PHP_LOL=() { x; }; $c >$tmp 2>&1")` 注入环境变量函数，再借 `error_log("a", 1)`（或 `mail(..., "-bv")`）触发子进程执行并读临时文件。
- **PATH 预处理**：Unix 下把 `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` 追加到 PATH；Windows 下追加 `system32`/`SysWOW64`/PowerShell 目录，避免命令因 PATH 缺失找不到。
- **输出合并**：执行结果与 `ob_get_contents()` 合并后返回，再走 `gzencode` 与 XOR/Base64 外层回显。
- **为什么有实战意义**：这解释了哥斯拉流量中的命令回显为何可能来自不同机制——例如禁用 `system` 但保留 `proc_open` 时，子进程与管道行为不同；只剩 `putenv`/`error_log` 时触发的是 Shellshock 子进程而非 PHP 直接执行，检测侧看到的进程链也不同。

## 触发条件

- 目标为哥斯拉 PHP 马，攻击者已通过会话调用 `execCommand` 模块（参数 `cmdLine`）。
- 目标 PHP 至少保留上述任一执行原语或其组合（或被禁用函数列表未覆盖 `pcntl`/`COM`）。
- 仅用于授权测试与恶意流量分析。

## 利用步骤

1. 攻击者发送解密后含 `cmdLine` + `execCommand` 的模块帧（外层按哥斯拉加密器封装）。
2. payload 按顺序探测并选择第一个可用函数执行命令。
3. 结果经 `ob_start` 捕获、`gzencode` 压缩、XOR + Base64 回显。
4. 分析侧按回显内容与主机行为反推实际命中的档位：出现 Bash/子进程、临时文件、`error_log` 调用可指向 pcntl 或 Shellshock 档。

## PoC

无独立 PoC（该链是哥斯拉 payload 的内置实现，触发方式是在会话中调用 `execCommand` 模块；分档执行需在对应受限环境逐项验证，本文未逐档实测）。

## 变体与关联

- 变体：魔改马可增删档位（例如加入 `imap_open`、`LD_PRELOAD`、FastCGI 等），但常见模板保持该顺序。
- 关联：[[web-php-rce-disable-functions-ld-preload]]（LD_PRELOAD 绕过）、[[web-php-rce-godzilla-aes-session-webshell-disguise]]（同一 payload 的会话机制）、[[defense-forensics-godzilla-php-payload-param-framing-module-dispatch]]（`cmdLine`/`execCommand` 的分帧与调度）、[[web-generic-rce-shellshock-cgi-user-agent-env-function]]（Shellshock 原理）。

## 检测与防御

- 检测：PHP 进程中 `popen`/`proc_open`/`pcntl_exec` 子进程、`/bin/bash -c` 或 `cmd.exe /c` 派生、临时目录中出现命令/结果文件对；`error_log`/`mail` 触发的异常子进程。
- 检测：PHP 配置被运行时 `putenv` 注入 `() { :; };` 形态的环境变量（Shellshock 特征）。
- 防御：在 `disable_functions` 中尽量覆盖 `system,passthru,shell_exec,exec,popen,proc_open,pcntl_exec` 等执行函数，并移除 COM 扩展；`putenv`/`error_log` 是否禁用需评估业务兼容性；限制 Web 用户对临时目录与 `/bin/bash` 的执行；主机层监控 PHP 子进程谱系。
