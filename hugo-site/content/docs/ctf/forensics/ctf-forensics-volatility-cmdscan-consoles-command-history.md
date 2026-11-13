---
id: ctf-forensics-volatility-cmdscan-consoles-command-history
title: Volatility2 cmdline/cmdscan/consoles 三件套：从内存恢复命令行输入与控制台输出，dump 恶意脚本定位 base64 秘密
type: scenario
domain: ctf
path: ctf/forensics
technique: volatility-cmdline-cmdscan-consoles-history
tags:
- forensics
- memory
- volatility
- cmdline
- cmdscan
- consoles
- ctf
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V642
  verified_at: '2026-11-13T02:32:56+08:00'
  notes: 已对照原文 12559 全文与 49 张图核对：cmdline（NOTEPAD.EXE evilscipt.py，图24）、cmdscan（St4G3$1/environment 等，图02/47）、consoles（St4G3$1 后 base64，图04）用法与原文一致；原稿 base64 示例串有误（解出乱码），已按原图 04.png 与标准编码修正为 ZmxhZ3t0aDFzXzFzX3RoM18xc3Rfc3Q0ZzMhIX0=（base64 -d 即 flag{th1s_1s_th3_1st_st4g3!!}）。查重 top 候选均为不同链的 Volatility 排查卡（cmdline/hashdump/netscan triage、mimikatz 等），非重复。CTF 靶场无产品版本，affected_versions 保持省略。未实际运行 Volatility。
url: /docs/ctf/forensics/ctf-forensics-volatility-cmdscan-consoles-command-history/
draft: false
kb_aliases:
- cmdscan consoles 取证
- 内存命令行历史
- 控制台缓冲区取证
- Volatility 命令历史
---

## 一句话结论

Windows 内存镜像里同时保留进程命令行（PEB）、控制台命令历史（csrss 的 COMMAND_HISTORY）和控制台屏幕缓冲区；Volatility2 的 `cmdline`、`cmdscan`、`consoles` 分别能列出进程完整命令行、用户敲过的命令和命令的输出画面，常能直接读到 base64/明文秘密，或据 `notepad evilscipt.py` 这类命令行定位并 dump 恶意脚本再逆向。

## 原理

- `cmdline`：读取每个进程 PEB 的 `ProcessParameters.CommandLine`，能发现“用 notepad/解释器打开的可疑脚本路径”“伪装进程的异常命令行”，是定位待分析文件的第一线索。
- `cmdscan`：从 `csrss.exe` 内存中的控制台命令历史结构（COMMAND_HISTORY，含命令数量、每条命令的进程句柄/应用名）恢复用户输入过的命令，如 `whoami`、`env` 等；即使窗口已关闭，历史仍可能残留。
- `consoles`：解析控制台屏幕缓冲区（CONSOLE_INFORMATION/屏幕缓冲区），恢复命令的**输出**，包括提示符路径、echo 出来的 base64 串等；与 `cmdscan` 互补，一个给“输入”，一个给“输出”。
- 这些结构只存在于内存，磁盘上的命令历史/控制台窗口早已消失；因此内存镜像取证必须先于关机/重启。
- 拿到可疑脚本路径后再用 `dumpfiles`/`memdump` 把脚本或文档落盘，按脚本逻辑逆向（如 XOR+base64）即可还原被处理的数据。

## 触发条件

- 已获取 Windows 内存镜像，profile 匹配（如 `Win7SP1x64`）；
- 目标用户使用过命令行/控制台程序（cmd、powershell、psexec 等）；
- 恶意脚本曾用文本编辑器或解释器打开（命令行留下路径）。

## 利用步骤

1. `imageinfo` 确定 profile。
2. `cmdline` 全量浏览，关注 `notepad <path>`、`cmd /c`、临时目录下的解释器调用。
3. `cmdscan` 看用户敲过的命令历史（可能包含 `env`、`whoami`、脚本执行命令）。
4. `consoles` 看命令输出画面，出现长 base64/hex 串时取出解码。
5. 对可疑脚本路径用 `filescan | grep <文件名>` + `dumpfiles -Q <offset>` 导出，静态复现其加密逻辑。

## PoC

```bash
python2 vol.py -f MemoryDump.raw imageinfo
python2 vol.py -f MemoryDump.raw --profile=Win7SP1x64 cmdline
python2 vol.py -f MemoryDump.raw --profile=Win7SP1x64 cmdscan
python2 vol.py -f MemoryDump.raw --profile=Win7SP1x64 consoles
```

`consoles` 输出中常见 `C:\Users\...\St4G3$1` 提示符后跟一行 base64（如 `ZmxhZ3t0aDFzXzFzX3RoM18xc3Rfc3Q0ZzMhIX0=`，直接 `base64 -d` 即 `flag{th1s_1s_th3_1st_st4g3!!}`）；`cmdline` 中出现 `"C:\Windows\system32\NOTEPAD.EXE" C:\Users\hello\Desktop\evilscipt.py` 即导出该脚本分析（如 `chr(ord(i)^3)` 后 base64 的逆运算）。

## 变体与关联

- 变体：PowerShell 历史（ConsoleHost_history.txt）残留在进程内存时，可用 strings 按路径搜索；`cmdline` 中的 base64/`-enc` 参数也要解码。
- 变体：`consoles` 恢复的是屏幕缓冲区，滚动出屏的内容可能已在 `consoles` 的 dump 中但不在 `cmdscan`，两者都要看。
- 关联：[[ctf-forensics-volatility-filescan-wallpaper-atbash-cmdscan]]——cmdscan 提示 + filescan 壁纸的 Atbash 组合。
- 关联：[[defense-forensics-volatility2-cmdline-hashdump-netscan-triage]]——cmdline 在入侵排查中的用法。
- 关联：[[ctf-forensics-memdump-notepad-edit-control-plaintext]]——从记事本进程内存提取编辑器中的明文。

## 检测与防御

- 该卡为取证分析手法；对攻击方，清屏/关闭窗口并不能清除 csrss 内存中的命令历史与屏幕缓冲。
- 防御/响应：内存镜像优先取证；敏感操作避免在控制台明文执行；事后用同类插件核查命令历史。
