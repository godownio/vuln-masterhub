---
id: web-generic-file-upload-defender-process-chain-webshell-command-block
title: Windows Defender 进程链查杀下 WebShell 命令无回显：Unable to fork 的排查与改用大马 Web 层执行
type: scenario
domain: web
path: web/generic/file-upload
technique: defender-process-chain-webshell-command-block-workaround
tags:
- file-upload
- webshell
- windows
- defender
- process-chain
- av-bypass
- troubleshooting
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V513
  verified_at: '2026-11-11T11:22:43+08:00'
  notes: '已对照原文与26张截图逐张核对：图18 Defender 告警 Trojan:Win32/WebShellTerminal.B（CmdLine 为 SysWOW64\cmd.exe /c cd /d C:/inetpub/wwwroot&whoami）、图20 冰蝎仅文件管理可用无命令回显、图21 自带 cmd.exe 仍失败、图22 disable_functions/disable_classes 均为 no value、图23 哥斯拉 505 system(): Unable to fork、图24 改用 exec/shell_exec/passthru 等仍无回显、图25 大马 Web 层执行 tasklist 成功、图26 进程确认只有 Defender，症状/排查顺序/结论与原文一致。原文未给版本，未设 affected_versions。dedup：20 候选均 new；与 encrypted-webshell-av-bypass、image-junk-padding 等静态内容免杀卡不同（本卡为静态已过、文件管理正常但命令执行被 Defender 进程链阻断的动态场景）；与 web-php-rce-godzilla-payload-command-exec-fallback-chain 也不同（后者是 payload 内部函数降级顺序，本卡是主机 AV 进程链阻断与大马绕过）'
url: /docs/web/generic/file-upload/web-generic-file-upload-defender-process-chain-webshell-command-block/
draft: false
kb_aliases:
- WebShell 命令执行无回显
- Unable to fork 505
- Defender 进程链查杀
- w3wp 子进程查杀
- 大马执行命令
---

## 一句话结论

Windows Server + Defender 环境中，已过静态查杀的冰蝎/哥斯拉 WebShell 常出现"文件管理正常、命令执行无回显"：`system()` 返回 505 `Unable to fork`、换 exec/shell_exec/passthru 也无效，原因是 Defender 按 `w3wp.exe`→`cmd.exe` 的进程链与命令行特征拦截；改用不依赖 WebShell 管理工具命令执行通道的"大马"在 Web 层直接调用命令函数即可执行 `tasklist` 等命令。

## 原理

- WebShell 管理工具（蚁剑、冰蝎、哥斯拉）的命令执行模块本质是在 `w3wp.exe`（IIS 工作进程，属于"灰进程"）中调用 `system`/`exec` 等函数拉起 `cmd.exe /c ...`。Defender 的行为监控/ASR 规则会检查父子进程关系与命令行特征（`w3wp.exe` 直接创建 `cmd.exe` 并带 WebShell 常见指令），命中 `Trojan:Win32/WebShellTerminal.B` 一类检测并阻断。
- 阻断发生在进程创建阶段：PHP 的 `system()` 拿到的是 `Unable to fork`（进程无法创建），页面没有命令输出；文件上传/下载/删除只涉及文件系统操作，不触发进程链规则，因此看起来"马是活的、命令却不能用"。
- 与 `disable_functions` 的区分：`phpinfo()` 中 `disable_functions` 为空，且换多种命令函数均失败，说明限制不在 PHP 配置，而在主机安全软件。
- 本地 VM 上对 WebShell 做的免杀测试（静态、动态）不代表真实服务器：真实环境 Defender 规则/云查杀可能更新更强，同一马在目标上仍会被行为拦截。
- "大马"（Web 管理脚本，如各类 PHP 管理面板式脚本）的命令执行页面通过自身代码直接调用命令函数，其进程链与请求特征不同于蚁剑/哥斯拉的命令通道，实例中成功执行 `tasklist`，从而完成命令验证。

## 触发条件

- 目标是 Windows Server（实例为 2016），启用 Defender 或同类 HIPS/EDR。
- WebShell（冰蝎/哥斯拉/蚁剑等）已落地且静态可用（文件管理正常）。
- `disable_functions` 未禁用命令函数，但命令执行被主机安全软件按进程链拦截。
- 上传目录可执行，能上传并访问"大马"脚本。

## 利用步骤

1. 确认症状：WebShell 文件上传/下载/删除可用；命令执行无回显。
2. 排除 PHP 层限制：访问 `phpinfo()` 查看 `disable_functions`、`disable_classes` 是否为空；尝试 `system`、`exec`、`shell_exec`、`passthru`、反引号等多种函数。
3. 排除权限/路径：尝试上传自带 `cmd.exe` 并用绝对路径执行（实例中仍失败，说明不是 cmd 权限问题）。
4. 判断进程链查杀：换用另一种 WebShell 工具（如蚁剑→哥斯拉）仍无回显，并出现 `505 ErrorMsg: system(): Unable to fork`；对照 Defender 告警（如 `Trojan:Win32/WebShellTerminal.B`，受影响项为 `cmd.exe /c cd /d C:/inetpub/wwwroot&whoami`）。
5. 绕过：通过 WebShell 管理工具的文件上传功能直接上传"大马"，访问大马的命令执行页面调用 `tasklist` 等命令（实例成功）；不要把大马做成图片马再解析执行（实例中该方式命令执行失败）。
6. 若大马也被拦截，改用无文件的内存马/合法系统工具执行链（另见 C2 目录相关卡），或等待/利用 Defender 规则差异。

## PoC

```text
# 1) 症状确认：WebShell 命令执行界面返回无输出
# 2) phpinfo 检查：disable_functions = no value
# 3) 哥斯拉执行报错：
#    505 ErrorMsg: system(): Unable to fork [...]
# 4) Defender 告警（示例）：
#    Trojan:Win32/WebShellTerminal.B
#    CmdLine: C:\Windows\SysWOW64\cmd.exe /c cd /d C:/inetpub/wwwroot&whoami&echo ...&cd&echo ...
# 5) 绕过：上传大马至同目录，访问其命令执行页
#    tasklist / whoami 正常返回
```

## 变体与关联

- 变体：Defender 的 ASR 规则（阻止 Office/脚本创建子进程、阻止 WMI 持久化等）会以类似方式阻断命令链，排查思路相同。
- 变体：仅拦 `cmd.exe` 时可尝试 `powershell.exe`、`wmic.exe`、`certutil.exe` 等 LOLBin；但多数规则同样覆盖。
- 关联：[[web-generic-file-upload-encrypted-webshell-av-bypass]]（静态内容免杀，与本卡动态进程链层面互补）；[[web-generic-file-upload-image-junk-padding-both-side-av-bypass]]（图片脏数据静态免杀）；[[web-generic-file-upload-windows-ntfs-data-stream-extension-bypass]]（同篇的上传入口）。
- 限制：取决于目标 Defender 版本与规则强度，本地免杀结果不可外推；大马本身也可能被查杀。

## 检测与防御

- 主机侧：启用 Defender ASR"阻止所有 Office 应用创建子进程"等规则，监控 `w3wp.exe`/`php-cgi.exe` 创建 `cmd.exe`、`powershell.exe` 的进程链；对 Web 目录写入可执行脚本告警。
- Web 侧：上传目录禁止脚本执行，限制写入权限；启用文件完整性监控。
- 应急：发现 `Unable to fork` 与 WebShell 告警时按入侵处置，排查同目录大马、内存马与横向痕迹。
