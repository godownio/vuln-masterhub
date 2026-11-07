---
id: ai-security-agent-security-cursor-tasks-json-folderopen-autorun-rce
title: Cursor 打开恶意项目即命令执行：.vscode/tasks.json 的 runOn=folderOpen + task.autoDetect 在缺失工作区信任校验时自动执行
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: cursor-tasks-json-folderopen-autorun-rce
tags:
- ai-security
- agent-security
- cursor
- ide
- vscode
- tasks-json
- workspace-trust
- command-execution
- rce
- malicious-repository
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T13:51:41+08:00'
  notes: '已对照原文全文与10张图核对：tasks.json 结构、runOn=folderOpen、task.autoDetect=on、VS Code 信任提示/Restricted Mode（图09）、Cursor 无信任提示直接执行 calc.exe（图04/10、终端‘正在执行任务: calc.exe’）均与原文一致。已把标题‘绕过 VS Code 工作区信任’改为‘在缺失工作区信任校验时自动执行’，并把 Cursor 未实施 trust gating 的表述标注为原文行为观测+现象推断（原文未做代码级定位）。未验证点：未本机复跑 Cursor；原文未给 Cursor 版本/CVE，未设置 affected_versions；无 sources/source_url。confidence=high 指实测行为，保留。'
url: /docs/ai-security/agent-security/ai-security-agent-security-cursor-tasks-json-folderopen-autorun-rce/
draft: false
kb_aliases:
- Cursor 打开项目 RCE
- Cursor tasks.json 命令执行
- folderOpen 自动任务
- task.autoDetect on
- 恶意 .vscode 目录
- Cursor workspace trust bypass
---

## 一句话结论

Cursor 基于 VS Code，但打开一个含 `.vscode/tasks.json` 的项目时不会像 VS Code 那样先要求“信任作者”再决定是否执行任务：只要任务配置了 `runOn: "folderOpen"`，且项目 `.vscode/settings.json` 中 `task.autoDetect` 为 `on`，Cursor 打开该文件夹就会自动执行任务里的 `command`，攻击者把 `cmd.exe /c calc.exe` 之类命令写入恶意仓库即可在受害者机器上执行任意命令。

## 原理

- **VS Code 任务系统**：工作区级任务定义在 `.vscode/tasks.json`，结构为 `version: "2.0.0"` + `tasks[]`。每个任务可设置 `type: "shell" | "process"`、`command`、`args`、`options.cwd`/`options.env`/`options.shell`，并可用 `windows`/`osx`/`linux` 覆盖不同平台配置。
- **folderOpen 自动触发**：`TaskDescription.runOptions.runOn` 支持 `"folderOpen"`，含义是“包含该任务的文件夹被打开时运行”。这是 VS Code 为构建/初始化任务提供的合法功能，但也意味着任务配置本身就是“打开即执行”的代码。
- **task.autoDetect**：VS Code 通过 `task.autoDetect` 设置控制是否自动检测任务；恶意项目在同目录 `.vscode/settings.json` 写入 `"task.autoDetect": "on"`，确保任务在打开时被识别并自动运行。
- **VS Code 的信任边界**：VS Code 打开未知项目会弹出 “Do you trust the authors of the files in this folder?”；选择不信任会进入 Restricted Mode，任务不会自动执行。也就是说，VS Code 把“打开文件夹”和“执行工作区定义的任务”拆成了两个信任级别。
- **Cursor 缺失这层门**：原文实测用 Cursor 打开同样项目时没有信任提示，直接执行 `tasks.json` 里的命令（截图为计算器被拉起、终端显示 `正在执行任务: calc.exe`）。原文只给出行为观测，未做代码级定位；从现象看，Cursor 作为 VS Code 分支在该场景未生效与 VS Code 等价的 workspace trust / task trust gating，默认把项目当作可信工作区，从而把“打开项目”变成“执行项目内命令”。
- **影响**：攻击者只需诱导受害者用 Cursor 打开一个恶意仓库/压缩包目录（例如从 GitHub 克隆、下载示例项目、接收同事发来的代码包），无需受害者点击运行、无需安装扩展、无需 AI 对话；命令以 Cursor 进程的用户权限执行。若受害者以管理员运行 Cursor，则命令同样具备高权限。
- **隐蔽性**：`.vscode` 目录在资源管理器中默认可能被折叠/隐藏，普通用户不会逐行审查；任务可以设置 `presentation.reveal: "never"`、`echo: false` 等降低可见性，也可以用看似正常的 label（如 `build`、`lint`）掩盖实际命令。

## 触发条件

- 目标使用受影响版本的 Cursor（原文未给出具体版本号，按“打开恶意项目即执行”的实测行为判断；VS Code 本身有信任提示）。
- 受害者用 Cursor 打开攻击者可控的项目目录（克隆仓库、解压压缩包、打开共享目录等）。
- 项目内 `.vscode/tasks.json` 含 `runOn: "folderOpen"` 的任务，且 `.vscode/settings.json` 设置 `task.autoDetect: "on"`（或在 Cursor 中该设置默认开启）。
- Cursor 未强制工作区信任、未把任务执行置于 Restricted Mode 之后。
- 任务命令在受害者操作系统上可执行（Windows 用 `cmd.exe`/PowerShell，Linux/macOS 用 `sh`/`bash`）。

## 利用步骤

1. 创建恶意项目目录，加入 `.vscode/tasks.json`：
   - `version: "2.0.0"`；
   - 一个 `type: "shell"` 的任务；
   - `runOptions.runOn: "folderOpen"`；
   - `windows.command` 设为 `cmd.exe /c calc.exe`（或其它命令），Linux/macOS 用 `linux`/`osx` 覆盖。
2. 加入 `.vscode/settings.json`，写入 `{"task.autoDetect": "on"}`，确保任务被自动检测。
3. 把项目打包成 zip/仓库，通过 GitHub、网盘、邮件附件、内部共享、伪装成“示例项目/漏洞复现环境”等方式投递。
4. 诱导受害者在 Cursor 中 `Open Folder` 打开该项目；Cursor 不弹信任提示，直接执行 folderOpen 任务。
5. 验证：计算器/写文件/回连；原文截图为 Cursor 终端显示 `正在执行任务: calc.exe` 且计算器弹出。
6. 授权测试只使用 `calc.exe` 或写无害标记文件，验证后删除 `.vscode` 配置。

## PoC

`.vscode/tasks.json`：

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "cmd",
      "type": "shell",
      "runOptions": {
        "runOn": "folderOpen"
      },
      "windows": {
        "command": "cmd.exe /c calc.exe"
      },
      "linux": {
        "command": "sh -c 'xcalc || gnome-calculator || true'"
      },
      "osx": {
        "command": "open -a Calculator"
      }
    }
  ]
}
```

`.vscode/settings.json`：

```json
{
  "task.autoDetect": "on"
}
```

受害者用 Cursor `Open Folder` 打开该目录后，任务自动运行；原文截图显示终端输出 `正在执行任务: calc.exe` 并弹出计算器。

## 变体与关联

- 变体（隐藏执行）：在任务中设置 `presentation.reveal: "never"`、`echo: false`，或用 `type: "process"` 直接启动程序、把命令拆到 `args`，减少终端可见输出。
- 变体（跨平台）：用 `windows`/`linux`/`osx` 覆盖分别投递 `cmd.exe /c`、`sh -c`、`open -a`；也可用 `options.env` 注入环境变量影响后续构建。
- 变体（持久化）：把命令改为写入 `.vscode/tasks.json` 的保存时任务、修改 `settings.json` 的默认终端/解释器、或结合 `launch.json`，使后续打开/保存/调试继续触发。
- 变体（投递）：恶意项目伪装成“漏洞复现环境”“面试题”“开源工具源码”，或利用供应链（被投毒的仓库/模板）让受害者在日常开发中打开。
- 关联：[[ai-security-agent-security-vscode-agent-autorun-comment-injection-rce]]（VS Code Agent 自动运行 + 注释提示注入；本卡是 Cursor 打开项目即执行任务，不依赖 AI 对话）、[[ai-security-agent-security-zcode-trust-folder-plugin-mcp-admission-bypass]]（另一 AI IDE 的 Trust Folder 旁路）、[[ai-security-agent-security-cursor-hooks-secure-coding-guardrail]]（Cursor hooks 的安全边界）、[[ai-security-supply-chain-python-pth-addsitedir-model-disguise]]（开发环境/供应链投递的另一路径）。
- 边界：VS Code 原版会弹信任提示并可在 Restricted Mode 阻止任务；Cursor 修复版本可能补上信任门。若受害者使用“仅打开单个文件”而非打开文件夹，任务系统不生效；若组织策略禁用 `task.autoDetect` 或工作区任务，链会失败。

## 检测与防御

- 打开项目前检查：审查 `.vscode/tasks.json`、`settings.json`、`launch.json`，重点看 `runOptions.runOn: "folderOpen"`、`type: "shell"`、`command` 中的 `cmd`/`powershell`/`sh -c`/`curl`/`wget`/下载后执行；不明项目先在隔离环境/低权限虚拟机打开。
- 配置加固：在用户/组织策略中关闭 `task.autoDetect`，禁用或限制工作区任务自动运行；使用 VS Code 的 Workspace Trust / Restricted Mode；Cursor 升级到修复版本并确认打开未知项目会弹信任提示。
- 运行隔离：以普通用户（非管理员）运行 Cursor；把不可信项目放在容器/沙箱/无敏感凭据的虚拟机中打开；限制 IDE 进程的出站网络与子进程。
- 检测：监控 Cursor/Code 进程派生的 `cmd.exe`、`powershell.exe`、`sh -c`、`calc.exe` 等异常子进程；监控 `.vscode` 目录在克隆/解压后立即出现的 `tasks.json`/`settings.json` 变更；对仓库做恶意配置扫描（`folderOpen`、`task.autoDetect`、可疑 command）。
- 响应：发现自动执行后立即关闭工作区、结束子进程、检查持久化（tasks/settings/launch、启动项、计划任务）、轮换该机器上可能暴露的凭据；保留恶意项目与终端输出作为证据。
- 说明：该技术仅应在授权测试环境验证，示例命令使用计算器等无害载荷。
