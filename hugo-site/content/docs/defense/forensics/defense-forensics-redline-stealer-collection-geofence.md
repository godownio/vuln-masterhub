---
id: defense-forensics-redline-stealer-collection-geofence
title: RedLine Stealer 信息窃取面：浏览器 Login Data/Autofill、Telegram tdata、Discord leveldb、Steam/钱包、FileZilla、VPN DPAPI 与 ip.sb 地理围栏
type: scenario
domain: defense
path: defense/forensics
technique: redline-stealer-collection-geofence
tags:
- forensics
- malware
- infostealer
- redline
- browser-credentials
- telegram
- discord
- steam
- crypto-wallet
- filezilla
- vpn
- dpapi
- geofencing
- incident-response
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V283
  verified_at: '2026-11-08T04:58:55+08:00'
  notes: 已对照原文与全部 33 张图核对：Discord leveldb *.log/*.ldb、Telegram tdata 长度 16 子目录、Steam 注册表 SteamPath 与 *s?fn*/config/*.vdf、Atomic/Armory/Exodus/Guarda/Jaxx、FileZilla sitemanager.xml(Account)、浏览器 DataContract、NordVPN user.config Base64+DPAPI LocalMachine、ProtonVPN 反转 *ovpn、api.ip.sb/geoip + blockedCountry/BlockedIP → Environment.Exit(0) 均一致。已修正原卡把 Steam 的 config/*s?fn* 误并入 Telegram 描述的问题。原子性：加载器（投放/解密落盘）与窃取面（信息收集）是两个独立技术原子；窃取面内各目标为同一收集模式的不同变体，未再拆分为宜，不判过粗。未执行样本；原文未声明样本版本，未设置 versions。
url: /docs/defense/forensics/defense-forensics-redline-stealer-collection-geofence/
draft: false
kb_aliases:
- RedLine 窃取目标
- RedLine 信息窃取分析
- RedLine 浏览器凭据
- Telegram tdata 窃取
- Discord leveldb 窃取
- 钱包文件窃取 Atomic Armory Exodus Guarda Jaxx
- FileZilla sitemanager.xml
- NordVPN DPAPI 解密
- ProtonVPN ovpn 窃取
- ip.sb 地理围栏
---

## 一句话结论

RedLine Stealer（实际主体为伪装成 `winlogon.exe` 的 .NET 程序）按固定路径和模式收集主机敏感数据：Discord `%appdata%\discord\Local Storage\leveldb` 的 `*.log`/`*.ldb`、Telegram `tdata`（长度 16 的子目录）、Steam 注册表 `SteamPath`（`*s?fn*`、`config`、`*.vdf`）、Atomic/Armory/Exodus/Guarda/Jaxx 钱包目录、FileZilla `sitemanager.xml`（解析 Host/Port/User/Pass）、浏览器版本/账户/Autofill 对象，以及 NordVPN `user.config`（Base64 + DPAPI `LocalMachine` 解密）和 ProtonVPN `*.ovpn`；同时通过 `api.ip.sb/geoip`（备用 `ipinfo.io/ip`、`api.ipify.org`）获取 IP/城市/国家/邮编，若命中 `blockedCountry`/`blockedIP` 则 `Environment.Exit(0)` 退出，形成地理围栏。

## 原理

- **Discord**：`Environment.ExpandEnvironmentVariables("%appdata%\\discord\\Local Storage\\leveldb")`，用 `Directory.GetFiles` 匹配 `*.log`、`*.ldb`，读取本地存储的 Token/缓存数据。
- **Telegram**：以 `SystemInfoHelper` 搜索 Telegram 进程/安装目录，取 `tdata` 目录；遍历 `tdata` 下长度为 16 的子目录（账户数据），按 `*` 匹配收集，打包外传。
- **Steam**：`Registry.CurrentUser.OpenSubKey("Software\\valve\\steam")` 读取 `SteamPath`，校验目录存在后收集 Steam 配置：根目录 `*s?fn*`（ssfn 账户文件）、`config` 下的 `*.vdf`（文章文字亦提及 ssfn/config/.vdf）。
- **加密钱包**：按 `Environment.GetFolderPath(ApplicationData)` 拼接目录并递归/非递归匹配：`\atomic`（`*` 递归）、`\Armory`（`*.wallet`）、`\Exodus`（`*.json` + 目录）、`\Guarda`（`*` 递归）、`\jaxx`；每个收集器类有 `Name` 属性和路径过滤逻辑。
- **FileZilla**：读取 `%appdata%\FileZilla\sitemanager.xml`，`XmlTextReader`/`XmlDocument` 解析 `<Server>` 节点，把 `Host`、`Port`、`User`、`Pass` 组装成 `Account { URL, Username, Password }`。
- **浏览器**：定义 `BrowserVersion { NameOfBrowser, Version, PathOfFile }`、`Account { URL, Username, Password }`、`Autofill { Name, Value }` 等 DataContract，配合浏览器目录/配置读取（文章主要展示对象模型，未展开 Chromium DPAPI 解密细节）。
- **VPN**：NordVPN 读取 `%USERPROFILE%\AppData\Local\...\user.config`，`XmlDocument.SelectSingleNode` 取设置值，Base64 解码后用 `ProtectedData.Unprotect(..., DataProtectionScope.LocalMachine)` 还原用户名/密码；ProtonVPN 在 `%USERPROFILE%\AppData\Local\ProtonVPN` 下按反转字符串得到的 `*ovpn` 模式收集 OpenVPN 配置。
- **地理位置与地理围栏**：`WebClient.DownloadData("https://api.ip.sb/geoip")` 获取 JSON，解析 `ip`（含冒号视为 IPv6 并置空）、`postal_code`、`country_code`；备用 `https://ipinfo.io/ip` 与 `https://api.ipify.org` 只取 IP。`ScanResult` 写入 `IPv4/City/Country/ZipCode`；若 `scanningArgs.BlockedCountry` 或 `BlockedIP` 命中当前值，直接 `Environment.Exit(0)`，避免在特定国家/IP 段运行（反分析/定向规避）。
- **为什么有效**：所有路径都是用户态可读文件/注册表，运行账号可访问；钱包/浏览器/VPN 的敏感数据常以明文或可解密形式保存在用户目录；地理围栏降低在分析师所在地区/沙箱 IP 的运行概率。
- **边界**：硬件 Keystore/浏览器 App-Bound Encryption、开启 EFS/权限隔离或数据不落盘时可能拿不到；NordVPN DPAPI 解密依赖同机/同用户或 LocalMachine 范围；Telegram/Discord 版本变化会改变目录结构。

## 触发条件

- Windows 主机运行 RedLine 主体（伪装 `winlogon.exe`），具备用户上下文文件读取权限。
- 主机上安装/登录了 Discord、Telegram、Steam、Atomic/Armory/Exodus/Guarda/Jaxx、FileZilla、NordVPN/ProtonVPN、浏览器等目标软件。
- 样本可出网访问 `api.ip.sb`/`ipinfo.io`/`api.ipify.org`（或在无网时使用备用信息）；当前 IP/国家不在样本的 `blockedCountry`/`blockedIP` 列表中。
- C2 通道可用，窃取结果可打包外传。

## 利用步骤

1. 在隔离环境运行/静态分析样本，定位收集器类（`Class15/Class16/...` 等）与 `Name` 属性（Armory、Atomic、Exodus、Guarda、Jaxx 等）。
2. 逐个还原路径与匹配模式：`%appdata%\discord\Local Storage\leveldb`（`*.log`/`*.ldb`）、`tdata`（长度 16 子目录）、Steam 注册表 `SteamPath`（`*s?fn*`、`config/*.vdf`）、各钱包目录/扩展名。
3. 分析 FileZilla `sitemanager.xml` 的 XML 解析与 `Account` 组装；记录窃取的 Host/Port/User/Pass 字段。
4. 分析 VPN：NordVPN `user.config` 的 XML 取值 + Base64 + `ProtectedData.Unprotect(LocalMachine)`；ProtonVPN `*.ovpn` 搜索模式（字符串反转还原）。
5. 分析浏览器对象模型（BrowserVersion/Account/Autofill）与对应浏览器目录；如样本包含 Chromium 凭据解密，可按 `Local State`/`Login Data`/DPAPI 链进一步还原。
6. 分析地理围栏：`api.ip.sb/geoip` 解析、`blockedCountry`/`blockedIP` 命中即 `Environment.Exit(0)`；据此判断样本的规避地区/沙箱策略。
7. 在受害主机上按上述路径检查文件访问/打包痕迹（见检测与防御），评估泄露范围。

## PoC

无独立脚本；以下为静态分析要点（路径/类名以样本为准）：

```text
# Discord
%appdata%\discord\Local Storage\leveldb  ->  *.log / *.ldb
# Telegram
<Telegram>\tdata  ->  16 字符子目录（Pattern=*）
# Steam
HKCU\Software\Valve\Steam : SteamPath  ->  *s?fn* ; config\*.vdf
# Wallets
%appdata%\atomic   (*, recursive)
%appdata%\Armory   (*.wallet)
%appdata%\Exodus   (*.json, *)
%appdata%\Guarda   (*, recursive)
%appdata%\jaxx
# FileZilla
%appdata%\FileZilla\sitemanager.xml -> Server/Host/Port/User/Pass -> Account
# NordVPN
%USERPROFILE%\AppData\Local\...\user.config
  -> XmlDocument.SelectSingleNode(...).InnerText
  -> Convert.FromBase64String -> ProtectedData.Unprotect(LocalMachine)
# ProtonVPN
%USERPROFILE%\AppData\Local\ProtonVPN  ->  *.ovpn
# Geo
WebClient.DownloadData("https://api.ip.sb/geoip")
  -> ip / postal_code / country_code
  -> blockedCountry/blockedIP 命中则 Environment.Exit(0)
```

## 变体与关联

- [[code-analysis-reverse-windows-redline-dotnet-aes-resource-dropper]]：同一 RedLine 样本的加载器/投放器分析；本卡是其落盘主体 `winlogon.exe` 的窃取逻辑。
- [[pentest-privilege-escalation-chromium-v10-dpapi-credential-decrypt]]：Chromium v10 凭据的 DPAPI 主密钥 + AES-256-GCM 离线解密；可用于补全本卡未展开的浏览器凭据解密细节。
- [[pentest-privilege-escalation-dpapi-localmachine-registry-credential]]：`ProtectedData.Unprotect(LocalMachine)` 解密应用密文的同类手法，与 NordVPN 分支一致。
- [[defense-forensics-chromium-artifact-offline-decrypt]]：Chromium 数据离线解析与七类数据还原，可作为浏览器窃取面的取证对照。
- 变体：不同 RedLine 版本/变种会增删钱包、VPN、IM 目标，路径与匹配模式随版本变化；地理围栏的 blockedCountry/blockedIP 列表也随样本配置不同。
- 边界：硬件加密/App-Bound Encryption、文件权限、软件未安装或未登录会导致对应收集器空跑。

## 检测与防御

- **检测（主机文件访问）**：进程 `winlogon.exe`/`svchost.exe`/`chrome.exe`（非系统路径）读取 `%appdata%\discord\Local Storage\leveldb`、Telegram `tdata`、`%appdata%\FileZilla\sitemanager.xml`、钱包目录、`...\user.config`、`*.ovpn`；短时间批量访问多个敏感目录并打包。
- **检测（注册表/网络）**：读取 `HKCU\Software\Valve\Steam\SteamPath`；进程访问 `api.ip.sb`、`ipinfo.io`、`api.ipify.org`；随后向 C2 上传压缩包。
- **检测（样本特征）**：`ScanResult`/`blockedCountry`/`blockedIP`/`Environment.Exit(0)`、`DataProtectionScope.LocalMachine`、`BrowserVersion`/`Autofill` DataContract、钱包目录字符串（atomic/Armory/Exodus/Guarda/jaxx）等。
- **防御**：EDR 对上述路径组合访问告警；限制不可信程序读取浏览器/钱包/VPN 配置（应用隔离、凭据保护、硬件 Keystore）；启用浏览器 App-Bound Encryption 与 DPAPI 保护；对 `%AppData%` 新 PE 与伪装进程监控；及时轮换被窃取的账号/钱包助记词/VPN 凭据。
- **响应**：隔离主机；检查 Discord/Telegram/Steam/钱包/FileZilla/VPN 的登录与资金活动；重置相关口令、撤销 Token、迁移加密资产；保留样本与访问日志用于溯源。
