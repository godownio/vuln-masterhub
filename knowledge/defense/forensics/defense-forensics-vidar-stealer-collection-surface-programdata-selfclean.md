---
id: defense-forensics-vidar-stealer-collection-surface-programdata-selfclean
title: Vidar Stealer 窃密面：14 款 Chromium Local State、17+ 钱包目录、Thunderbird、WinSCP/FileZilla、跳转列表、$Recycle.Bin、NTFS $Secure 与 SOFTWARE hive，ProgramData 暂存自锁后删除
type: scenario
domain: defense
path: defense/forensics
technique: vidar-stealer-collection-surface
aliases:
- Vidar 窃密目标
- Vidar Stealer 分析
- 浏览器 Local State 收集
- 加密钱包目录窃取
- 跳转列表窃取
- $Recycle.Bin 读取
- NTFS $Secure 读取
- SOFTWARE hive 文件读取
- ProgramData 暂存自删
tags:
- forensics
- malware
- infostealer
- vidar
- browser-credentials
- crypto-wallet
- thunderbird
- winscp
- filezilla
- jump-list
- recycle-bin
- ntfs-secure
- registry-hive
- programdata
- anti-forensics
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V343
  verified_at: '2026-11-08T22:02:04+08:00'
  notes: 已对照图12/13/23-30核对浏览器 Local State、Thunderbird、钱包、WinSCP/FileZilla、跳转列表、$Recycle.Bin、$Secure、SOFTWARE hive 及 ProgramData 锁定/SetDispositionInformationEx 删除/cmd rd 清理；原文未给样本版本。
---

## 一句话结论

注入 `RegAsm.exe` 的 Vidar 窃密体按固定清单收集：14 款 Chromium 系浏览器的 `Local State`、Thunderbird 配置、17 个以上加密钱包目录、Telegram 数据、WinSCP/FileZilla 凭据、Recent 跳转列表、`$Recycle.Bin` 的 `desktop.ini`、NTFS `$Secure:$SDH:$INDEX_ALLOCATION` 以及 `C:\Windows\System32\config\SOFTWARE` hive；所有数据以随机文件名汇总到 `C:\ProgramData\<随机大写目录>`，运行中反复 LockFile/UnlockFile 独占，外传后以 `SetDispositionInformationEx(FILE_DISPOSITION_DELETE)` 删除，并由 `cmd /c timeout /t 10 & rd /s /q <目录>` 兜底清目录。样本未观察到持久化机制。

## 原理

- **浏览器 Local State**：Chromium 系浏览器把加密主密钥/DPAPI 引用等放在 `User Data\Local State`，配合 `Login Data`、`Cookies`、`History`、`Web Data` 等即可离线还原保存的密码与 Cookie。样本枚举了 Chrome、Chrome SxS、Chromium、Amigo、Torch、Vivaldi、Comodo Dragon、Epic Privacy Browser、CocCoc、Brave、CentBrowser、7Star、Chedot、Microsoft Edge 共 14 个品牌的同一路径，说明其目标是尽可能覆盖受害机上装过的浏览器。
- **邮件与 IM**：`%APPDATA%\Thunderbird\Profiles\` 含邮件账户配置与本地邮件库；文中另称收集 Telegram 应用数据。二者都能直接暴露账号、通信内容或会话密钥。
- **加密钱包**：按钱包客户端固定目录收集 `wallet.dat`、keystore/JSON、leveldb/Local Storage 等：Bitcoin、Dogecoin、Raven、Daedalus Mainnet、Blockstream Green、Wasabi Client、Ethereum、Electron、Electron-LTC、Exodus（含 `exodus.wallet` 与 `backups`）、ElectronCash、MultiDoge、atomic（`Local Storage\leveldb`）、Binance、Coinomi（Roaming 与 Local 两处）、Ledger Live（`Local Storage\leveldb`、`Session Storage`）等。钱包文件一旦泄露即可离线导入/解密转移资产。
- **远程连接凭据**：解码字符串含 `Software\Martin Prikryl\WinSCP 2\Configuration`、`...\Sessions`、`UseMasterPassword`、`PortNumber`、`Password:`，以及 `%APPDATA%\FileZilla\recentservers.xml` 和 `<Pass encoding="base64">`；两类客户端都把站点凭据保存在可读配置中，FileZilla 口令仅 Base64 编码。
- **Windows 使用痕迹**：`%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms` 是跳转列表，记录最近打开的文件、常用程序与任务；`C:\$Recycle.Bin\<SID>\desktop.ini` 可暴露回收站内容与原始路径；`C:\$Directory` 形式的 ReadFile 指向 `$Recycle.Bin`、`$Windows.~BT`、`$SysReset` 等系统目录。
- **NTFS 元数据**：读取 `C:\$Secure:$SDH:$INDEX_ALLOCATION`（安全描述符索引）可获取文件安全描述符相关元数据，用于判断文件归属/权限或还原目录结构。
- **注册表 hive**：直接 ReadFile `C:\Windows\System32\config\SOFTWARE`（离线 hive 文件），可在不调用注册表 API 的情况下收集已安装软件、系统配置与部分凭据线索，规避注册表审计。
- **暂存、锁定与清理**：收集结果以随机文件名写入 `C:\ProgramData\HJJDGHCBGDHI`（目录名为随机大写串）；运行中反复 `LockFile`/`UnlockFile`，限制其他进程读取暂存文件；外传完成后用 `SetDispositionInformationEx`（`FILE_DISPOSITION_DELETE`）删除，并启动 `cmd.exe /c timeout /t 10 & rd /s /q "C:\ProgramData\HJJDGHCBGDHI" & exit` 延时清目录；进程随后自终止。没有持久化，说明其定位是一次性窃密。
- **为什么有效**：上述路径全部位于用户可读目录/系统可读文件，普通用户权限即可访问；收集清单覆盖浏览器、钱包、邮件、远程连接与系统痕迹多条变现链；暂存目录随机命名、文件锁与延时删除压缩了取证窗口。

## 触发条件

- Windows 主机运行被注入的 `RegAsm.exe`（或同族 Vidar 载荷），具备当前用户文件读取权限。
- 主机安装/登录了目标浏览器、钱包、Thunderbird、WinSCP、FileZilla、Telegram 等软件，对应目录存在。
- 进程可创建 `C:\ProgramData` 子目录、可启动 `cmd.exe`/`timeout.exe`，并能出网向 C2 回传数据。
- 未启用严格的 EDR 文件访问审计、浏览器 App-Bound Encryption 或钱包硬件加密。

## 利用步骤

1. 注入体启动后先下载/加载 sqlite3 二进制（文中从 C2 取 `sqlx[1].dll` 落到 `INetCache\IE\<随机目录>`），用于解析浏览器/应用数据库。
2. 按清单遍历浏览器 `Local State`、`Login Data`、`Cookies`、`History` 等；读取 Thunderbird `Profiles`、Telegram 数据目录。
3. 遍历加密钱包目录，收集钱包文件、keystore、`Local Storage\leveldb`、`Session Storage` 等。
4. 读取 WinSCP 注册表配置/Sessions 与 FileZilla `recentservers.xml`，提取主机、端口、用户名、口令。
5. 读取跳转列表 `AutomaticDestinations\*.automaticDestinations-ms`、`$Recycle.Bin` 下的 `desktop.ini`、`C:\$Secure:$SDH:$INDEX_ALLOCATION` 与 `config\SOFTWARE` hive。
6. 把结果以随机文件名写入 `C:\ProgramData\<随机大写目录>`，运行中 LockFile/UnlockFile 独占。
7. 通过 TLS C2 回传，完成后 `SetDispositionInformationEx` 删除文件，并由 `cmd /c timeout /t 10 & rd /s /q` 清理目录，进程退出。
8. 取证/分析侧按上述路径检查访问痕迹、暂存目录残留与删除命令时间线，评估泄露范围。

## PoC

以下为观察到的收集目标清单（路径以 `%APPDATA%`/`%LOCALAPPDATA%` 展开，按样本实际访问整理）：

```text
# 浏览器 Local State（14 个品牌，User Data\Local State）
%LOCALAPPDATA%\Google\Chrome\User Data\Local State
%LOCALAPPDATA%\Google\Chrome SxS\User Data\Local State
%LOCALAPPDATA%\Chromium\User Data\Local State
%LOCALAPPDATA%\Amigo\User Data\Local State
%LOCALAPPDATA%\Torch\User Data\Local State
%LOCALAPPDATA%\Vivaldi\User Data\Local State
%LOCALAPPDATA%\Comodo\Dragon\User Data\Local State
%LOCALAPPDATA%\Epic Privacy Browser\User Data\Local State
%LOCALAPPDATA%\CocCoc\Browser\User Data\Local State
%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Local State
%LOCALAPPDATA%\CentBrowser\User Data\Local State
%LOCALAPPDATA%\7Star\7Star\User Data\Local State
%LOCALAPPDATA%\Chedot\User Data\Local State
%LOCALAPPDATA%\Microsoft\Edge\User Data\Local State

# 邮件 / 钱包
%APPDATA%\Thunderbird\Profiles\
%APPDATA%\Bitcoin\wallets\ ; %APPDATA%\Dogecoin ; %APPDATA%\Raven
%APPDATA%\Daedalus Mainnet\wallets\ ; %APPDATA%\Blockstream Green\wallets\
%APPDATA%\Wasabi Client\Wallets\ ; %APPDATA%\Ethereum
%APPDATA%\Electron\wallets\ ; %APPDATA%\Electron-LTC\wallets\
%APPDATA%\Exodus\exodus.wallet ; %APPDATA%\Exodus\backups\
%APPDATA%\ElectronCash\wallets\ ; %APPDATA%\MultiDoge
%APPDATA%\atomic\Local Storage\leveldb\ ; %APPDATA%\Binance
%APPDATA%\Coinomi\Coinomi\wallets\ ; %LOCALAPPDATA%\Coinomi\Coinomi\wallets\
%APPDATA%\Ledger Live\Local Storage\leveldb\ ; %APPDATA%\Ledger Live\Session Storage\

# 远程连接凭据
HKCU\Software\Martin Prikryl\WinSCP 2\Configuration ; ...\Sessions
%APPDATA%\FileZilla\recentservers.xml   (<Pass encoding="base64">)

# Windows 痕迹 / NTFS / 注册表 hive
%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms
C:\$Recycle.Bin\<SID>\desktop.ini
C:\$Secure:$SDH:$INDEX_ALLOCATION
C:\Windows\System32\config\SOFTWARE

# 暂存 / 清理
C:\ProgramData\<随机大写目录>\<随机文件名>
cmd.exe /c timeout /t 10 & rd /s /q "C:\ProgramData\<随机大写目录>" & exit
```

说明：以上为路径与命令级别的观察结果，不含可执行载荷；sqlite3 DLL 的落点为 `%LOCALAPPDATA%\Microsoft\Windows\INetCache\IE\<随机目录>`。

## 变体与关联

- [[defense-forensics-redline-stealer-collection-geofence]]：RedLine 的窃取面（Login Data/Autofill、Telegram tdata、Discord、Steam、钱包、FileZilla、VPN、地理围栏）；与本卡重叠于浏览器/钱包/FileZilla，差异是本卡增加跳转列表、`$Recycle.Bin`、NTFS `$Secure`、SOFTWARE hive、WinSCP 与暂存自锁删除。
- [[defense-forensics-snake-keylogger-stealer-collection-exfil-channels]]：Snake 的浏览器/邮件/IM 窃取面与多通道外传，可对比外传侧。
- [[pentest-privilege-escalation-chromium-v10-dpapi-credential-decrypt]]：拿到 `Local State` 后的 DPAPI/AES-GCM 离线解密，补全浏览器凭据变现链。
- [[ctf-forensics-ntfs-mft-slack-ads-flag-segments]]：NTFS 元数据取证方法，可用于理解 `$Secure:$SDH` 与 `$Recycle.Bin` 的取证价值。
- 变体：不同 Vidar 版本/构建设置会增删浏览器品牌、钱包目录与文件类型；部分版本增加 FTP/SMTP 外传、剪贴板、截图、进程列表等；暂存目录名与清理命令也可变化。
- 边界：浏览器 App-Bound Encryption（Chrome v20+）、钱包硬件加密、文件权限/EFS、未安装对应软件会导致相应收集项为空。

## 检测与防御

- 检测（文件访问）：非浏览器进程（本文为 `RegAsm.exe`）在短时间内批量读取多个浏览器 `Local State`、钱包目录、`Thunderbird\Profiles`、`FileZilla\recentservers.xml`、`config\SOFTWARE`、`$Secure:$SDH:$INDEX_ALLOCATION`；Sysmon EID 11/文件审计出现 `$Recycle.Bin`、`AutomaticDestinations` 读取。
- 检测（暂存/清理）：创建 `C:\ProgramData\<随机大写目录>`；`LockFile`/`UnlockFile` 反复调用；`SetDispositionInformationEx` 带 `FILE_DISPOSITION_DELETE`；命令行出现 `timeout /t 10 & rd /s /q "C:\ProgramData\..." & exit`（`cmd.exe`/`timeout.exe` 由注入进程拉起）。
- 检测（网络）：注入进程向 C2 上传压缩/数据库文件；下载 `sqlx[1].dll` 等 sqlite3 二进制到 `INetCache\IE`。
- 防御：EDR 对上述路径组合访问与随机 ProgramData 目录告警；开启浏览器 App-Bound Encryption、钱包硬件加密/独立密码；限制普通进程读取 `config` hive 与 `$Secure`（需管理员权限的功能谨慎授予）；应用白名单阻止 `RegAsm.exe` 等 .NET 工具异常出站。
- 响应：隔离主机；按清单轮换浏览器保存的密码/Cookie、钱包助记词/私钥、WinSCP/FileZilla/Thunderbird 凭据；检查 `$Recycle.Bin` 与暂存目录残留并固定证据；排查同批次样本的 C2 与下载源。
