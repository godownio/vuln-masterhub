---
id: defense-detection-ghostlocker2-go-ransomware-behavior-ioc
title: GhostLocker 2.0（Go 版）勒索软件执行链与 IOC 检测：Startup 随机名持久化、C2 注册/外传路径与 .ghost 加密
type: scenario
domain: defense
path: defense/detection
technique: ghostlocker2-go-ransomware-behavior-ioc
tags:
- ransomware
- ghostlocker
- ghostsec
- go
- ioc
- detection
- persistence
- exfiltration
- startup-folder
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V503
  verified_at: '2026-11-11T02:47:50+08:00'
  notes: 已对照原文与20/20图核对：Startup 32字节随机名自复制（图15）、/incrementLaunch(form-urlencoded)与/addInfection(application/json) 的 Go net/http 调用（图11/12）、JSON 字段 id/identifier/infection_date/ip/key/ransom_amount/status/username（图13）、taskkill//im/sc stop 字符串拼接（图9/13/14）、.xlsx→/upload→main_encrypt 顺序（图16）、Desktop\Ransomnote.html + cmd /c start（图17）、AES-128/跳过C:\Windows 与4个SHA-256/IOC 均与原文一致；C2 IP 与哈希为时点 IOC，未对样本做本地逆向验证。
url: /docs/defense/detection/defense-detection-ghostlocker2-go-ransomware-behavior-ioc/
draft: false
kb_aliases:
- GhostLocker 2.0
- GhostSec
- STMX_GhostLocker
- GhostLocker RaaS
- .ghost 勒索扩展名
- Ransomnote.html
- incrementLaunch
- addInfection
---

## 一句话结论

GhostLocker 2.0 是 GhostSec 开发的 Golang 勒索软件（RaaS 计划 STMX_GhostLocker），执行链为：将自身复制到 Windows 启动文件夹并以 32 字节随机字符串命名 → `POST /incrementLaunch` 建立 C2 连接 → 生成密钥与加密 ID、把受害者信息以 JSON `POST /addInfection` 注册到 C2 面板 → 按构建器配置用 `taskkill`/服务控制等终止指定进程、服务与计划任务 → 按扩展名列表把目标文件先 `POST /upload` 外传（双重勒索）→ 加密并追加 `.ghost` 扩展名（跳过 `C:\Windows`）→ 在桌面写入 `Ransomnote.html` 并用 `start` 打开勒索信；检测可围绕启动文件夹随机名文件、上述 HTTP 路径/JSON 字段、`taskkill` 批量终止与 `.ghost`/`Ransomnote.html` 痕迹展开。

## 原理

- **持久化**：GhostLocker 2.0 启动后把自身复制到 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`，文件名是运行时生成的 32 字节随机字符串（无扩展名一致性特征，需按“启动目录中新增随机名可执行文件”检测）。早期 Python 版本还带一个监视组件，从启动位置拉起释放的勒索二进制；Go 版去掉了该监视组件。
- **C2 注册协议**：先 `POST http(s)://<c2>/incrementLaunch`（Go 版用 `net/http.(*Client).Post`，`application/x-www-form-urlencoded`，body 含 `username`）表示启动次数；随后在内存中构造 JSON，字段包含 `id`（Beacon/实例标识）、`identifier`、`infection_date`、`ip`、`key`（加密密钥/ID）、`ransom_amount`、`status`、`username`，以 `application/json` `POST /addInfection` 注册感染。C2 面板据此展示受害者、加密状态与收益。
- **反检测与终止**：勒索软件按构建器配置中的列表终止进程/服务/计划任务（示例 `taskkill /f /im soft.exe`；代码中对 `taskkill`、`/im`、`sc`、`stop` 等字符串拼接后 `os/exec.Command` 执行），并支持 `UAC Bypass Attempt`、`Remove Background` 等选项。构建器还提供 `Persistent`/`Watchdog`（可指定看门狗 exe，被查杀后重新拉起）、`SmartCrypt`（自动决定加密范围）、加密目录列表、延迟等配置。
- **先外传后加密（双重勒索）**：加密前按扩展名列表（示例样本配置为 `.doc/.docx/.xls/.xlsx`）搜索文件，通过 `POST /upload` 上传到 C2 服务器，之后才进入加密流程；勒索信声称“文件已被窃取并加密”，并威胁七天不联系就公开数据。
- **加密与勒索信**：加密使用 AES-128（Python 早期版本为 AES-256，勒索信中仍写 RSA-2048 + AES-128 的措辞），加密后文件名追加 `.ghost`，遍历时跳过 `C:\Windows`；完成后把内嵌的 HTML 勒索信写到桌面 `Ransomnote.html`（内含加密 ID、赎金金额、会话链接 `/victimchat?id=<EncryptionID>`），并用 `cmd /c start` 打开。
- **为什么可检测**：上述行为在主机与网络侧都有稳定可观测点——启动目录随机名文件、批量 `taskkill`/`sc stop`、短时间内大量 `.ghost` 文件、桌面新增 HTML 勒索信、固定 URI 的 C2 注册/上传请求；即使样本换版本，URI 与 JSON 字段仍可能复用（Go 版与 Python 版在 `/incrementLaunch`、`/addInfection`、`/upload` 上保持一致）。
- **边界与时效**：本文事实来自 Talos 的公开威胁报告，未对样本做本地逆向；C2 IP 与哈希会随时间失效，URI/字段可能被后续版本修改（GhostSec 已在宣传 GhostLocker V3）。置信度定为 medium。

## 触发条件

- 受害主机为 Windows，用户执行了 GhostLocker 2.0 样本（常见通过钓鱼/暴露面入侵后投递）。
- 主机可访问 C2 服务器（示例 `94[.]103[.]91[.]246`）的 HTTP(S) 端口。
- 样本配置中包含目标扩展名/目录，且当前用户对启动文件夹、桌面和目标文件有写权限。
- 检测方具备进程创建、文件写入、网络代理/流量与启动项监控能力。

## 利用步骤

（以下为分析/检测视角的执行链还原，不是攻击操作指南）

1. 样本落地执行后复制自身到 Startup 目录，文件名 32 字节随机串。
2. 发起 `POST /incrementLaunch`，再以 JSON `POST /addInfection` 注册受害信息（`id`/`ip`/`key`/`infection_date`/`ransom_amount`/`status`/`username`）。
3. 按配置执行 `taskkill`/服务停止/计划任务删除，尝试关闭安全软件并做 UAC 绕过。
4. 按扩展名列表收集文件并 `POST /upload` 外传。
5. 加密文件追加 `.ghost`，跳过 `C:\Windows`；生成加密 ID。
6. 桌面写入 `Ransomnote.html` 并用 `start` 打开，提示通过 `/victimchat?id=<ID>` 联系。

## PoC

无 PoC（文章为威胁情报翻译，未提供样本或可执行代码）。可用于检测的最小特征：

```text
文件：%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\<32 字节随机名>
网络：POST /incrementLaunch（application/x-www-form-urlencoded；含 username）
      POST /addInfection（application/json；含 id/identifier/infection_date/ip/key/ransom_amount/status/username）
      POST /upload（目标扩展名文件外传）
      GET  /victimchat?id=<EncryptionID>、/login?next=
文件：*.ghost、桌面 Ransomnote.html
进程：taskkill /f /im <name>、sc stop <service>、schtasks 删除等批量终止行为
C2：94[.]103[.]91[.]246（时点 IOC）
样本 SHA-256：
a1b468e9550f9960c5e60f7c52ca3c058de19d42eafa760b9d5282eb24b7c55f
8b758ccdfbfa5ff3a0b67b2063c2397531cf0f7b3d278298da76528f443779e9
36760e9bbfaf5a28ec7f85d13c7e8078a4ee4e5168b672639e97037d66eb1d17
8fa28795e4cd95e6c78c4a1308ea80674102669f9980b2006599d82eff6237b3
```

## 变体与关联

- **GhostLocker 1.0（Python）**：同样复制到 Startup（`shutil.copy`），用 `requests.post` 调 `/incrementLaunch`；带监视组件负责从启动位置拉起加密二进制；AES-256；勒索信与 2.0 不同。
- **GhostLocker 2.0（Go）**：去掉监视组件，AES-128，`net/http` 直连 C2；构建器提供 `Persistent`/`Watchdog`、`SmartCrypt`、kill 列表、Run Commands、Delay、UAC Bypass、Remove Background 等选项；宣传中提及 GhostLocker V3 在开发。
- **联合行动**：GhostSec 与 Stormous 联合使用 GhostLocker 与 StormousX 进行双重勒索，RaaS 计划名为 STMX_GhostLocker；相关受害者/赎金数据来自其 Telegram 与 Tor 博客，IOC 中的 IP/哈希为时点值。
- **关联手法**：启动目录随机名持久化、加密前外传、批量杀进程的通用勒索行为，可与 `code-analysis/reverse/windows` 下的勒索软件加密行为卡、`pentest/persistence` 启动项卡对照。
- **其他工具（信息不足未成卡）**：GhostSec 深度扫描工具（Python + BeautifulSoup + BuiltWith 的网站技术栈扫描）与 GhostPresser（用 `wordpress_logged_in` cookie 调 `admin-ajax.php` 安装主题等 WordPress 管理操作）在原文中只有工具菜单/功能描述，未给出登录绕过或利用细节，故仅在此记录。

## 检测与防御

- **主机检测**：启动文件夹新增随机名可执行文件；短时间内大量 `.ghost` 扩展名文件与桌面 `Ransomnote.html`；`taskkill /f /im`、`sc stop`、计划任务删除等批量终止行为；进程访问大量文档后发起 HTTP 上传。
- **网络检测**：HTTP 请求命中 `/incrementLaunch`、`/addInfection`、`/upload`、`/victimchat?id=`、`/login?next=` 等 URI；JSON 含 `identifier`/`infection_date`/`ransom_amount`/`status` 字段；对已知 C2 IP/域名与样本哈希做 IOC 匹配（注意时效）。
- **防御**：终端防护/EDR 行为规则与启动项监控；限制启动文件夹写入与未知程序执行；离线/不可变备份与恢复演练；出站流量白名单，阻断未知 C2；邮件与下载网关拦截样本；一旦感染按勒索事件响应流程隔离、取证、恢复，不支付赎金。
- **情报**：结合 GhostSec/Stormous 的 TTP 与 IOC 更新检测规则；IOC 随版本变化，需以行为特征为主、IOC 为辅。
