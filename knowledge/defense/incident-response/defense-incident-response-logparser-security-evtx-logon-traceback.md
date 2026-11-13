---
id: defense-incident-response-logparser-security-evtx-logon-traceback
title: Windows 登录溯源：用 LogParser 查 Security.evtx，按 EventID 4624/4625 与时间窗提取用户名和来源 IP
type: scenario
domain: defense
path: defense/incident-response
technique: logparser-security-evtx-logon-traceback
aliases:
- LogParser 溯源
- Security.evtx 登录分析
- 4624 登录成功
- 4625 登录失败
- EXTRACT_TOKEN 提取登录 IP
- Windows 安全日志排查
tags:
- incident-response
- windows
- event-log
- evtx
- logparser
- logon
- triage
- timeline
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V481
  verified_at: '2026-11-10T20:13:25+08:00'
  notes: 已对照原文与9张图核对：4624/4625/4720/4634/4647/4672 事件语义、LogParser -i:EVT -o:DATAGRID 查询、EXTRACT_TOKEN(Strings,5,'|')/EXTRACT_TOKEN(Message,38,' ') 提取用户名与来源 IP、时间窗筛选均与原文一致（原文第二句时间窗被截断，卡内已补全写法并声明）。未验证点：Strings[5]/Message[38] 下标随系统版本/语言漂移，未在真实 evtx 上复跑；图片仅覆盖事件查看器/tasklist/schtasks/注册表等常规排查，未提供 LogParser 实测输出。
---

## 一句话结论

拿到 Windows 的 `Security.evtx` 后，可用 LogParser 的 EVT 输入与类 SQL 语法按 `EventID`（4624 登录成功、4625 登录失败、4720 创建用户、4634/4647 注销、4672 管理员登录）和时间窗筛选事件，再用 `EXTRACT_TOKEN` 从事件的 `Strings` 数组或 `Message` 文本中提取目标用户名与来源 IP，快速还原登录时间线、发现隐藏账号和异常登录来源；字段下标随 Windows 版本/语言漂移，必须先用样本事件校准。

## 原理

- **事件 ID 语义**：安全日志中 4624=登录成功、4625=登录失败、4720=创建用户、4634=注销成功、4647=用户启动的注销、4672=使用超级用户/管理员权限登录。筛选这些事件即可还原“谁在何时从哪台主机登录/被创建/被授予高权限”。
- **LogParser 的 EVT 输入**：`LogParser.exe -i:EVT` 直接解析 `.evtx`，`-o:DATAGRID`/`-o:CSV` 控制输出；查询是类 SQL：`SELECT <字段> FROM <evtx 路径> WHERE <条件>`。`TimeGenerated` 是事件生成时间，可做时间窗过滤。
- **两种取字段视图**：事件的 `Strings` 数组按事件 XML 中 `Data Name=` 的顺序保存字段，4624 里 `Strings[5]` 通常就是 `TargetUserName`；`Message` 是渲染后的整段文本，可用 `EXTRACT_TOKEN(Message, n, ' ')` 按分隔符取第 n 段（如来源地址）。为什么两种都要会：`Strings` 取结构化字段更稳，`Message` 适合快速看人可读内容，但两者位置都可能随系统版本/语言变化。
- **为什么要先校准**：`EXTRACT_TOKEN` 的序号是硬编码的，目标系统的补丁级别、事件结构或系统语言不同都会让序号错位，导致提取出空值或错误字段；先 `SELECT TOP 5 *` 看一条真实事件，再确定索引是必要步骤。
- **溯源价值**：4720（创建用户）与 4624（该账户登录）交叉可发现隐藏/后门账号；4625 短时间大量失败是暴力破解；4624 的登录类型（2 本地交互、3 网络、10 远程桌面）与来源 IP 可区分本地运维与远程入侵；把上述事件按时间排序即可拼出攻击者的登录/账户操作时间线。
- **边界**：审计策略未开启则根本没有这些事件；日志被攻击者清除/轮转时需从备份或集中日志补；`Message` 按空格分词对含空格字段（如 `DOMAIN\user`、带空格的地址）不可靠；LogParser 已停止更新，现代环境可用 `Get-WinEvent -FilterHashtable` 达到同等目的。

## 触发条件

- 能取得 Windows `Security.evtx`（现场导出、镜像提取或集中日志平台导出），并有 LogParser 可执行文件；
- 系统开启了登录审核/账户管理审核（否则 4624/4720 等事件缺失）；
- 已知或可推断事件时间范围、可疑账号或来源 IP，用于缩小查询；
- 仅用于授权应急响应与取证。

## 利用步骤

1. 先复制/导出 `Security.evtx` 并记录哈希，避免直接在原件上操作。
2. 用 `SELECT TOP 5 *` 查看一条 4624 事件的 `Strings` 与 `Message` 实际结构，确认 `TargetUserName`、来源 IP 所在的索引。
3. 按事件 ID 与时间窗筛选：先取 4624/4625 建立登录时间线，再取 4720/4672 找账户创建与管理员登录。
4. 用 `EXTRACT_TOKEN` 提取用户名、来源 IP、登录类型，输出 DATAGRID/CSV 并按时间排序。
5. 把可疑登录与 4720 创建用户、后续进程/服务/任务事件对齐，形成攻击者操作时间线；对来源 IP 与其他主机日志做横向关联。
6. 处置前保留日志证据副本，必要时导出为 CSV 归档。

## PoC

```bat
:: 查看事件结构（先校准字段下标）
LogParser.exe -i:EVT -o:DATAGRID "SELECT TOP 5 * FROM C:\evidence\Security.evtx WHERE EventID=4624"

:: 登录成功事件（全部字段）
LogParser.exe -i:EVT -o:DATAGRID "SELECT * FROM C:\evidence\Security.evtx WHERE EventID=4624"

:: 指定时间窗 + 提取用户名与来源 IP（序号需按目标系统校准）
LogParser.exe -i:EVT -o:DATAGRID "SELECT TimeGenerated, EXTRACT_TOKEN(Strings,5,'|') AS Username, EXTRACT_TOKEN(Message,38,' ') AS SrcIp FROM C:\evidence\Security.evtx WHERE EventID=4624 AND TimeGenerated > TO_TIMESTAMP('2023-02-19 23:32:11','yyyy-MM-dd HH:mm:ss')"

:: 登录失败事件
LogParser.exe -i:EVT -o:DATAGRID "SELECT TimeGenerated, EXTRACT_TOKEN(Strings,5,'|') AS Username FROM C:\evidence\Security.evtx WHERE EventID=4625"
```

以上按文章查询语句整理，补齐了原文省略的路径/时间函数写法；字段下标（`Strings,5`、`Message,38`）依赖事件版本与语言，未在真实 evtx 上复跑，使用前必须用样本事件验证。

## 变体与关联

- 变体：用 PowerShell `Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=...}` 实现同样筛选，见 [[defense-incident-response-windows-cli-only-triage-command-matrix]]。
- 变体：导出 CSV 后用 awk/Excel 按用户名、来源 IP 聚合；对 4625 做频次统计识别暴力破解源。
- 关联：[[defense-forensics-windows-sid-correlation-timeline]]——用 SID 把 4624/4726/4688 串成横向移动与账户清理时间线；[[defense-incident-response-pcap-web-intrusion-attacker-timeline]]——安全日志 4624 类型 10 用于补齐 pcap 中缺失的 RDP 阶段。
- 边界：无审核策略、事件日志被清空时方法失效；`Message` 分词提取对多语言系统不稳定，优先 `Strings` 结构化字段。

## 检测与防御

- 检测（应急/狩猎）：4625 高频失败（暴破）、非办公网来源的 4624 类型 3/10、4720 新增账户后紧接 4672 管理员登录、短时间内 4624 与 4726 交替，都是高价值告警组合。
- 检测（日志完整性）：事件日志服务被停止、Security.evtx 被清空/截断、审计策略被修改（如 4719）都说明攻击者在清理痕迹。
- 防御：开启登录/账户管理/进程创建审核并集中采集到 SIEM；保护日志文件权限与留存周期；对关键域/服务器启用 4624 类型 10 的基线告警。
- 加固：LogParser 停止维护，新环境优先使用 `Get-WinEvent`/SIEM 查询语言；字段提取逻辑做成模板并按系统版本校验。
