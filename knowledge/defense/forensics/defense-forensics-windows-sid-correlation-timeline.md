---
id: defense-forensics-windows-sid-correlation-timeline
title: Windows SID 取证关联：用计算机 SID 前缀与 RID 把 4624/4726/4688 串成横向移动与账户清理时间线
type: scenario
domain: defense
path: defense/forensics
technique: windows-sid-forensic-correlation
aliases:
- Windows SID 取证
- SID 时间线分析
- SID 前缀过滤 4624
- RID 分布分析
- 账户删除事件 4726 关联
- 横向移动 SID 追踪
tags:
- forensics
- windows
- sid
- event-log
- 4624
- 4726
- 4688
- lateral-movement
- registry
- blue-team
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V171
  verified_at: '2026-11-06T11:38:05+08:00'
  notes: 已对照原文核对：SID 结构/前缀、RID 区间、ProfileList 与 SAM 路径、4624/4726/4688 关联步骤、SID 前缀过滤条件与原文及图 06/08 一致；未验证点：文章为取证方法论，无实测数据，黄金票据/克隆 SID 重复等为教科书性描述，卡片已按方法论口径保留。
---

## 一句话结论

Windows 用户名可改、账户可删，但 SID 在其生命周期内保持稳定；取证时以计算机 SID 前缀（`S-1-5-21-<三组数字>-`）过滤安全日志中的 4624 登录事件、按 RID 区间区分内置/本地/迁移账户、用 4726 删除事件和 4688 进程创建事件中的 SubjectUserSid 做前向/横向关联，就能把分散的登录、账户创建/删除、进程执行串成一条可追踪攻击者横向移动与痕迹清理的时间线。

## 原理

- **SID 结构与稳定性**：SID 形如 `S-1-5-21-<机器/域标识>-<RID>`；本机创建的本地账户都以本机计算机 SID 为前缀，域账户以域 SID 为前缀。重命名账户不会改变 SID，删除后 SID 也不会回收复用；因此 SID 比用户名更适合作为跨日志、跨主机的关联键。
- **RID 语义**：RID < 1000 为内置账户/组（500 内置 Administrator、501 Guest、502 krbtgt 等）；1000–9999 通常为本地创建的用户/组；>10000 可能是迁移账户或工具创建账户。RID 分布与创建时间结合可快速识别异常账户。
- **注册表映射**：`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>` 保存 `ProfileImagePath`、`Flags`、`State`，用于 SID→用户配置文件映射；`HKLM\SAM\SAM\Domains\Account\Users\<RID>` 的 `F`/`V` 值保存账户属性、密码哈希时间戳与组信息（需 SYSTEM 权限导出）。
- **事件日志关联**：4624 记录登录类型、TargetUserSid、源 IP/工作站；4720/4726 记录账户创建/删除及 SubjectUserSid；4688 记录进程创建及 SubjectUserSid，可把 PowerShell 等无文件活动绑定到具体身份。
- **攻击链映射**：初始入侵通常对应普通用户 SID；提权后切换到高权限 SID；横向移动出现同一高权限 SID 在多主机/多 IP 的登录；收尾阶段出现批量 4726 删除后门账户。黄金票据等伪造票据可声明任意用户/组 SID，需要结合票据属性与 AD 实际属性做一致性校验，不能只看 SID 字符串。
- **边界**：未 sysprep 的虚拟机模板克隆、第三方备份还原可能造成计算机 SID 重复；域 SID 与本地 SID 可能同时存在；SID 解析可能因域控离线/账户已删除而失败。因此 SID 关联必须与时间戳、源 IP、进程命令行等其他证据交叉验证。

## 触发条件

- 取得 Windows 磁盘镜像、`Security.evtx`、注册表 hive（SAM/SOFTWARE/SECURITY）或集中日志平台中的相应事件。
- 审计策略已启用登录审核、账户管理审核、进程创建审核（4688）；否则关键事件缺失，只能依赖其他数据源。
- 已知或可推导目标计算机的 SID 前缀（可从 ProfileList、本地账户 SID 或镜像中提取）。
- 分析者能解析事件 XML 中的 `TargetUserSid`、`SubjectUserSid`、`TargetSid` 等字段，并保留原始 SID 与解析后的用户名。

## 分析步骤

1. **建立系统基线**：确认 OS 版本/build、安装时间、计算机名、是否加域、RDP/共享配置；从 `ProfileList` 与 `HKEY_USERS` 枚举所有本地/缓存域账户 SID，记录 `ProfileImagePath` 与账户状态。
2. **提取 SID 前缀与 RID 清单**：确定本机计算机 SID 前缀；把账户 SID 按 RID 排序，标记 RID<1000 的内置账户、1000–9999 的本地账户、>10000 的迁移/工具账户；对未知 SID 建立待查清单。
3. **日志粗筛**：在 Security 日志中用 `EventID=4624` 加 SID 前缀条件（如 `Data contains "S-1-5-21-244795756-2605320691-3516395164-"`）筛出该机创建主体的所有登录，再按时间范围、登录类型（2 交互、3 网络、10 RDP）、源 IP/工作站精筛。
4. **账户生命周期关联**：对可疑 SID 回溯 4720（创建）、4722（启用）、4723/4724（改密/重置）、4728/4732（加入特权组）、4726（删除）；按时间排序，识别“创建后迅速加入管理员组又很快删除”的临时后门账户。
5. **进程与无文件活动关联**：用 4688 的 SubjectUserSid 把 PowerShell/wsmprovhost 等进程创建绑定到 SID，结合命令行、父进程、网络连接与 PowerShell 4104 脚本块日志，判断该 SID 是否执行了编码/混淆命令或外联。
6. **横向移动与票据异常**：统计同一高权限 SID 在多台主机、多个源 IP 的登录；检查登录类型与时间段是否偏离基线；对黄金票据告警，核对票据声明的用户 SID/组 SID 与 AD 中该账户实际属性、历史登录是否一致，并关注异常长的票据有效期。
7. **时间线与报告**：把上述事件按 UTC/本地时区统一后排序，标注初始入口 SID、提权 SID、跳板 SID、执行加密/外传的 SID；保留原始 SID 字符串与解析状态，附上注册表/日志证据路径。

## PoC / 查询示例

事件日志筛选（美亚/ELK/Autopsy 等等价查询）：

```text
EventID = 4624 AND Data contains "S-1-5-21-244795756-2605320691-3516395164-"
```

注册表证据位置：

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>
  ProfileImagePath, Flags, State
HKLM\SAM\SAM\Domains\Account\Users\<RID>
  F = 账户固定属性（含密码哈希、时间戳等）
  V = 用户名、描述、主目录、组信息等
```

SID 解析示例：

```text
S-1-5-21-1234567890-0987654321-7355608-1001
  S-1-5-21-...-7355608 = 计算机/域标识前缀
  1001                 = RID（本地创建账户常见起点 1000）
```

时间线关联（伪代码）：

```python
events = load_evtx("Security.evtx")
sid_prefix = "S-1-5-21-244795756-2605320691-3516395164-"

logons = [e for e in events if e.id == 4624 and sid_prefix in e.target_sid]
deletions = [e for e in events if e.id == 4726 and sid_prefix in e.target_sid]
processes = [e for e in events if e.id == 4688 and sid_prefix in e.subject_sid]

timeline = sorted(logons + deletions + processes, key=lambda e: e.time)
```

## 变体与关联

- 变体：以域 SID 前缀追踪域账户在成员机上的登录；以 SID History 识别迁移账户及潜在 SID History 注入；以 ACL 中残留的已删除账户 SID 发现权限后门。
- 变体：无文件攻击中把 4688、PowerShell 4104、Sysmon 1/3/11 与内存取证（Volatility）按 SID 和时间关联；日志被清时改用集中转发日志、IIS 文本日志、Defender 事件等多源时间线。
- 关联：[[defense-forensics-multisource-timeline-log-clear]]（日志被清后的多源时间线重建）、[[defense-forensics-cloudtrail-s3-exfil-identity-trace]]（云侧身份追踪）、[[pentest-ad-recycle-bin-orphan-sid-acl-restore]]（已删除账户 SID 残留 ACL 的滥用）、[[pentest-ad-rbcd-group-allowedtoact-dcsync]]（域内高权限 SID 滥用）。
- 边界：未 sysprep 克隆导致 SID 重复、域控离线导致 SID 解析失败、审计策略缺失导致 4688/4726 不存在时，SID 关联会失效或误判，需要其他证据补强。

## 检测与防御

- **审计配置**：启用登录/账户管理/进程创建审核，开启 PowerShell 模块日志与脚本块日志，部署 Sysmon 并采集命令行；日志实时转发到独立日志服务器，防止本地清除。
- **SID 清单**：维护域/本地账户、服务账户、内置高权限账户的 SID 基线；对新出现 SID、RID>10000 的账户、非工作时间使用 RID 500/512 等行为告警。
- **异常检测**：同一 SID 短时间跨多个 IP/主机登录（不可能旅行）、高权限 SID 从非管理终端登录、创建后迅速加入管理员组又删除的账户、4726 批量删除簇、黄金票据的 SID/组声明与 AD 属性不一致。
- **响应**：确认恶意 SID 后禁用/删除账户并轮换凭据；检查 ACL、计划任务、服务、注册表权限中残留的该 SID；清理后门账户与票据，审计域控 krbtgt 是否需要重置。
