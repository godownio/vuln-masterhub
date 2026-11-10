---
id: defense-detection-windows-outbound-ip-authcode-autostart-suspicious-process-triage
title: 反钓鱼/后门自查：用「公网外联 + Authenticode 签名状态 + 自启动归属 + 高危文件名」四要素给进程打分，弹出可疑清单
type: scenario
domain: defense
path: defense/detection
technique: windows-outbound-ip-signature-autostart-process-triage
tags:
- windows
- detection
- triage
- process
- network-connection
- authenticode
- autostart
- persistence
- phishing
- edr
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W
  verified_at: '2026-11-08T17:25:02+08:00'
  notes: 已对照原文核对；本次核对未读取图片；GetTcpTable2 取 dwOwningPid 映射 IP↔进程、isPublicIP 剔除 10/127/172.16-31/192.168/169.254/0、WinVerifyTrust+WINTRUST_ACTION_GENERIC_VERIFY_V2 三态（ERROR_SUCCESS/TRUST_E_NOSIGNATURE/其它）、Run/RunOnce/Wow6432Node/Services 的 RegEnumValue 路径比对、启动目录文件签名扫描、关键词与 com|exe|bat 匹配、AllocateAndInitializeSid+CheckTokenMembership 判管理员后 ShellExecuteExW runas 重启，均与正文逐段一致；卡内对原文两处缺陷的判断（detectTrojanBehavior 恒真、isSystemProcess 内层句柄未关）与代码相符。未验证点：未编译运行；原文为通用自查工具、无产品版本，未设 affected_versions。
url: /docs/defense/detection/defense-detection-windows-outbound-ip-authcode-autostart-suspicious-process-triage/
draft: false
kb_aliases:
- 可疑进程快速自查
- 反钓鱼自查工具
- 外联公网 IP 的进程
- WinVerifyTrust 判定未签名
- 自启动归属比对
- 高危进程名关键词
- 后门排查四要素
---

## 一句话结论

在拿不准一台 Windows 主机上哪个进程可疑时，可以把「是否有公网 TCP 外联」作为第一道筛（`GetTcpTable2` 直接给出 `dwOwningPid`，一次遍历即得 IP↔进程映射），再叠加「文件是否通过 Authenticode 校验」「是否出现在 Run/RunOnce/服务/启动目录/计划任务里」「进程名是否带 `财务/工资/报表/2024/PC` 一类投递话术关键词」四项，把结果按「名称伪造 / 签名伪造 / 无签名」分类弹窗，运维无需 EDR 也能在几分钟内得到一个按可疑度排序的候选清单。

## 原理

- **为什么从外联入手**：钓鱼木马/后门要回连 C2，必然产生出站连接；而正常办公软件的外联目标相对固定。`GetTcpTable2` 返回的 `MIB_TCPROW2` 数组每项自带 `dwOwningPid`，用 `OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ)` + `EnumProcessModules`/`GetModuleBaseNameW`/`GetModuleFileNameExW` 即可把 PID 换成「进程名 + 完整路径」，这一步就把「几万个进程」缩到「有网络活动的几十个」。
- **为什么要剔私网**：`127.0.0.0/8`、`10/8`、`172.16/12`、`192.168/16`、`169.254/16`、`0.0.0.0` 常是本地服务、代理、SMB、mDNS 噪声；只保留公网对端可以显著降低误报（原文第二版即加入 `isPublicIP`）。
- **签名状态为什么有判别力**：`WinVerifyTrust` + `WINTRUST_ACTION_GENERIC_VERIFY_V2` 对文件做完整 Authenticode 校验，返回三类结果——`ERROR_SUCCESS`（签名有效且链可信）、`TRUST_E_NOSIGNATURE`（根本没有签名）、其它错误（有签名但证书不受信/被吊销/被篡改）。正常商业软件几乎都签名，而钓鱼投递的可执行文件绝大多数是「无签名」或「签名无效」；把「签名有效」的进程直接放行，能再砍掉一大半正常软件。
- **自启动为什么能加权**：后门要持久化，通常会写 Run/RunOnce（含 `Wow6432Node`）或注册为服务。把进程路径拿到 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run(Once)`、`Wow6432Node` 同名键、`SYSTEM\CurrentControlSet\Services` 里逐个比对，命中即说明「这个进程是被配置成开机自启的」，可疑度上升；启动目录则用 `FindFirstFile` 列文件并对每个文件做签名校验，未签名的启动项直接列出。
- **文件名关键词为什么有用**：钓鱼附件常用「工资表 / 财务报表 / 人员调整 / 2024 / PC端」这类业务话术命名，并通过 `com/exe/bat` 扩展名投递；把进程名与这类关键词、扩展名做正则匹配，可以抓住「伪装成文档的程序」这一类（原文的 `isHighRiskProcess` 即按关键词 + 扩展名匹配）。
- **四个信号叠加而非单点判定**：单看外联会误报（浏览器、IM、更新程序），单看未签名会误报（内部小工具），单看自启动会误报（大量正常软件）。组合后「未签名 + 有公网外联 + 在自启动里 + 名字像业务文档」几乎必是投递物，而「已签名 + 无自启 + 系统目录」可直接排除。
- **为什么值得自己写而不是只买 EDR**：中小环境没有 EDR、或 EDR 已被 BYOVD/白利用绕过时，这种「只依赖系统 API」的自查工具可以作为独立第二意见；代码里用到的 `GetTcpTable2`/`WinVerifyTrust`/`RegEnumValue` 都不需要驱动、不需要联网。

## 触发条件

- Windows 主机（示例代码 VS2022 编译，需管理员权限以读取其它进程的路径与签名）。
- 怀疑主机被钓鱼投递/存在不明后门，需要在不装额外 agent 的前提下做一次快速自查。
- 主机能出网或至少能本地枚举（`GetTcpTable2` 不依赖外网）。
- 已知本单位的业务话术关键词（用于文件名匹配），否则该维度退化为「仅看扩展名」。

## 利用步骤

1. 提权运行自查程序：先用 `AllocateAndInitializeSid(SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS)` + `CheckTokenMembership` 判断是否管理员，否则 `ShellExecuteExW` 以 `runas` 重启自身。
2. 枚举 TCP 连接：`GetTcpTable2(NULL, &size, TRUE)` 先取长度、再分配、再取表；遍历 `table[i]`，`inet_ntop` 转远端 IP，`dwOwningPid` 转进程名/路径。
3. 过滤：丢弃 `dwRemoteAddr == 0` 与私网/环回/APIPA 网段，只保留公网对端；输出「进程名 + 远端 IP + 完整路径」。
4. 签名判定：对每个进程路径调 `WinVerifyTrust(WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_UI_NONE)`，按返回值分成 `SIGNED_AND_TRUSTED` / `SIGNED_BUT_NOT_TRUSTED` / `NOT_SIGNED`；**签名可信的直接跳过**。
5. 自启动归属：`RegOpenKeyEx` 打开 Run/RunOnce（HKLM 与其 `Wow6432Node`）与 Services，`RegEnumValue` 判断值数据里是否包含该进程路径；另用 `FindFirstFile` 扫描公共与用户启动目录，对目录内文件逐个做签名校验，列出未签名项。
6. 名称匹配：把进程名与「财务/工资/报表/调整/2024/PC」等关键词、`com|exe|bat` 扩展名匹配，命中标为「名称伪造高危进程」。
7. 汇总弹窗：按「名称伪造 / 签名伪造 / 无签名」三类分别列出进程名、PID、路径、远端 IP、是否已加启动，交人工确认与取证。

## PoC

```cpp
// 1) 外联公网 IP 的进程（GetTcpTable2 自带 dwOwningPid）
PMIB_TCPTABLE2 t = nullptr; DWORD sz = 0;
GetTcpTable2(NULL, &sz, TRUE);  t = (PMIB_TCPTABLE2)malloc(sz);
if (GetTcpTable2(t, &sz, TRUE) == NO_ERROR)
  for (DWORD i = 0; i < t->dwNumEntries; i++) {
    DWORD ip = t->table[i].dwRemoteAddr; BYTE *b = (BYTE*)&ip;
    if (b[0]==0 || b[0]==127 || b[0]==10 ||
        (b[0]==192&&b[1]==168) || (b[0]==172&&b[1]>=16&&b[1]<=31) ||
        (b[0]==169&&b[1]==254)) continue;                 // 剔私网/环回
    printf("%s -> %u.%u.%u.%u\n", ProcPath(t->table[i].dwOwningPid).c_str(), b[0],b[1],b[2],b[3]);
  }

// 2) 三类签名状态
WINTRUST_FILE_INFO fi = { sizeof(fi) }; fi.pcwszFilePath = path;
WINTRUST_DATA wd = { sizeof(wd) }; wd.dwUIChoice = WTD_UI_NONE;
wd.fdwRevocationChecks = WTD_REVOKE_NONE; wd.dwUnionChoice = WTD_CHOICE_FILE; wd.pFile = &fi;
wd.dwStateAction = WTD_STATEACTION_VERIFY;
LONG st = WinVerifyTrust(NULL, &(GUID)WINTRUST_ACTION_GENERIC_VERIFY_V2, &wd);
wd.dwStateAction = WTD_STATEACTION_CLOSE;
WinVerifyTrust(NULL, &(GUID)WINTRUST_ACTION_GENERIC_VERIFY_V2, &wd);
// st == ERROR_SUCCESS -> 可信；TRUST_E_NOSIGNATURE -> 无签名；其它 -> 签名无效

// 3) 自启动归属
const wchar_t *keys[] = { L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                          L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                          L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                          L"SYSTEM\\CurrentControlSet\\Services" };
// RegEnumValue 逐个比对值数据是否包含 processPath
```

原文给出的是一套可编译的完整程序（外联枚举 → 私网过滤 → 启动目录/计划任务检查 → 签名过滤 → 高危关键词 → 弹窗）。

## 变体与关联

- **命令行替代**：不想写程序时可用 `Get-NetTCPConnection -State Established` + `Get-AuthenticodeSignature` + `Get-CimInstance Win32_StartupCommand`/`schtasks /query` 组合，逻辑等价但依赖 PowerShell 未被篡改。
- **加权评分而非布尔**：把四个维度做成 0～N 分（未签名 +3、有公网外联 +2、在自启动 +2、名称命中关键词 +2），按分数排序比「任一命中就报警」更实用。
- **数据来源扩展**：`GetExtendedTcpTable` 的 `TCP_TABLE_OWNER_MODULE_ALL` 可直接拿到进程路径；`WinVerifyTrust` 之外可加 `Get-AuthenticodeSignature` 的证书链/签发者信息用于识别「签名但签发者可疑」。
- **关联**：[[defense-incident-response-windows-persistence-triage-run-schtask-service]]（Run/计划任务/服务的逐项核对流程）、[[defense-detection-proram-agent-signed-hello-mutex-run-key]]（同类样本的 RUN 键与签名特征）、[[code-analysis-reverse-windows-process-image-masquerade-forensics]]（进程名伪装取证）、[[defense-detection-sqlps-lolbin-powershell]]（另一类用合法组件投递的检测）。

## 检测与防御

- **作为检测手段的边界**：本方法只看「当前时刻的 TCP 连接 + 文件签名 + 静态自启动配置」，躲不过：① 无外联的落地阶段（等待指令）；② 用合法签名程序侧加载（白加黑）；③ 通过 `HKCU` 以外的冷门持久化点（WMI 订阅、COM 劫持、计划任务 XML）；④ 短连接（采样时刻未连）。因此它只能作为第一轮粗筛，需要配合 `Autoruns`、计划任务全量导出、`Sysmon`/`Get-WinEvent` 与内存扫描做纵深。
- **运维侧加固**：开启 Windows Defender Application Control / 驱动签名强制；对未签名可执行文件的执行做告警（`AppLocker`/`WDAC` 规则）；限制普通用户从下载目录直接运行 `exe/com/bat`。
- **原文代码的坑（复现时务必修正）**：`detectTrojanBehavior` 里「遍历到任意其它 PID 就置 `hasSuspiciousBehavior = true`」的逻辑恒真，等于没判断；`isSystemProcess(OpenProcess(...))` 未关闭内层句柄；`isHighRiskProcess` 对每个证据都独立触发，容易把正常软件判成高危。落地时应改成明确的评分与引用计数管理，避免把自查工具本身变成误报源。
- **留痕**：自查结果应导出为文件（含进程路径、签名状态、远端 IP、时间戳）以便与后续取证/横向排查对照，不要只看弹窗。
