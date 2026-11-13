---
id: defense-detection-impacket-psexec-atexec-artifacts
title: impacket PsExec/AtExec 检测特征：remcomsvc 固定服务镜像、\RemCom_communication 管道与 atexec 的 Temp 重定向
type: scenario
domain: defense
path: defense/detection
technique: impacket-psexec-atexec-artifacts-detection
aliases:
- impacket PsExec 检测
- RemCom_communication 管道
- remcomsvc 服务镜像特征
- atexec Temp 重定向检测
- 8 位随机服务名
tags:
- windows
- smb
- psexec
- atexec
- impacket
- lateral-movement
- detection
- named-pipe
- service
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V482
  verified_at: '2026-11-10T20:59:11+08:00'
  notes: 已对照原文与18张幻灯片逐张核对：slide08 PsExec 时序（上传 ADMIN$→MS-SCMR 创建启动服务→命名管道 stdin/stdout/stderr→卸载服务/删除exe）、slide09 AtExec 时序（MS-TSCH 计划任务→结果写 ADMIN$ txt→读回→删除任务/文件）、slide10 impacket 源码特征（REMCOMSVC 硬编码 b'4d5a9000...'、openPipe \RemCom_communication、8位随机字母+'.exe' 服务名、atexec cmd.exe '/c %s > %windir%\Temp\%s 2>&1'）均与卡内一致；检测组合（4697/7045/4698、进程链、SMB 写入、管道）与幻灯片'服务创建/计划任务创建/命令行进程链/SMB文件特征/端口通信'对应，补充的事件ID与Sigma伪代码属合理检测实现。与既有 pentest-lateral-movement-psexec-smb-service-hash-lateral 卡（利用流程+通用检测）为检测视角不同原子，dedup top候选 related/new，非重复。幻灯片未标组件版本，affected_versions 留空正确。未验证点：检测伪代码未在本机 Sigma/SIEM 实测；管道名为实际 impacket 源码常量（幻灯片截图字符略糊，按 impacket 官方 psexec.py 为 \RemCom_communication）；REMCOMSVC 哈希未在本机计算。path defense/detection 存在；无 sources/source_url/文章ID/URL/长段摘录。
---

## 一句话结论

impacket 的 `psexec.py` 与 `atexec.py` 会在目标留下可稳定匹配的工件：`remcomsvc.py` 内硬编码的 `REMCOMSVC` 服务 exe 字节、固定命名管道 `\RemCom_communication`、8 位随机字母服务名 + `.exe`；`atexec.py` 经 MS-TSCH 创建计划任务并让 `cmd.exe` 把输出重定向到 `%windir%\Temp\<随机名> 2>&1`，再从 ADMIN$ 共享读回。将服务/计划任务审计、进程命令行与进程链、SMB 写入文件、命名管道名组合起来即可高置信检出。

## 原理

- **psexec 执行模型**：SMB 认证后把服务 exe 上传到 ADMIN$ 共享，用 MS-SCMR 创建并启动服务，服务通过命名管道回传 stdin/stdout/stderr，结束后卸载服务并删除 exe。
- **可固定的静态特征**：impacket `remcomsvc.py` 中 `REMCOMSVC` 是一段硬编码的 PE 字节（以 `4d5a90000300000004000000fff...` 开头），每次执行上传的服务镜像内容相同，可按字节或哈希直接匹配；命令管道名固定为 `\RemCom_communication`。
- **随机但可模式化的动态特征**：服务名由 8 位随机 ASCII 字母加 `.exe` 生成（`''.join(random.choice(string.ascii_letters) for i in range(8)) + '.exe'`），服务名呈现 `^[A-Za-z]{8}$` 的强模式，和正常业务服务命名差异明显。
- **atexec 执行模型**：通过 MS-TSCH 创建调用 `cmd` 的计划任务；任务命令为 `cmd.exe /C <命令> > %windir%\Temp\<tmpFileName> 2>&1`，结果写入临时文件后客户端从 ADMIN$ 共享读取，随后删除任务与文件。
- **检测组合**：单看服务创建（4697/7045）或计划任务创建（4698）误报较高；叠加 SMB 向 ADMIN$ 写入随机名 exe/txt、`\RemCom_communication` 管道、`cmd /C ... > %windir%\Temp\... 2>&1` 命令行与 `services.exe`/`taskeng.exe` 进程链后，置信度显著提高。
- **为什么工具会暴露**：密钥/服务镜像/管道名等常量在 impacket 中没有随机化；服务名虽然随机但长度和字符集固定；atexec 的重定向路径与临时文件命名也是固定模板。

## 触发条件

- 目标为 Windows，攻击者使用 impacket `psexec.py`/`atexec.py`（或复用其 remcomsvc/atexec 模块的衍生工具）。
- 目标开启安全审计（4697 服务创建、4698 计划任务创建）与 System 日志 7045，或部署了 EDR/SMB 流量与命名管道监控。
- 检测方能获取进程命令行、进程树、SMB 写入文件与命名管道事件中的至少两类遥测。

## 利用步骤

1. 收集服务创建事件（4697/7045）与计划任务创建事件（4698/106），提取服务名、ImagePath、任务命令行、创建者账户与来源 IP。
2. 对服务名套用 `^[A-Za-z]{8}\.exe$` 模式，并检查 ImagePath 是否指向 ADMIN$ 或临时目录。
3. 对上传的服务 exe 计算哈希/字节前缀，比对 impacket `REMCOMSVC` 固定镜像。
4. 检查命名管道 `\RemCom_communication` 的创建与连接（Sysmon Event 17/18 或 EDR 管道遥测）。
5. 对进程命令行匹配 `cmd(.exe)? +/C .*>\s*%windir%\\Temp\\` 与 `2>&1` 组合，并关联 `services.exe`/`taskeng.exe` 父进程链。
6. 关联 SMB 对 ADMIN$ 的写入（随机名 exe 或 txt）与随后读取；按时间线把认证、写入、服务/任务创建、执行、删除串起来。
7. 命中后隔离主机、提取服务 exe/临时文件样本，排查同一来源 IP 的其他横向目标。

## PoC

最小检测逻辑（伪代码，可落到 Sigma/Splunk/EDR 规则）：

```text
service_name matches ^[A-Za-z]{8}\.exe$
  OR pipe_name == "\RemCom_communication"
  OR (process_name == cmd.exe AND cmdline matches "/C .*>\s*%windir%\\Temp\\.*2>&1")
  OR sha256(uploaded_service_exe) == <impacket REMCOMSVC hash>
=> alert: suspected impacket psexec/atexec
```

可先离线验证：从 impacket 源码提取 `REMCOMSVC` 字节计算哈希，再到目标 ADMIN$ 与临时目录比对同名/同哈希文件。

## 变体与关联

- **psexec 变体**：smbexec 不落服务二进制（把命令塞进服务 ImagePath），没有 REMCOMSVC 镜像特征；SCShell 修改已有服务的 ImagePath；这些需要服务配置变更与命令行检测补充。
- **规避方向**：替换现有服务/计划任务、修改命名管道与文件/服务名、cmd 与 powershell 命令混淆、改用注册表或远程协议属性回显（幻灯片列出的方向）；对应检测要转向行为与进程链而非固定常量。
- 关联：[[pentest-lateral-movement-psexec-smb-service-hash-lateral]]（PsExec/impacket 横向利用）、[[pentest-persistence-atsvc-netrjobadd-rpc-at-job]]（AT 作业持久化）、[[pentest-persistence-schrpcregistertask-rpc-scheduled-task]]（直接 RPC 注册计划任务）。
- 边界：只关闭 4697/4698 审计且无 EDR/SMB 遥测时无法检出；攻击者改写 impacket 常量或换用其他工具后，固定特征失效，需要行为检测兜底。

## 检测与防御

- **检测**：启用服务创建、计划任务创建与对象访问审计；对 `^[A-Za-z]{8}\.exe$` 服务名、ADMIN$ 随机名文件、`\RemCom_communication` 管道、`%windir%\Temp` 重定向命令行建立关联告警；对服务 exe 做哈希黑名单与签名校验。
- **防御**：限制 445 与 ADMIN$/C$ 管理共享到跳板网段；最小化本地管理员凭据暴露并启用 LAPS；禁用 NTLM/启用 Protected Users 与 Credential Guard；对服务/计划任务创建做白名单与审批；EDR 监控 `services.exe` 与 `taskeng.exe` 的异常子进程。
