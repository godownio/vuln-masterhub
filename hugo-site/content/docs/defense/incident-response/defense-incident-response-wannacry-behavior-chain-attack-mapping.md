---
id: defense-incident-response-wannacry-behavior-chain-attack-mapping
title: WannaCry 勒索病毒行为链与 ATT&CK 映射：服务持久化 + 删除卷影/备份 + AES/RSA 双层密钥 + Tor C2 + MS17-010 横向
type: scenario
domain: defense
path: defense/incident-response
technique: wannacry-behavior-chain-attack-mapping
tags:
- ransomware
- wannacry
- att-ck
- ttp
- ms17-010
- eternalblue
- tor
- vssadmin
- aes
- rsa
- persistence
- incident-response
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V485
  verified_at: '2026-11-10T21:30:35+08:00'
  notes: 已对照原文全文与10张图核对：ATT&CK ID（T1047/T1543.003/T1222.001/T1564.001/T1083/T1120/T1018/T1016/T1210/T1570/T1573/T1090.003/T1486/T1490/T1489）与文中汇总表逐一相符；mssecsvc2.0创建伪代码(CreateServiceA/StartServiceA)、vssadmin/wmic删卷影、attrib+icacls、GetLogicalDrives/GetAdaptersInfo/445端口select验证、taskkill关Exchange/MSSQL/MySQL、Tor(taskhsvc.exe,127.0.0.1:9050 SOCKS5,.onion)、AES+子公钥/主公钥封装000000.eky 均见原文与截图；无 sources/source_url、无文章ID/URL长摘录；与 defense-incident-response-ransomware-pre-encryption-cleanup 为 related（后者仅通用加密前清理，本卡为WannaCry完整链+ATT&CK映射），dedup_review理由成立，保留两张；dup-scan.json(11-08)早于建卡(11-10)且无本卡pair。原文未涉软件版本，未设affected_versions。未验证点：未在本机复现样本
url: /docs/defense/incident-response/defense-incident-response-wannacry-behavior-chain-attack-mapping/
draft: false
kb_aliases:
- WannaCry 行为分析
- WannaCry ATT&CK 映射
- WannaCry TTP
- 永恒之蓝勒索
- mssecsvc2.0 服务
- WannaCry Tor C2
- AES RSA 双层密钥勒索
---

## 一句话结论

WannaCry 的完整行为链可映射为 ATT&CK：用 WMI/vssadmin 删除卷影（T1047）、创建 `mssecsvc2.0` 服务持久化（T1543.003）、`attrib`/`icacls` 隐藏并放权（T1222.001/T1564.001）、按扩展名/驱动器/网段发现目标（T1083/T1120/T1018/T1016）、经 MS17-010 SMBv1 横向并传输 shellcode（T1210/T1570）、安装 Tor 走 SOCKS5 隐藏服务 C2（T1573/T1090.003）、用 AES+RSA 双层密钥加密文件（T1486）、删除备份并禁用恢复/服务（T1490/T1489）；这条行为序列比加密动作更早、更适合作为检测与阻断点。

## 原理

- **执行与反取证（T1047）**：WannaCry 调用 `vssadmin delete shadows /all /quiet` 与 `wmic shadowcopy delete` 删除卷影副本，使受害者无法通过系统还原恢复文件；WMI 命令还可远程执行，便于横向。
- **服务持久化（T1543.003）**：创建服务 `mssecsvc2.0`，显示名为 “Microsoft Security Center (2.0) Service”，映像路径指向当前可执行文件，以系统服务身份在重启后继续运行，实现持久化与权限维持。
- **防御规避（T1222.001/T1564.001）**：在修改 `c.wnry` 等文件后执行 `attrib +h .` 把当前目录设为隐藏，并执行 `icacls . /grant Everyone:F /T /C /Q` 给 Everyone 完全控制权限并递归应用，方便后续加密与传播。
- **环境发现（T1083/T1120/T1018/T1016）**：按内置扩展名列表搜索用户文件（跳过 `.exe`、`.dll`、`.wncry`），桌面/文档/用户目录优先，原始文件覆盖写入后删除或移入 `%TEMP%`；另一个线程每隔几秒扫描新接入驱动器；通过 `GetAdaptersInfo` 获取本机网段，遍历子网 IP 并检查 445 端口开放，为横向做准备。
- **横向移动（T1210/T1570）**：对 445 开放且存在 MS17-010（永恒之蓝，SMBv1）漏洞的主机发起利用，获得访问权限后把 shellcode/载荷传输到目标并执行，形成蠕虫式自传播。
- **命令与控制（T1573/T1090.003）**：释放并安装 Tor，主程序目录 `TaskData` 中的 Tor 被重命名为 `taskhsvc.exe` 运行，在 `127.0.0.1:9050` 建立 SOCKS5 代理；WannaCry 经该代理访问硬编码的 `.onion` 隐藏服务，在 80 端口使用自定义加密协议传输密钥、查询付款状态。多跳代理+加密信道使 C2 难以按 IP/域名封禁。
- **影响（T1486）**：每个文件用随机 AES 密钥加密；AES 密钥再用“子公钥”加密；子私钥再用“主公钥”加密后写入 `000000.eky`。解密必须依次用攻击者持有的主私钥解出子私钥、再解出 AES 密钥；受害者仅持有公钥，无法自行解密，这是勒索不可逆的关键。
- **禁止恢复与服务（T1490/T1489）**：用 `vssadmin`、`wbadmin delete catalog`、`bcdedit /set {default} bootstatuspolicy ignoreallfailures`、`bcdedit /set {default} recoveryenabled no`、`REAgentC` 等删除/禁用恢复能力；用 `taskkill` 关闭 Exchange、SQL Server、MySQL 等占用文件的进程/服务，保证加密顺利进行。

## 触发条件

- 目标为 Windows 主机，存在未打 MS17-010 补丁且开放 445/SMBv1 的机器（蠕虫横向前提）。
- 主机可写用户目录与系统服务（WannaCry 通常以高权限运行），可安装服务/驱动。
- 网络允许 SMB 横向与 Tor 出站（或攻击者已内置可用的 C2 通道）。
- 缺少针对卷影删除、服务创建、Tor 代理、异常 SMB 扫描的检测与阻断。

## 利用步骤

1. 初始执行：通过钓鱼/漏洞投放释放 WannaCry 载荷，创建并启动 `mssecsvc2.0` 服务实现持久化。
2. 反取证：执行 `vssadmin delete shadows /all /quiet` 与 `wmic shadowcopy delete` 删除卷影副本。
3. 隐藏与放权：`attrib +h .`、`icacls . /grant Everyone:F /T /C /Q`。
4. 发现：枚举驱动器与用户文件，按扩展名筛选；扫描新接入驱动器；获取本机网段并探测 445。
5. 横向：对 445 开放且存在 MS17-010 的主机利用永恒之蓝，传输并执行 shellcode，重复上述流程。
6. C2：安装 Tor，经 `127.0.0.1:9050` SOCKS5 访问 `.onion` C2，传输密钥/查询付款。
7. 加密与破坏恢复：AES 加密文件、RSA 封装密钥写 `000000.eky`；用 `wbadmin`/`bcdedit`/`REAgentC`/`taskkill` 删除备份、禁用恢复并停止数据库服务。
8. 勒索：展示勒索界面与解密演示，要求比特币付款。

## PoC

```bat
:: 删除卷影副本
vssadmin delete shadows /all /quiet
wmic shadowcopy delete

:: 隐藏目录并给 Everyone 完全控制
attrib +h .
icacls . /grant Everyone:F /T /C /Q

:: 删除备份与禁用恢复
wbadmin delete catalog -quiet
bcdedit /set {default} bootstatuspolicy ignoreallfailures
bcdedit /set {default} recoveryenabled no

:: 关闭占用文件的服务
taskkill /f /im sqlservr.exe
```

## 变体与关联

- 变体：WannaCry 的 Tor C2 可被其他匿名网络/域前置替代；删除卷影/禁用恢复的命令组合是多数勒索软件的通用前置行为，见 [[defense-incident-response-ransomware-pre-encryption-cleanup]]。
- 变体：加密方案可换成“每文件随机 AES + 硬编码 RSA 公钥封装”，见 [[code-analysis-reverse-windows-cryptnet-hybrid-encryption-rsa-wrapped-aes-key-iv]]。
- 关联：MS17-010 漏洞利用与横向细节见 [[pentest-lateral-movement-ms17-010-eternalblue-psexec]]；ATT&CK 行为映射的报告方法可参考同系列实践。
- 边界：原文为 ATT&CK 映射文章，未给出 WannaCry 样本或完整逆向细节；行为命令与键层次来自文章引用与分析结论，复现需在隔离环境并遵守授权。

## 检测与防御

- 检测：监控 `vssadmin`/`wmic shadowcopy`/`wbadmin`/`bcdedit`/`REAgentC` 命令行；服务创建（事件 7045）中出现伪装名 `mssecsvc2.0`；`attrib +h` 与 `icacls /grant Everyone:F` 组合；445 端口异常扫描与 MS17-010 利用流量；`taskhsvc.exe`/Tor 进程与 9050 SOCKS5；大量文件被 AES 加密后改名/写 `000000.eky`。
- 防御：及时打 MS17-010 补丁、禁用 SMBv1、网络分段限制 445 横向；阻断 Tor/匿名网络出站；限制服务创建与管理权限；启用 EDR/ASR 规则与离线备份；对卷影/备份做不可删除保护。
- 处置：隔离主机、保留内存与样本、恢复备份、排查同网段其他 MS17-010 主机。
