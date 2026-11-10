---
id: defense-forensics-volatility2-mimikatz-wdigest-credential
title: Volatility2 mimikatz 插件从内存镜像提取 wdigest 账户凭据
type: scenario
domain: defense
path: defense/forensics
technique: volatility2-mimikatz-wdigest-memory-credential
aliases:
- Volatility mimikatz 插件
- 内存镜像提取 Windows 口令
- wdigest 凭据
- Win7SP1x64 mimikatz
- LSASS 内存凭据
tags:
- windows
- forensics
- memory
- volatility2
- mimikatz
- wdigest
- credential
- incident-response
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V311
  verified_at: '2026-11-08T13:10:37+08:00'
  notes: 已对照图03 Volatility 2.6.1 mimikatz 输出逐项核对：wdigest admin ADMIN-PC 70604f4586f81a93、wdigest ADMIN-PC$ WORKGROUP；profile Win7SP1x64 与命令一致。未复现。
---

## 一句话结论

对 Windows 内存镜像运行 Volatility2 的 `mimikatz` 插件，插件会定位 LSASS 进程并解析 wdigest 等凭据提供者结构，输出 `Module/User/Domain/Password` 表；本题在 `Win7SP1x64` 镜像上直接得到 `admin@ADMIN-PC` 的凭据值 `70604f4586f81a93`。

## 原理

- Windows 登录会话的凭据由 LSASS 进程管理；wdigest 凭据提供者在特定 Windows 版本上会把可逆的登录凭据缓存在 LSASS 内存中，供 HTTP 摘要认证等场景使用。
- Volatility2 的 `mimikatz` 插件内置与 mimikatz `sekurlsa` 类似的解析逻辑：在内存中找到 `lsass.exe`，按内核/系统版本的结构偏移枚举 logon session 与 credential provider，读取其中的用户名、域名和凭据材料。
- 因为凭据以结构体形式驻留在内存里，内存镜像又保存了 LSASS 的原始页，所以离线即可恢复；不需要在目标机上运行任何程序。
- 输出中的 `Password` 列是插件恢复出的凭据材料，具体形态（明文、哈希或 blob）取决于系统版本与 wdigest 配置；本题原文直接把它当作口令/凭据使用，值为 `70604f4586f81a93`。
- Windows 8.1 及之后默认不再在内存中缓存 wdigest 明文（微软通过 KB2871997 与注册表 `UseLogonCredential=0` 关闭），因此该路径对老系统（如 Windows 7）更有效。

## 触发条件

- 已获取 Windows 内存镜像（`.raw`/`.dmp`，DumpIt、WinPmem、虚拟机快照或休眠文件）。
- 镜像内核版本与 Volatility2 profile 匹配（本题为 `Win7SP1x64`），且镜像完整、未加密。
- 目标系统上发生过交互式登录/凭据缓存，且 wdigest 未禁用。
- 有可运行 Volatility2 的环境；`mimikatz` 插件依赖 LSASS 结构解析，版本/符号不匹配时可能读取失败。

## 利用步骤

1. 识别镜像 profile：`vol.py -f ez_raw.raw imageinfo`，确认 `Suggested Profile(s)` 含 `Win7SP1x64`。
2. 运行 mimikatz 插件：`vol.py -f ez_raw.raw --profile=Win7SP1x64 mimikatz`。
3. 读取表格：`Module` 为凭据提供者（本题 `wdigest`），`User`/`Domain` 为账户与机器/域，`Password` 为恢复值；本例 `wdigest admin ADMIN-PC 70604f4586f81a93`。
4. 交叉验证：用 `hashdump`/`lsadump`/`cachedump` 补充本地 SAM、LSA secret 与域缓存凭据；用 `cmdline`/`netscan` 把凭据与攻击者活动关联。
5. 记录命令、插件版本、profile、输出与镜像哈希，作为证据。
6. 处置阶段轮换该账户及复用该口令的其他系统凭据。

## PoC

```bash
# 识别 profile
vol.py -f ez_raw.raw imageinfo

# 从 LSASS 内存提取凭据
vol.py -f ez_raw.raw --profile=Win7SP1x64 mimikatz
```

输出示例（本题截图）：

```text
Volatility Foundation Volatility Framework 2.6.1
Module   User            Domain          Password
wdigest  admin           ADMIN-PC        70604f4586f81a93
wdigest  ADMIN-PC$       WORKGROUP
```

## 变体与关联

- **Volatility2 其他凭据插件**：`hashdump` 取 SAM NTLM、`lsadump` 取 LSA secrets、`cachedump` 取域缓存；与 `mimikatz` 互为补充。
- **Volatility3**：用 `windows.hashdump`、`windows.cachedump` 等插件；mimikatz 类解析可借助符号与 `windows.memmap`/dump 后离线分析。
- **在线提取**：在已控制主机上运行 mimikatz `sekurlsa::wdigest`/`sekurlsa::logonpasswords`，原理相同。
- **禁用 wdigest 的后果**：`UseLogonCredential=0` 后 wdigest 不再缓存可逆凭据，但 Kerberos/NTLM 哈希、票据仍可能被其他模块/插件提取。
- 关联：[[defense-forensics-volatility2-cmdline-hashdump-netscan-triage]]（Volatility2 四查）、[[ctf-forensics-windows-sam-system-offline-ntlm-mask-crack]]（离线 SAM 与 NTLM 爆破）。

## 检测与防御

- **配置**：在 Windows 8.1+/Server 2012 R2+ 确认 `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential=0`；老系统安装 KB2871997 或升级。
- **凭据保护**：启用 Credential Guard / LSA 保护（RunAsPPL），限制调试权限与内存读取；高价值账户使用托管服务账户/短生命周期凭据。
- **检测**：内存中出现 mimikatz 特征、LSASS 被非授权进程读取/转储、`procdump lsass`、`comsvcs.dll MiniDump` 等行为；对内存镜像取证工具的使用也应纳入授权与审计。
- **响应**：一旦确认内存凭据泄露，视同口令已泄露，立即轮换账户口令、撤销票据/会话，并排查横向复用。
