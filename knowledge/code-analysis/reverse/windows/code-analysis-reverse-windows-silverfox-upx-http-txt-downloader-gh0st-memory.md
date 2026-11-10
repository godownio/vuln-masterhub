---
id: code-analysis-reverse-windows-silverfox-upx-http-txt-downloader-gh0st-memory
title: 银狐 UPX 下载器：URLDownloadToFileW 拉取伪装 txt → SysWOW64 落盘执行 → 二次 UPX → 内存解密 Gh0st Server.dll
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: silverfox-upx-http-txt-downloader-gh0st-memory
aliases:
- 银狐 UPX 下载器
- URLDownloadToFileW 下载器
- xxq.txt xiaoq.txt
- SysWOW64 testnxhz
- Server.dll Gh0st
- JeffcEn 导出
tags:
- windows
- malware-analysis
- silverfox
- upx
- downloader
- gh0st
- urlmon
- process-injection
- c2
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V423
  verified_at: '2026-11-09T16:54:38+08:00'
  notes: 已对照原文与32张图核对：UPX3.08 MFC(2024-02-23)、CreateDirectoryA SysWOW64\testnxhz、URLDownloadToFileW 156.237.223.108:5637 拉取 xxq.txt→xxq.jp 与 xiaoq.txt→testen、ShellExecuteA、第二段UPX Borland Delphi 2024-02-26、VirtualAlloc后内存MZ、导出JeffcEn、Server.dll+Yara Gh0st均与图01-08一致。未验证点：PoC未执行、未取回下载物复算、核心解密算法原文未展开。无sources/文章ID/长段摘录，路径合法；dedup top1为自身，related候选(gh0st-vmprotect-rc4/inno-dlclr/cef-helper等)非同链；dup-scan(11-08 19:10)早于本批建卡无涉及pair；三卡各对应一个样本链，无互相重复。
---

## 一句话结论

银狐样本一用一个 UPX 3.08 加壳的 MFC 下载器创建 `C:\Windows\SysWOW64\testnxhz`，通过 `URLDownloadToFileW` 从 `156.237.223.108:5637` 拉取 `xxq.txt`/`xiaoq.txt` 并分别保存为 `xxq.jp` 与 `testen`，再用 `ShellExecuteA` 打开执行；下载到的第二段同样 UPX 加壳（Borland Delphi，2024-02-26 编译），运行后 `VirtualAlloc` 并在内存中解密出 Gh0st 修改版 `Server.dll`（导出 `JeffcEn`），实现“下载器/载荷双 UPX + 核心模块不落盘”的加载链。

## 原理

- **双 UPX 降低静态特征**：外层下载器与下载到的第二段都用 UPX 3.08 压缩（外层 MFC、内层 Borland Delphi），磁盘上看不到明文导入表与核心字符串；UPX 是通用壳，单凭壳特征不足以拦截。
- **伪装扩展名与系统目录**：下载 URL 以 `.txt` 结尾，落盘却用 `.jp` 与无扩展名的 `testen`；目标目录选在 `C:\Windows\SysWOW64\` 下新建的 `testnxhz`，与系统文件混放。`CreateDirectoryA` 先建目录，`URLDownloadToFileW` 直接写文件，扩展名与内容不一致，可绕过按后缀的内容检查。
- **ShellExecuteA 执行**：IDA 中依次 `URLDownloadToFileW` 两个 URL，再 `ShellExecuteA(NULL,"open","...\\xxq.jp",...)`、`ShellExecuteA(NULL,"open","...\\testen",...)`，依赖系统文件关联/文件实际格式拉起下载物；这一步把“下载”与“执行”拆开，下载器本身不包含直接 `CreateProcess` 的可疑导入。
- **内存解密核心模块**：第二段样本在 x64dbg 中命中 `VirtualAlloc`，随后内存出现完整 `MZ`/PE 结构；该 PE 的导出表包含 `JeffcEn`（与样本三一致），Yara 识别为 `CommunityCreated_Gh0st_Cringe_mem`，Metadata 显示模块名 `Server.dll`、编译 2024-02-26。即在内存中解密/映射出 Gh0st 修改版服务端 DLL，而不是把核心 DLL 落盘。
- **Gh0st 能力画像**：Yara 命中 stealer、`SpecialKeyNames`、`DelayBatch` 逃逸、`DownloadUsingWininet`、`CustomUserAgent`、`PostHttpForm`、`ProcessInjectionTargets`、`FingerprintHardware/Environment`、`CreateScheduledTask`、`ElevatePrivileges`、`RunShell` 等规则，说明核心模块具备窃密、注入、计划任务持久化与提权能力。
- **下载基础设施**：`xxq.txt` 仅 1.4KB（2023-12-20 上传），`xiaoq.txt` 520.5KB（2024-02-26 上传），托管在 HttpFileServer 上并显示 840 次命中；小文件可能是加载器/配置，大文件是第二段载荷。

## 触发条件

- 受害者运行外层 UPX 下载器（钓鱼包/下载站/其他 loader 释放）。
- 主机可出网访问下载服务器 `156.237.223.108:5637`，且 `C:\Windows\SysWOW64` 可写（通常需管理员，或由上层提权链获得）。
- 系统允许 `URLDownloadToFileW` 与 `ShellExecuteA` 正常工作，下载物能被文件关联拉起。
- 分析侧：需要样本与隔离环境；核心模块的内存解密算法/密钥未在文中展开，动态调试可 dump。

## 利用步骤

1. 用 DIE/PEiD 识别外层 UPX 3.08，`upx -d` 脱壳后查看导入与字符串。
2. 定位 `CreateDirectoryA("C:\\Windows\\SysWOW64\\testnxhz")`、两条 `URLDownloadToFileW` 与后续 `ShellExecuteA`，提取下载 URL 与落盘名。
3. 从服务器取回 `xxq.txt`/`xiaoq.txt`（只做静态获取，不在分析机执行），识别第二段 UPX（Borland Delphi）。
4. 脱壳第二段，x64dbg 在 `VirtualAlloc` 下断，运行到解密完成后 dump 内存中的 PE。
5. 用 PE 工具确认 `Server.dll`、导出 `JeffcEn`、Yara Gh0st 规则；提取 C2/配置（若解密函数未还原则记录为待补）。
6. 把下载 URL、文件哈希、目录 `testnxhz`、`JeffcEn` 导出作为 IOC，关联同源样本三（C2 156.237.223.130）。

## PoC

```bash
# 静态分析骨架（不执行样本）
upx -d sample1.exe -o sample1.unpacked.exe
strings -a sample1.unpacked.exe | grep -Ei 'testnxhz|xxq|xiaoq|SysWOW64'
# 在隔离环境 x64dbg 中对 VirtualAlloc 下断，dump 解密后的 PE
```

```text
预期产物：
  C:\Windows\SysWOW64\testnxhz\xxq.jp      # 源 xxq.txt，1.4KB
  C:\Windows\SysWOW64\testnxhz\testen      # 源 xiaoq.txt，520.5KB
  内存 dump：PE32 DLL，模块名 Server.dll，导出 JeffcEn
```

## 变体与关联

- 下载目录/文件名可变；同一团伙会把 `.txt` 换成 `.dat`/`.png` 等非可执行后缀，再由白程序或关联打开。
- 核心模块 `JeffcEn` 在样本三中同样出现，说明下载器只是外层包装，核心载荷在多条投递链间复用。
- 关联：[[code-analysis-reverse-windows-silverfox-caesar-shift-oss-wininet-rolling-xor]]（银狐 WinInet 配置下载链）、[[pentest-c2-silverfox-gh0st-vmprotect-rc4-clrcreateinstance]]（Gh0st 变种内存加载）、[[code-analysis-reverse-windows-silverfox-cef-helper-dll-sideload-inflation]]（另一条银狐白加黑链）。
- 边界：若 `SysWOW64` 不可写、下载服务器失效或 `ShellExecuteA` 关联被禁用，链在下载/执行阶段断掉；核心模块解密算法未还原时无法完全复现内存 PE。

## 检测与防御

- **主机**：监控 `C:\Windows\SysWOW64\` 下新建随机目录与 `.txt`→`.jp`/无扩展名文件；`URLDownloadToFileW` 从非业务域名下载后紧接 `ShellExecuteA`；双 UPX 文件与 `JeffcEn` 导出、Gh0st Yara 命中。
- **网络**：封锁 `156.237.223.108:5637` 及同段 IP；对 HttpFileServer 特征（Server 头、目录列表）与 `.txt` 下载可执行内容告警。
- **终端**：限制普通用户写 `SysWOW64`；开启 AMSI/EDR 对 `URLDownloadToFileW`+`ShellExecute` 组合的行为规则；定期扫描内存中的 Gh0st 模块与 `JeffcEn` 导出。
- **取证**：保留下载目录、浏览器/URLMon 缓存、Prefetch 与内存镜像；对 `xxq.jp`/`testen` 计算哈希并做家族比对。
