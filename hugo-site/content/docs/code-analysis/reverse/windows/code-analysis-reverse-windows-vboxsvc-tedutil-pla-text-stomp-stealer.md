---
id: code-analysis-reverse-windows-vboxsvc-tedutil-pla-text-stomp-stealer
title: VBoxSVC.exe 侧加载 tedutil.dll：tsunami.avi 解密解压后覆盖 pla.dll .text 注入 cmd.exe 并投递窃密木马
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: vboxsvc-tedutil-pla-text-stomp-inject-stealer
tags:
- windows
- reverse
- malware-analysis
- dll-sideload
- module-stomping
- process-injection
- stealer
- gpg
- tar
- avi
- msix
- rtl-decompress
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V491
  verified_at: '2026-11-10T23:42:56+08:00'
  notes: 已对照原文全文与45/45图核对：VBoxSVC.exe侧加载tedutil.dll(无效MS签名)、CreateFile/GetFileSize/GlobalAlloc/ReadFile读tsunami.avi+解密+ntdll!RtlDecompressBuffer、LoadLibraryW windir\SysWOW64\pla.dll后VirtualProtect(0x40)覆盖.text并恢复保护跳转、shellcode构造windir\SysWOW64\cmd.exe+CreateProcessW+VirtualAllocEx/WriteProcessMemory/VirtualProtectEx/CreateRemoteThread注入+NtTerminateProcess、x_config_Decrypt解出Local State/Login Data/Web Data/Cookies/APPDATA/USERPROFILE与NJPjkgSGacU暂存+fhaduad.com/upload1，均与图一致；与既有模块踩踏/侧加载卡为通用技术vs具体样本链，非重复，且与同篇MSIX投递卡互补不重复；无sources/文章ID/URL(仅IOC)/长段摘录，路径合法；原文无组件版本，versions为空
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-vboxsvc-tedutil-pla-text-stomp-stealer/
draft: false
kb_aliases:
- VBoxSVC.exe 白加黑
- tedutil.dll 侧加载
- tsunami.avi 载荷
- pla.dll text 区段覆盖
- 模块踩踏 module stomping
- RtlDecompressBuffer 载荷解压
- cmd.exe 远程线程注入
- MSIX 投递窃密木马
- fhaduad.com upload1
---

## 一句话结论

该 MSIX 投递链的落地载荷由 `VBoxSVC.exe`、`tedutil.dll`、`tsunami.avi` 三个文件组成：合法的 `VBoxSVC.exe` 从同目录静态加载伪装成微软签名的 `tedutil.dll` 完成侧加载；`tedutil.dll` 用 `CreateFileW`/`GetFileSize`/`GlobalAlloc`/`ReadFile` 把 `tsunami.avi`（RIFF/AVI 容器）读入内存，解密后再用 `ntdll!RtlDecompressBuffer` 解压出下一阶段代码；随后 `LoadLibraryW("C:\Windows\SysWOW64\pla.dll")`，把 `pla.dll` 的 `.text` 改为 RWX 并用恶意 shellcode 覆盖、恢复保护后跳入 `.text` 执行（模块踩踏）；shellcode 启动 `windir\SysWOW64\cmd.exe`，用 `VirtualAllocEx`/`WriteProcessMemory`/`VirtualProtect`/`CreateRemoteThread` 把代码注入 cmd.exe 并在其内部再次覆盖 `pla.dll` 的 `.text`，最后 `NtTerminateProcess` 结束宿主进程；注入体解密配置后收集浏览器、钱包与通信软件数据并外传。

## 原理

- **白加黑侧加载**：`VBoxSVC.exe` 是 VirtualBox 的合法组件，其导入表静态引用同目录的 `tedutil.dll`。Windows 加载器按“应用目录优先”解析 DLL，因此把恶意 `tedutil.dll` 与宿主放在 `%APPDATA%\<随机名>\` 同一目录，运行宿主即加载恶意 DLL。`tedutil.dll` 带有伪造/无效的 Microsoft Corporation 签名（证书信息存在但签名无效），可欺骗只看“有无签名”的粗略检查。
- **AVI 容器藏载荷**：`tsunami.avi` 以 `RIFF` 头开头，表面上是一个 AVI 文件，实际头部之后是加密数据。`tedutil.dll` 读取整个文件到 `GlobalAlloc` 内存后先解密（文章展示了解密循环，具体算法/密钥未展开），再调用 `ntdll!RtlDecompressBuffer`（LZNT1 等格式）解压，得到内含 `MZ`/PE 特征与后续 shellcode 的明文。
- **模块踩踏（module stomping）**：直接 `VirtualAlloc` 私有可执行内存会留下“无模块可执行页”特征。样本改为 `LoadLibraryW("C:\Windows\SysWOW64\pla.dll")` 载入一个已签名的系统 DLL，把 `.text` 区段原始内容备份到新内存，用 `VirtualProtect(…, PAGE_EXECUTE_READWRITE, …)` 把 `.text` 改为可写可执行，写入恶意 shellcode，再恢复原保护并 `jmp` 进入 `.text`。这样执行地址落在 `pla.dll` 的合法模块范围内，内存扫描看到的是“已加载签名模块的 .text”，从而降低无模块内存告警；原 `.text` 备份可用于还原。
- **远程进程注入**：shellcode 在栈上逐字节构造 `windir\SysWOW64\cmd.exe` 并 `CreateProcessW` 启动 cmd.exe；随后 `VirtualAllocEx` 在 cmd.exe 分配内存、`WriteProcessMemory` 写入注入代码、`VirtualProtect` 改权限、`CreateRemoteThread` 执行；注入代码在目标进程内同样覆盖 `pla.dll` 的 `.text`。`NtTerminateProcess` 结束 VBoxSVC.exe 宿主，切断进程链证据。
- **窃密与外传**：注入体通过 `x_config_Decrypt` 一类函数解密字符串，得到浏览器文件名（`Local State`、`Login Data`、`Web Data`、`Cookies`）、环境变量（`APPDATA`、`USERPROFILE`）与钱包/通信软件路径（VERGE、Exodus、Electrum、Coinomi、Telegram、ICQ、Skype、Element、Discord、Jaxx、bytecoin、Guarda、Armory、Zcash 等），把浏览器数据写到 `%LocalAppData%\Microsoft\NJPjkgSGacU` 暂存，再向 `fhaduad.com/upload1` POST 上传。
- **为什么整条链难检测**：签名宿主 + 无效签名 DLL 的组合降低静态信誉告警；载荷藏在 AVI 中规避文件类型检测；模块踩踏把代码放进签名系统 DLL 的 `.text`；注入 cmd.exe 后宿主退出，行为链分散在多个正常进程里。

## 触发条件

- Windows x64 主机（存在 `C:\Windows\SysWOW64\` 与 `pla.dll`），用户执行 MSIX 投递的 PowerShell 脚本并成功下载、解密、解包载荷。
- 三个文件位于同一可写目录（样本为 `%APPDATA%\<随机名>\`）；`VBoxSVC.exe` 被启动且能加载同目录 `tedutil.dll`。
- 脚本用 `gpg.exe` 解密需要口令 `pendos!`（样本硬编码在脚本中），`tar` 能解包；目标可访问下载与上传域名。
- 提权/注入依赖当前用户权限；cmd.exe 与目标进程可写。

## 利用步骤

1. **投递与释放**：MSIX 内脚本下载 `https://seifugbsdfi.online/hvn.tar.gpg`，用 `echo 'pendos!' | gpg.exe --batch --yes --passphrase-fd 0 --decrypt --output <name>.rar <name>.gg` 解密，再 `tar --extract` 到 `%APPDATA%\<随机名>`，得到 `VBoxSVC.exe`、`tedutil.dll`、`tsunami.avi`（见 [[pentest-initial-access-msix-psf-launcher-script-execution]]）。
2. **侧加载**：运行 `VBoxSVC.exe`，同目录 `tedutil.dll` 被加载；确认 `tedutil.dll` 的导入导出表（导出 `CreateDataLoader`、`CreateMediaTypeViewer` 等伪装函数）与无效签名。
3. **载荷释放**：在 `tedutil.dll` 中对 `CreateFileW`/`ReadFile`/`GlobalAlloc` 下断，跟踪 `tsunami.avi` 读取；在解密函数返回处与 `RtlDecompressBuffer` 返回处 dump 数据，确认出现 `MZ`/PE 与 shellcode。
4. **模块踩踏**：在 `LoadLibraryW("...\pla.dll")` 返回后定位 `pla.dll` 的 `.text`，对 `VirtualProtect`、`memcpy` 写入点下断；观察 `.text` 被覆盖、保护恢复与跳转执行。
5. **注入分析**：在 shellcode 中对 `CreateProcessW`、`VirtualAllocEx`、`WriteProcessMemory`、`CreateRemoteThread`、`NtTerminateProcess` 下断，确认注入 cmd.exe 与宿主退出；从 cmd.exe 内存 dump 注入体。
6. **窃密分析**：在注入体中对 `x_config_Decrypt` 字符串解密与 `HttpSendRequest`/WinINet 上传点下断，导出收集路径列表（浏览器/钱包/IM）与上传地址 `fhaduad.com/upload1`；记录样本哈希与 IOC。

## PoC

无 PoC（文章为样本分析，未提供可执行脚本）。关键落地命令与文件布局如下（示意）：

```powershell
# 脚本中的解密与解包步骤（样本硬编码口令 pendos!）
echo 'pendos!' | .\gpg.exe --batch --yes --passphrase-fd 0 --decrypt --output $env:APPDATA\$xxx.rar $env:APPDATA\$xxx.gg
Invoke-Expression "tar --extract --file=`"$tarPath`" --directory=`"$extractPath`""
& "$env:APPDATA\$xxx\VBoxSVC.exe"
```

```text
%APPDATA%\<随机名>\
  VBoxSVC.exe     合法 VirtualBox 宿主，静态导入 tedutil.dll
  tedutil.dll     恶意侧加载 DLL（伪/无效 Microsoft 签名）
  tsunami.avi     RIFF/AVI 容器，内含加密载荷
```

## 变体与关联

- 同链前置：[[pentest-initial-access-msix-psf-launcher-script-execution]]（签名 MSIX + PSF 执行 PowerShell）。
- 同类技术：[[pentest-c2-bof-loader-module-stomping-syscall-opsec]]（模块踩踏复用 DLL `.text` 的通用做法）、[[pentest-initial-access-msi-wrapper-cab-expand-signed-host-dll-sideload]]、[[pentest-initial-access-hta-certutil-tar-signed-exe-chain]]（安装包/HTA + 解包 + 签名宿主侧加载）。
- 关联窃取面：[[defense-forensics-redline-stealer-collection-geofence]]、[[defense-forensics-vidar-stealer-collection-surface-programdata-selfclean]]、[[defense-forensics-wallet-extension-id-local-extension-settings-collection]]。
- 变体：宿主 EXE 与侧加载 DLL 可更换（任意签名程序 + 同名导入 DLL）；`tsunami.avi` 的容器类型与解密算法可变化；模块踩踏可换成 `NtProtectVirtualMemory`/间接系统调用或改为线程池注入；注入目标可从 cmd.exe 换成任意白进程。
- 边界：`pla.dll` 不存在或被 ASR/内存完整性拦截、`VirtualProtect` 失败、`VBoxSVC.exe` 无法从用户目录加载同目录 DLL（如启用安全 DLL 搜索模式）时链会中断；解密算法未公开，复现需以样本或内存 dump 为准。

## 检测与防御

- **进程与文件**：监控从 `%APPDATA%` 等用户可写目录启动的 `VBoxSVC.exe`，以及同目录出现的 `tedutil.dll`/`tsunami.avi`；检查 DLL 签名有效性而非仅看签名者字段；关注 `gpg.exe --passphrase-fd`、`tar --extract` 等 LOLBin 组合与随机命名的 `%APPDATA%` 目录。
- **内存与注入**：对比磁盘与内存中 `pla.dll` 的 `.text` 哈希，检测模块踩踏；监控 `VirtualAllocEx`+`WriteProcessMemory`+`VirtualProtect`+`CreateRemoteThread` 组合、cmd.exe 被远程线程启动子进程、宿主进程异常退出；启用 Sysmon 8/10/11/25 与 EDR 内存扫描。
- **网络**：检测 `seifugbsdfi.online/hvn.tar.gpg`、`756-ads-info.site/?status=start|install`、`fhaduad.com/upload1` 等 IOC；对 gpg 压缩包下载与随后 POST 上传的组合行为告警。
- **防御**：启用内存完整性/HVCI 与攻击面减少规则（阻止 Office/脚本子进程创建、阻止未签名 DLL 加载）；限制用户目录可执行；应用控制阻止 `VBoxSVC.exe` 从非安装目录运行；对签名证书与发布者做信誉校验；发现后隔离主机、提取 `%APPDATA%` 载荷与 cmd.exe 内存、轮换凭据与钱包资产。
