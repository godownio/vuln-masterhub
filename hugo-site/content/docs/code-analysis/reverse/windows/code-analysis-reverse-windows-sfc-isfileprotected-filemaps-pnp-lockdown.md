---
id: code-analysis-reverse-windows-sfc-isfileprotected-filemaps-pnp-lockdown
title: Windows SFC IsFileProtected 受保护文件判定：WinSxS\FileMaps 哈希清单与 PnP Lockdown class=1 双路径
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: sfc-isfileprotected-filemaps-pnp-lockdown
tags:
- windows
- sfc
- wrp
- reverse-engineering
- filemaps
- pnp-lockdown
- protected-files
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V362
  verified_at: '2026-11-09T02:57:31+08:00'
  notes: 已对照原文与36张图片核对：SfcIsFileProtected 两段逻辑(sub_7089411E→FileMaps cdf-ms、PnpIsFilePnpDriver→PnpLockdownFiles Class=1)、FileMaps 哈希清单内容、Class=1/3 打开差异、最小 SfcIsFileProtected 程序均与图一致；卡内无 sources/文章ID/长段摘录，路径 code-analysis/reverse/windows 合法，非组件漏洞故无 affected_versions/CVE 正确。未验证点：Windows 11 未实测(案例为 10.0.19041)，卡内写 10/11 属合理外推。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-sfc-isfileprotected-filemaps-pnp-lockdown/
draft: false
kb_aliases:
- SfcIsFileProtected
- SFC 受保护文件判断
- FileMaps cdf-ms
- PnpLockdownFiles
- WRP 文件保护判定
---

## 一句话结论

Windows 10/11 的 `SfcIsFileProtected`（sfc_os.dll 导出、sfc.exe 使用）判断一个文件是否受 WRP 保护时走两条路径：先把文件所在目录映射到 `C:\Windows\WinSxS\FileMaps\$$_<目录哈希>.cdf-ms` 清单并匹配文件名；未命中再查注册表 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles\<文件完整路径>` 的 `Class` 值，等于 1 才判为受保护；用 `sfc.h` 的 `SfcIsFileProtected` 可写最小程序直接查询任意文件。

## 原理

- 入口是 `sfc_os.dll` 的 `SfcIsFileProtected`，IDA 反编译可见两段：`v2 = sub_7089411E(ProtFileName, &v6)`（第一部分）与 `PnpIsFilePnpDriver(ProtFileName, &v5)`，仅当 `v5 == 1` 时 `v6 = 1`（第二部分），最后 `RtlSetLastWin32Error` 返回。
- **第一部分（FileMaps 清单）**：取目标文件路径的目录部分，经 `\SystemRoot\WinSxS\FileMaps\` 拼接并计算出一个哈希文件名（目录结构不同则哈希不同，例如 `$$_system32_<hash>.cdf-ms`）。随后用 `CreateFile`/`CreateFileMapping` 以内存映射方式打开该清单（Process Monitor 里只看到 CreateFileMapping，看不到 ReadFile，容易误判为“没有读取”），`RtlInitUnicodeString` 后在清单数据里匹配目标文件名；命中即受保护。
- **第二部分（PnP Lockdown 注册表）**：`RegOpenKeyExW(HKLM, "Software\\Microsoft\\Windows\\CurrentVersion\\Setup\\PnpLockdownFiles", ...)` 打开根键，再以“文件完整路径”（如 `%SystemRoot%\System32\CIRCoInst.dll`）为子键名打开，`RegQueryValueExW(..., "Class", ...)` 读取 DWORD。`Class == 1` 表示该文件属于即插即用驱动/组件，受 WRP 保护；XP 源码中该判断由 setupapi 的 `PnpIsFilePnpDriver` 完成，现代系统同样由 setupapi 参与。
- 历史对照：Windows XP 的 `SfcInitProt` → `SfcLoadSfcFiles(TRUE)`（加载 sfcfiles.dll）→ `SfcInitializeDllLists` 构建保护列表，列表静态写在按语言/SKU 区分的 `x86_wks.h`（`TabFiles[]`/`MedFiles[]`/`WksFiles[]`）。Win10 已无 sfcfiles.dll，`SfcGetNextProtectedFile` 等枚举函数被废弃，保护信息改由 FileMaps 清单与 PnP Lockdown 注册表提供。
- 第一部分命中时只看“文件名是否在目录对应清单中”，不解引用文件内容；第二部分只看注册表 Class 值。因此该 API 可以在不打开目标文件内容的情况下回答“是否受保护”。

## 触发条件

- 目标为 Windows 10/11（案例版本 10.0.19041）；调用者需有权限访问 WinSxS\FileMaps 与 PnpLockdownFiles（本机普通读取通常即可，案例以管理员运行）。
- 查询的是完整路径；不同目录（System32、SysWOW64、驱动目录等）对应不同的 FileMaps 清单。
- 文件是否真的被 WRP 强制保护还取决于 TrustedInstaller ACL 与 SFC 修复策略，本 API 只回答“是否在保护清单中”。

## 利用步骤

1. 最小判定：编写调用 `SfcIsFileProtected(NULL, L"C:\\Windows\\System32\\CIRCoInst.dll")` 的控制台程序（`#include <sfc.h>`，链接 sfc.lib），返回真即受保护；可批量枚举候选文件，为后续持久化/替换选址避开会被 SFC 修复的文件。
2. 动态确认：Process Monitor 过滤 sfc.exe/TiWorker.exe，观察 `CreateFile`/`CreateFileMapping` 是否打开 `C:\Windows\WinSxS\FileMaps\$$_*.cdf-ms`，以及是否 `RegOpenKey` 到 `PnpLockdownFiles\<目标路径>`、`RegQueryValue Class`。
3. 静态核对第一路径：在 `C:\Windows\WinSxS\FileMaps` 找到目录对应的 `.cdf-ms`，用十六进制查看器按 UTF-16LE 搜索目标文件名，确认“文件名-目录哈希”映射。
4. 静态核对第二路径：打开 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles`，查看目标路径子键的 `Class`、`Owners`、`Source` 值：`Class=1` 为保护，`Class=3` 等其它值不受该路径保护。
5. 若要验证判定顺序，可对 `SfcIsFileProtected` 下断点单步，观察先走 FileMaps 分支（命中即返回），未命中才进入 `PnpIsFilePnpDriver`。

## PoC

最小查询程序（原文示例，判断 `CIRCoInst.dll` 是否受保护）：

```c
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <sfc.h>
#pragma comment(lib, "sfc")

int _tmain(int argc, _TCHAR* argv[])
{
    if (SfcIsFileProtected(NULL, _T("C:\\Windows\\System32\\CIRCoInst.dll"))) {
        printf("protected.");
    } else {
        printf("no protected.");
    }
    return 0;
}
```

FileMaps 清单示例（目录 System32 对应一个哈希文件，内容为 UTF-16 字符串，包含 `kernel32.dll` 等文件名）：

```text
C:\Windows\WinSxS\FileMaps\$$_system32_<hash>.cdf-ms
```

PnP Lockdown 子键示例：

```text
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\PnpLockdownFiles\%SystemRoot%\System32\CIRCoInst.dll
  Class   REG_DWORD   0x00000001
  Owners  REG_MULTI_SZ usbcir.inf
  Source  REG_EXPAND_SZ %SystemRoot%\System32\DriverStore\FileRepository\usbcir.inf_amd64_...
```

## 变体与关联

- 变体：`SfcIsFileProtected` 只做“清单命中”判断；真正执行 `sfc /VERIFYFILE` 时还会进入哈希校验链（组件键 S256H、TiWorker、manifest），见 [[code-analysis-reverse-windows-sfc-verifyfile-deriveddata-s256-tiworker-hash]]。
- 变体：PnP Lockdown 注册表同时被 setupapi 在驱动加载路径查询，加载驱动时也会看到对 `PnpLockdownFiles\<路径>` 的访问，容易与 SFC 自身行为混淆，过滤进程名可区分。
- 关联：FileMaps 是目录到文件名的哈希清单，适合用来判断“某目录下哪些文件属于 WRP”；与 Windows 文件保护修复（TrustedInstaller 拥有 WRP 资源）配合理解。
- 边界：XP 时代 sfcfiles.dll 静态列表的逆向方法（`x86_wks.h`）不能直接套用到 Win10；Win10 需以 FileMaps + PnpLockdownFiles 为准。

## 检测与防御

- 该 API 本身是合法系统接口，攻击者调用它枚举受保护文件不会产生明显恶意特征；检测重点应放在后续对受保护文件的写操作与对保护数据的篡改。
- 保护 `C:\Windows\WinSxS\FileMaps` 与 `HKLM\...\PnpLockdownFiles` 的 ACL（默认仅 TrustedInstaller/SYSTEM 可写），监控对这些位置的写入与删除。
- 若发现系统文件被替换而 SFC 未修复，应同时核查 FileMaps/PnpLockdownFiles 与 `HKLM\COMPONENTS` 是否被改动。
- 对红队/恶意软件分析：先确认目标文件是否在保护清单中，再决定是否值得投入替换；对蓝队：可将“非系统进程读取 FileMaps 清单”作为低置信度侦察行为线索。
