---
id: code-analysis-reverse-anti-debug-silverfox-vmtools-mac-mouse-checks
title: 银狐变种环境检测组合：VMware Tools 目录 + VMware MAC OUI + 鼠标位置轮询 + C:\ProgramData\1.txt 文件标记
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: silverfox-vm-sandbox-fingerprint-combo
aliases:
- 银狐反虚拟机变种
- VMware Tools 目录检测
- VMware MAC OUI 检测
- 鼠标位置反沙箱
- C:\ProgramData\1.txt 标记
tags:
- silverfox
- anti-debug
- anti-vm
- sandbox-evasion
- mac-oui
- cursor
- windows
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T07:55:37+08:00'
  notes: 已对照原文与全部41张图核对：PathIsDirectoryW(VMware Tools)（图25）、Netbios取MAC并比对00-0c-29/00-03-ff/08-00-27（图24）、GetCursorPos+Sleep(0x7D)轮询（图23）、GetFileAttributesA(C:\ProgramData\1.txt)（图22）、CreateMutexW(uacme2023-09-19)+GetLastError183（图26）、管理员token判断（图27）、主机名注册表与Time值（图29-30），均一致。未验证点：未运行样本；图24 OUI字符串按8字节比较，卡内按前3字节memcmp描述为便于理解。
---

## 一句话结论

银狐变种在恶意逻辑前串联多项环境指纹：`PathIsDirectoryW("C:\\Program Files\\VMware\\VMware Tools\\")` 探测 VMware Tools、用 `Netbios()` 取 MAC 并比对 VMware OUI（`00-0c-29`、`00-03-ff`、`08-00-27`）、用 `GetCursorPos` 轮询鼠标位置判断是否有真实用户操作、检查 `C:\ProgramData\1.txt` 文件标记，再叠加主机名注册表查询、时间/互斥体与管理员权限判断；任一项命中就跳过恶意分支，导致沙箱/虚拟机中样本“不行为”。

## 原理

- **VMware Tools 目录**：`PathIsDirectoryW(L"C:\\Program Files\\VMware\\VMware Tools\\")` 返回 TRUE 说明安装了 VMware Tools，基本可判定为 VMware 虚拟机；样本据此走退出/跳过分支。与加载 `vmGuestLib.dll` 相比，目录检查不依赖 DLL 名称/导出，规避针对 API 的 hook。
- **MAC OUI**：通过 `Netbios()`（NCB 结构，`ncb_command=0x32/0x33/0x50/0x51` 等）枚举网卡并取 MAC，取前 3 字节与 VMware 的 OUI 比较：
  - `00-0c-29`（VMware）
  - `00-03-ff`（VMware）
  - `08-00-27`（VirtualBox 也常用，样本一并检查）
  
  命中即判定虚拟环境。OUI 是网卡厂商分配的前缀，正常物理机不会使用这些虚拟化厂商前缀。
- **鼠标位置轮询**：`GetCursorPos` 取当前位置，`Sleep(0x7D)`（125ms）后再次取，比较 x/y 是否变化；若坐标不变则继续循环，直到鼠标移动。沙箱/自动化环境通常没有真实用户移动鼠标，样本借此等待“真人操作”，超时/永不满足则不进入后续逻辑。该手法比单纯 `Sleep` 更能区分人工分析与自动化沙箱。
- **文件标记**：`GetFileAttributesA("C:\\ProgramData\\1.txt")`，判断文件是否存在且不是目录（`attrs != -1 && (attrs & 0x10) == 0`）；该文件可作为“已感染/已执行”标记，避免重复运行或识别分析环境。结合 `C:\ProgramData` 可写路径，标记文件难以被普通用户注意。
- **主机名与注册表**：`GetComputerNameW` 取主机名，拼 `Software\<hostname>\` 查询/写入注册表；用于记录感染主机、感染时间（值名 `Time`，格式 `年-月-日 时:分`）以及后续配置。
- **互斥体与权限**：`CreateMutexW(0,0,L"uacme2023-09-19")`，`GetLastError()==183`（ERROR_ALREADY_EXISTS）即退出；随后用 `OpenProcessToken`/`GetTokenInformation(TokenElevationType)`/`CheckTokenMembership(WinBuiltinAdministratorsSid)` 判断是否管理员，决定后续提权/安装分支。
- 为什么组合有效：单项检查都可能被沙箱伪造（改 MAC、装 VMware Tools、模拟鼠标），但多项同时命中会显著提高分析环境成本；样本把检查分散在 shellcode 与 payload 不同阶段，分析者需逐项 patch/hook 才能走到恶意逻辑。

## 触发条件

- 样本在目标上执行到环境检测阶段（前置 MSI/Python 链已跑通）。
- 目标为 Windows；`C:\Program Files\VMware\VMware Tools\` 可被查询、`Netbios` 可用、`GetCursorPos` 可调用。
- 分析环境若为 VMware/VirtualBox、MAC 为虚拟 OUI、无鼠标操作，样本会跳过恶意分支。
- 互斥体 `uacme2023-09-19` 未被占用；样本以非管理员/管理员不同分支运行。

## 利用步骤

1. 在调试器中定位 `PathIsDirectoryW`、`Netbios`、`GetCursorPos`、`GetFileAttributesA` 等调用点，确认检查顺序与返回值分支。
2. 对 VMware Tools 目录检查：patch 返回值为 FALSE，或把路径改成不存在；对 MAC OUI：patch 比较结果或伪造物理网卡 MAC。
3. 对鼠标轮询：在调试器中持续修改光标坐标/跳过循环；对文件标记：创建/删除 `C:\ProgramData\1.txt` 观察分支变化。
4. 对互斥体：确保 `uacme2023-09-19` 不存在或 patch `GetLastError` 比较；对管理员检查：以管理员运行或 patch `TokenElevationType`。
5. 逐项绕过后再观察 C2 通信（`ul.mxbc110.com`）与持久化导出调用。

## PoC

VMware Tools 目录检查（原文）：

```c
if (!result) {
    result = PathIsDirectoryW(L"C:\\Program Files\\VMware\\VMware Tools\\");
    if (!result) {
        // 继续恶意逻辑
    }
}
```

MAC OUI 比较（原文伪代码）：

```c
Netbios(&ncb);                  // 取 MAC
if (v9[0]) {
    while (1) {
        // 取第 n 个网卡 MAC
        if (memcmp(mac, "00-0c-29", 3) == 0 ||
            memcmp(mac, "00-03-ff", 3) == 0 ||
            memcmp(mac, "08-00-27", 3) == 0) {
            // 判定虚拟机
        }
    }
}
```

鼠标轮询（原文）：

```c
if (GetCursorPos(&Point)) {
    do {
        Sleep(0x7D);
        CursorPos = GetCursorPos(&Point);
    } while ((Point.x == origin.x || Point.y == origin.y) && CursorPos);
}
```

互斥体与管理员检查（原文）：`CreateMutexW(0,0,L"uacme2023-09-19")`，`GetLastError()==183` 则退出；`OpenProcessToken` + `GetTokenInformation(TokenElevationType)` + `CheckTokenMembership(WinBuiltinAdministratorsSid)`。

## 变体与关联

- 同类反虚拟机卡：`code-analysis/reverse/anti-debug` 下「银狐安装器反虚拟机三件套：vmGuestLib、WMI 热区与 PhysicalDrive0 磁盘容量」用不同检查组合；本卡是 **VMware Tools 目录 + MAC OUI + 鼠标轮询 + 文件标记** 的变体，检查项与触发/PoC 不同。
- 「Windows 免杀沙箱指纹组合检测」也包含 MAC OUI/VM 进程等；本卡补充鼠标位置轮询与 `C:\ProgramData\1.txt` 标记这两个样本特有项。
- 后续 AV 对抗/提权注入见本文章另一张卡；前置投递链见 MSI/Python 卡。

## 检测与防御

- 检测：在样本中搜索 `VMware Tools` 路径、`00-0c-29`/`00-03-ff`/`08-00-27` 字符串、`Netbios`/`GetCursorPos` 调用序列、`C:\ProgramData\1.txt` 路径与 `uacme2023-09-19` 互斥体；沙箱中监控长时间 `GetCursorPos` 轮询与 `PathIsDirectoryW` 调用。
- 防御/分析：沙箱伪造物理网卡 MAC、移除 VMware Tools 目录/伪装物理机、注入鼠标移动事件、预先创建/删除标记文件；对 `Netbios`/`GetCursorPos` 等 API 做 hook 并记录。
- 排查：检查主机上 `C:\ProgramData\1.txt`、注册表 `Software\<hostname>\Time`、互斥体 `uacme2023-09-19`；结合 C2 `ul.mxbc110.com` 与样本 HASH 做情报匹配。
