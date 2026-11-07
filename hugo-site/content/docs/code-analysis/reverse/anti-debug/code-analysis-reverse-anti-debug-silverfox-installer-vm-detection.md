---
id: code-analysis-reverse-anti-debug-silverfox-installer-vm-detection
title: 银狐安装器反虚拟机三件套：vmGuestLib、WMI 热区与 PhysicalDrive0 磁盘容量
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: silverfox-installer-vm-detection
tags:
- anti-debug
- anti-vm
- anti-sandbox
- windows
- malware-analysis
- wmi
- deviceiocontrol
- silverfox
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V93
  verified_at: '2026-11-05T19:48:33+08:00'
  notes: 已对照原文与36张图片核对：vmGuestLib.dll解密字符串+LoadLibraryA、WMI MSAcpi_ThermalZoneTemperature/CurrentTemperature、PhysicalDrive0 IOCTL 0x7405C/ClassReadDriveCapacity/除以1GB与250比较、GetTickCount64+Sleep(2000)+1800ms阈值、UAC与Mutex检查、0xC0000005伪崩溃均与截图一致；未运行样本
url: /docs/code-analysis/reverse/anti-debug/code-analysis-reverse-anti-debug-silverfox-installer-vm-detection/
draft: false
kb_aliases:
- vmGuestLib.dll 反虚拟机
- MSAcpi_ThermalZoneTemperature 检测
- IOCTL_DISK_GET_LENGTH_INFO 磁盘容量
- PhysicalDrive0 反虚拟机
- 银狐反虚拟机
- 安装器反沙箱
---

## 一句话结论

伪装成 HelloGPT 安装程序的银狐样本在恶意逻辑前组合了多项环境检查：用 `LoadLibraryA("vmGuestLib.dll")` 探测 VMware Tools、用 WMI `SELECT * FROM MSAcpi_ThermalZoneTemperature` 探测 ACPI 热区（虚拟机通常没有）、用 `\\.\PhysicalDrive0` 的 `IOCTL_DISK_GET_LENGTH_INFO`（0x7405C）读取磁盘容量并拒绝小于 250GB 的环境；再叠加 GetTickCount64 时间加速检测、UAC/管理员与 Mutex 检查，任一命中就弹出 `0xC0000005` 并退出，分析时需要在 IDA/x64dbg 中 patch 返回值或 hook 对应 API 才能进入恶意分支。

## 原理

- **vmGuestLib.dll 检测**：`LoadLibraryA("vmGuestLib.dll")` 是 VMware Tools 提供的库；样本把字符串用 SIMD/XOR 常量解密后动态加载，加载成功说明运行在安装了 VMware Tools 的虚拟机中。代码里先调用该 API，再根据返回值走虚拟机/物理机分支；失败/成功路径最终可能调用 `MessageBoxA(0, "0xC0000005", "error", 0)` 伪装成崩溃。
- **WMI 热区检测**：通过 COM 创建 `IWbemLocator`/`IWbemServices`，执行 WQL `SELECT * FROM MSAcpi_ThermalZoneTemperature`；代码用 `IEnumWbemClassObject::Next` 枚举结果，若至少找到一个温度对象则读取 `CurrentTemperature`。虚拟机/沙箱通常不暴露 ACPI 热区，枚举不到对象，从而被判定为虚拟环境。
- **磁盘容量检测**：打开 `\\.\PhysicalDrive0`，调用 `DeviceIoControl`，IOCTL 码 `0x7405C` 对应 `IOCTL_DISK_GET_LENGTH_INFO`；`disk.sys` 的 `DiskIoctlGetLengthInfo` 从设备扩展/`ClassReadDriveCapacity` 取磁盘容量，返回给用户态。样本把返回值除以 `0x40000000`（1GB）并与 250 比较，`size / 1GB < 250` 判定为虚拟机/沙箱（常见分析环境磁盘较小）。
- **时间加速检测**：通过 hash/混淆方式解析 `GetTickCount64`（原文实际调用为 GetTickCount64），Sleep 一段时间后再次取值，比较时间差；若差值小于约 1800ms（原文注释 2s、阈值 1.8s），说明沙箱对时间进行了加速。该手法与通用反沙箱时间检测相同，但此处 API 解析被混淆。
- **UAC/管理员与 Mutex**：安装器默认以管理员权限启动，样本检查当前是否提权（返回 1 走正常安装）；随后做单实例 Mutex 检查与“Mutex 是否真实存在”的判断，避免重复运行/分析环境伪造。
- **触发表现**：在虚拟机中运行会抛出 `0xC0000005`（访问冲突）但没有 eventvwr 记录，物理机正常运行；这是样本主动走虚拟机分支/制造崩溃，而不是普通漏洞崩溃。
- **绕过思路**：最直接的是在 IDA/x64dbg 中把检查函数返回值改为“物理机/正常”（RAX=1 或 patch `ret`/条件跳转），或用 Frida/API Monitor hook `LoadLibraryA`、`DeviceIoControl`、WMI、`GetTickCount64`，返回符合预期的结果；只 patch 一处往往不够，需要逐个检查处理。

## 触发条件

- Windows 样本（伪装成 HelloGPT 安装程序），在恶意逻辑前执行环境检查。
- 运行在 VMware/VirtualBox/沙箱中；`vmGuestLib.dll`、ACPI 热区、磁盘容量、时间流速等特征暴露。
- 样本以管理员权限启动（安装器 UAC），并有 Mutex 单实例逻辑。
- 分析者需要能调试/修改样本（IDA、x64dbg、Frida、API Monitor）或在物理机/高仿真环境运行。

## 利用步骤

1. 在虚拟机运行样本，记录是否出现 `0xC0000005`、eventvwr 是否有记录、物理机是否正常；若虚拟机崩溃而物理机正常，优先怀疑反虚拟机。
2. 在 IDA 中定位主分支函数（原文 `sub_140032F0` 一类），识别两个检查函数的返回值组合：反沙箱/时间检查与反虚拟机检查；进入 `else` 分支找到 MessageBoxA 的 VM 提示。
3. 识别字符串解密：`vmGuestLib.dll` 等字符串由 SIMD/XOR 常量解密，交叉引用到 `LoadLibraryA` 调用；确认加载失败/成功的分支。
4. 定位 WMI 检查：COM 初始化、`ExecQuery` 的 WQL 字符串、`IEnumWbemClassObject::Next` 与 `CurrentTemperature` 读取；确认“无对象 -> VM”的路径。
5. 定位磁盘检查：`CreateFileA("\\\\.\\PhysicalDrive0")`、`DeviceIoControl(..., 0x7405C, ...)`、返回值 `/ 0x40000000 < 250` 的比较；确认阈值和分支。
6. 选择绕过方式：
   - **静态 patch**：把检查函数返回值改为物理机（如 `mov eax,1; ret`），或把条件跳转改成无条件跳转；x64dbg 可在断点处直接 `Set RAX=1` 放行。
   - **动态 hook**：Frida/API Monitor hook `LoadLibraryA`（对 vmGuestLib 返回 NULL）、`DeviceIoControl`（返回 >=250GB 的容量）、WMI 查询（返回一个热区对象）、`GetTickCount64`（返回真实时间差）；注意 hook 顺序与调用约定。
7. 逐项验证：每 patch 一项后重新运行，观察是否进入安装/释放逻辑；有些检查会组合成 `&&`，需要全部满足。
8. 进入正常逻辑后，按投放链继续分析（释放真正的 HelloGPT 安装器、远程 CAB、RC4、expand.exe、ttd.exe/liblua.dll 等），见关联卡片。

## PoC

```c
/* 样本中的关键检查（伪代码/还原形态，非可执行 PoC） */
LoadLibraryA("vmGuestLib.dll");                  /* VMware Tools 检测 */

/* WMI：虚拟机通常没有 ACPI 热区 */
ExecQuery(L"WQL", L"SELECT * FROM MSAcpi_ThermalZoneTemperature", ...);
IEnumWbemClassObject_Next(..., &obj, ...);       /* 无对象 -> VM */

/* 磁盘容量：< 250GB 判定虚拟机/沙箱 */
h = CreateFileA("\\\\.\\PhysicalDrive0", ...);
DeviceIoControl(h, 0x7405C, NULL, 0, &len, 8, &ret, NULL);
if (len / 0x40000000 < 250) { /* VM */ }

/* 时间加速：GetTickCount64 差值 < 1800ms 判定被加速 */
t1 = GetTickCount64();
Sleep(2000);
t2 = GetTickCount64();
if (t2 - t1 < 1800) { /* sandbox */ }
```

```text
# x64dbg/IDA 绕过要点：
# 1) 在检查函数返回处断下，Set RAX=1（物理机/正常）
# 2) 或把条件跳转 patch 成 jmp，跳过 MessageBoxA/退出分支
# 3) 若样本用 && 组合多个检查，逐个 patch
# 4) 也可 hook LoadLibraryA/DeviceIoControl/WMI/GetTickCount64 返回预期值
```

## 变体与关联

- **变体：更多 VM 指纹**：MAC OUI、CPU 核心数/内存、主板/BIOS 字符串、`vmGuestLib.dll` 之外的 VMware/VBox 驱动/进程、WMI `Win32_ComputerSystem` 厂商字段等；分析时可统一用 hook 返回伪造值。
- **变体：反沙箱时间检测**：通用时间加速检测（`Sleep` 实际耗时 vs 请求值）见 [[code-analysis-reverse-anti-debug-sandbox-environment-checks]]；本样本额外用了 hash 混淆的 `GetTickCount64`，但原理相同。
- **变体：磁盘/热区伪造**：高仿真沙箱可提供 >=250GB 虚拟磁盘、ACPI 热区对象、真实时间流速，降低被识别概率；也可用内核驱动/硬件虚拟化隐藏。
- **关联卡片**：[[pentest-c2-silverfox-hellogpt-installer-dropper-chain]]（同一样本的投放链）、[[code-analysis-reverse-anti-debug-visual-environmental-keying-screenshot]]（视觉环境键控反沙箱）、[[code-analysis-reverse-vm-vmprotect-identification-behavior-analysis]]（VMProtect 壳识别，ttd.exe 使用 VMP）。
- **边界**：不同样本/版本的检查组合和阈值可能变化；只 patch 一处可能仍被其他检查拦截；物理机运行也可能命中磁盘容量/时间阈值，需按实际环境调整。

## 检测与防御

- **分析环境**：使用硬件虚拟化/高仿真沙箱，提供真实磁盘容量、ACPI 热区、时间流速、VMware Tools 可选隐藏；对 `LoadLibraryA("vmGuestLib.dll")`、WMI 热区查询、`PhysicalDrive0` + IOCTL 0x7405C 做监控。
- **行为检测**：安装器在早期查询 WMI 热区、打开 PhysicalDrive0、读取磁盘容量、调用 `GetTickCount64`/`Sleep` 组合，属于可疑反分析行为；结合后续 `expand.exe`、`ttd.exe`、随机临时目录等投放行为告警。
- **终端防护**：监控 `MessageBoxA("0xC0000005")` 之类伪崩溃、样本在虚拟机中静默退出、安装器创建的子进程链；对银狐家族样本做多引擎/YARA 检测。
- **响应**：发现样本后保留内存/进程/文件证据，检查 `%TEMP%` 随机目录、`ttd.exe`、`liblua.dll`、`guofu.txt`、`payload.cab` 等投放物；不要仅依赖沙箱自动结论（反 VM 会让沙箱看不到后续行为）。
