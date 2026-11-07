---
id: defense-forensics-silverfox-winos4-file-registry-artifact-dump
title: 银狐/Winos4 主机痕迹采集：Network 分组备注、DirectInput 键盘记录、kernelquick Rootkit 与 Dwm 注入 shellcode
type: scenario
domain: defense
path: defense/forensics
technique: silverfox-winos4-file-registry-artifact-dump
aliases:
- 银狐文件痕迹
- Winos4 留痕分析
- kernelquick rootkit
- DisplaySessionContainers.log
- IpDates shellcode
- HKCU Network REMARK GROUP
- 键盘记录取证
- ValleyRAT 取证
tags:
- windows
- forensics
- registry
- silverfox
- winos4
- rootkit
- keylogger
- incident-response
cve: []
severity: high
confidence: high
affected_versions: Winos4.0（银狐 / ValleyRAT）
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V183
  verified_at: '2026-11-06T20:11:39+08:00'
  notes: 已对照 90727 原文与 10 张图核对：HKCU\Network GROUP/REMARK UTF-16LE、HKCU\key open、ProgramData\DisplaySessionContainers.log（CSIDL_COMMON_APPDATA 35、0x3200000 上限）、23423.txt→kernelquick.sys+服务、KernelQuick_Hide* 六值、HKLM\SOFTWARE\IpDates 与 dwm.exe 注入均一致；PoC 为只读取证骨架未对真实样本执行。卡片提到的 IpDatespecial 来自关联卡而非本文。
---

## 一句话结论

银狐/Winos4 除把插件藏在 `HKCU\Console\0|1` 外，还会留下多类可用于溯源的非插件痕迹：`HKCU\Network` 下 `GROUP`/`REMARK` 的分组备注（UTF-16LE）、`HKCU\key` 的 `open` 键盘记录状态、`C:\ProgramData\DisplaySessionContainers.log` 的 DirectInput 键盘日志、`C:\ProgramData\23423.txt` 改写成的 `kernelquick.sys` 驱动与 `kernelquick` 服务、服务下 `KernelQuick_Hide*` 隐藏/保护列表，以及 `HKLM\SOFTWARE\IpDates` 中由驱动注入 `dwm.exe` 的上线 shellcode；按这些键值/文件路径逐一导出即可还原攻击者的配置、键盘记录与持久化 Rootkit。

## 原理

- **多阶段架构**：银狐采用 `shellcode 加载器 → 上线模块 → 登录模块` 的多阶段模式，登录模块是处理命令的核心；配置与插件大量放在注册表，减少落盘与流量传输。
- **分组/备注**：登录模块通过 `HKCU\Network` 下的 `GROUP`（分组）与 `REMARK`（备注）保存控制端设置，数据为 UTF-16LE；原文反编译可见默认值 `默认`、`1.0.0`、`测试备注`。这两个值用于受害主机分组管理，是识别控制端操作者习惯的线索。
- **键盘记录**：登录模块调用 `DirectInput8Create` 做键盘记录；开关状态写在 `HKCU\key` 的 `open` 值（原文逻辑读取 `open` 并与 `"1"` 比较）。离线记录写入 `CSIDL_COMMON_APPDATA`（通常 `C:\ProgramData`）下的 `DisplaySessionContainers.log`；代码会创建互斥体、检查文件大小（上限约 `0x3200000`，超过则删除重建），因此日志文件可能存在、被轮转或删除。
- **Rootkit 驱动**：驱动模块把自身二进制写入 `C:\ProgramData\23423.txt`（隐藏属性），再 `MoveFileW` 改名为 `kernelquick.sys`，创建内核驱动服务 `kernelquick`（`SERVICE_KERNEL_DRIVER`、`SERVICE_DEMAND_START`）并 `StartServiceW` 启动。
- **隐藏/保护对象**：驱动服务注册表项下写入 `KernelQuick_HideFsFiles`、`KernelQuick_HideFsDirs`、`KernelQuick_HideRegKeys`、`KernelQuick_HideRegValues`、`KernelQuick_ProtectedImages`、`KernelQuick_HideImages` 等值，指定要隐藏的文件/目录/注册表键值/进程；驱动由开源项目 `hidden` 修改而来，可隐藏自身与载荷。
- **Dwm 注入持久化**：上线 shellcode 写入 `HKLM\SOFTWARE` 的 `IpDates`（REG_BINARY）；驱动启动时通过 `ZwOpenKey`/`ZwQueryValueKey` 读取该值，并注入到 `dwm.exe` 进程执行，实现开机自动上线与隐匿。
- **取证价值**：插件注册表卡覆盖 `Console\0|1`；本卡覆盖其余痕迹。由于 Rootkit 会隐藏文件/注册表，常规浏览可能看不到，必须按已知路径直接读取/导出，并优先保存证据再清理。

## 触发条件

- 主机确认或高度怀疑感染银狐/Winos4/ValleyRAT，且已执行过登录模块/驱动模块。
- 取证者拥有管理员权限（HKLM、服务、ProgramData 访问）；离线分析时可挂载用户/系统 hive。
- 注册表/文件尚未被清理工具删除；Rootkit 可能隐藏对象，但按路径直接访问仍可能成功（取决于隐藏实现）。
- 需要区分 32/64 位：`HKCU\Console\0` 为 32 位插件，`Console\1` 为 64 位插件；读取时使用 `KEY_WOW64_64KEY` 避免重定向。
- 键盘日志可能因大小上限被轮转/删除，越早采集越好。

## 利用步骤

1. **分组/备注**：读取 `HKCU\Network` 的 `GROUP`、`REMARK`，按 UTF-16LE 解码并去掉结尾 NUL；记录原始二进制与解码文本。
2. **键盘记录状态**：读取 `HKCU\key` 的 `open`，确认是否为 `"1"`；导出 `C:\ProgramData\DisplaySessionContainers.log`，按 UTF-16LE 转 UTF-8 保存，评估泄露的账号/密码/聊天内容。
3. **Rootkit 文件/服务**：检查 `C:\ProgramData\23423.txt` 与 `kernelquick.sys`（注意隐藏属性），计算哈希；读取 `HKLM\SYSTEM\CurrentControlSet\Services\kernelquick` 的 `ImagePath`、`DisplayName`、`Start`、`Type`。
4. **隐藏/保护列表**：导出服务项下 `KernelQuick_HideFsFiles`、`KernelQuick_HideFsDirs`、`KernelQuick_HideRegKeys`、`KernelQuick_HideRegValues`、`KernelQuick_ProtectedImages`、`KernelQuick_HideImages`，还原攻击者隐藏了哪些对象。
5. **Dwm 注入 shellcode**：导出 `HKLM\SOFTWARE` 的 `IpDates`（REG_BINARY）到 `driver_load_shellcode.bin`，计算哈希；可进一步做 shellcode 分析/沙箱。
6. **插件载荷**：按 [[defense-forensics-winos4-plugin-registry-residency-extraction]] 导出 `HKCU\Console\0|1` 下的 MD5 命名 REG_BINARY，解析 UTF-16LE 插件名 + MD5 + PE。
7. **C2 配置**：读取 `HKCU\Console\IpDate`（以及 `IpDatespecial`），按 UTF-16LE/二进制解析主控 IP、端口、协议、分组等信息。
8. **固化证据**：把所有导出文件写入只读取证目录并计算 SHA256；记录采集时间、主机名、用户 SID；之后按 [[defense-incident-response-silverfox-service-watchdog-injected-process-cleanup]] 的顺序清理。

## PoC

以下为只读取证脚本骨架（Windows，管理员权限；未在本机对真实样本执行）：

```python
import winreg, os, re, ctypes

def read_binary(root, path, name=None):
    with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
        if name:
            v, t = winreg.QueryValueEx(k, name)
            return v, t
        out = {}
        i = 0
        while True:
            try:
                n, v, t = winreg.EnumValue(k, i); out[n] = (v, t); i += 1
            except OSError:
                break
        return out

# 1) 分组/备注（UTF-16LE）
for name in ("GROUP", "REMARK"):
    v, t = read_binary(winreg.HKEY_CURRENT_USER, r"Network", name)
    print(name, v.decode("utf-16-le", "replace").rstrip("\x00"))

# 2) 键盘记录状态 + 日志
v, t = read_binary(winreg.HKEY_CURRENT_USER, r"key", "open")
print("keylogger open:", v)
log = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                   "DisplaySessionContainers.log")
if os.path.exists(log):
    data = open(log, "rb").read()
    open("keyboard_logs.txt", "w", encoding="utf-8", errors="replace").write(
        data.decode("utf-16-le", "replace"))

# 3) Rootkit 服务/隐藏列表
svc = r"SYSTEM\CurrentControlSet\Services\kernelquick"
vals = read_binary(winreg.HKEY_LOCAL_MACHINE, svc)
for n in ("ImagePath", "DisplayName", "Start", "Type",
          "KernelQuick_HideFsFiles", "KernelQuick_HideFsDirs",
          "KernelQuick_HideRegKeys", "KernelQuick_HideRegValues",
          "KernelQuick_ProtectedImages", "KernelQuick_HideImages"):
    if n in vals:
        print(n, vals[n][0])

# 4) Dwm 注入 shellcode
v, t = read_binary(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE", "IpDates")
open("driver_load_shellcode.bin", "wb").write(v)
print("shellcode bytes:", len(v))
```

解析提示：`Console\0|1` 插件值的三段式解析、`IpDate` 配置解析见关联卡；所有 REG_BINARY 先原样导出再解析，避免解码破坏证据。

## 变体与关联

- **插件注册表驻留**：`HKCU\Console\0|1\<MD5>` 的三段式插件与 `IpDate` 配置见 [[defense-forensics-winos4-plugin-registry-residency-extraction]]。
- **C2 通信解密**：4 字节长度 + 10 字节密钥 + 1 字节指令的滚动 XOR 见 [[defense-forensics-winos4-c2-frame-xor-decrypt]]。
- **清理顺序**：服务看门狗、系统进程注入与载荷目录清理见 [[defense-incident-response-silverfox-service-watchdog-injected-process-cleanup]]。
- **变体**：不同银狐版本可能改变 `GROUP`/`REMARK` 键名、键盘日志路径、驱动文件名/服务名、隐藏值名；Rootkit 可能隐藏注册表项，导致常规枚举看不到，需按已知路径直接读取或离线挂载 hive。
- **变体**：键盘日志可能被轮转/删除；若文件不存在，检查同目录其它日志、卷影副本、内存中的 DirectInput 缓冲区。

## 检测与防御

- **注册表监控**：重点监控 `HKCU\Network\GROUP|REMARK`、`HKCU\key\open`、`HKCU\Console\IpDate|IpDatespecial`、`HKLM\SYSTEM\CurrentControlSet\Services\kernelquick` 及 `KernelQuick_Hide*` 值、`HKLM\SOFTWARE\IpDates` 的写入。
- **文件监控**：`C:\ProgramData\DisplaySessionContainers.log`、`23423.txt`、`kernelquick.sys` 的创建/改名/隐藏属性变化；驱动服务创建与 `StartService` 行为。
- **行为检测**：`dwm.exe` 被注入/远程线程、DirectInput 键盘钩子、内核驱动加载后隐藏文件/注册表、`kernelquick` 服务启动；结合 EDR 内核回调与注册表审计。
- **取证/响应**：先导出所有键值与文件并哈希，再按清理卡顺序处置；检查其他用户 hive 与卷影副本；评估键盘日志导致的凭据泄露并轮换。
- **加固**：启用驱动签名/受保护进程、限制普通用户创建内核服务、监控 `ProgramData` 下隐藏的可执行/驱动文件；对已知银狐 IoC 做威胁狩猎。
