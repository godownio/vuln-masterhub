---
id: code-analysis-reverse-windows-game-sun-pointer-scan-win32-write
title: Cheat Engine 指针扫描定位游戏数值基址+偏移，并用 Python win32 Read/WriteProcessMemory 修改阳光值
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: game-value-ce-pointer-scan-win32-memory-write
aliases:
- 植物大战僵尸修改阳光
- Cheat Engine 指针扫描
- 基址+偏移
- ReadProcessMemory WriteProcessMemory
- 游戏数值内存修改
tags:
- reverse
- windows
- game
- cheat-engine
- pointer-scan
- memory-edit
- python
- win32
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V295
  verified_at: '2026-11-08T07:52:47+08:00'
  notes: 已对照原文content.md与全部32张图逐张核对：CE附加PlantsVsZombies.exe(图01)、阳光500首次扫描(图02-04)、改值375二次扫描收敛到唯一地址364AD478(图05-08)、查看写入指令得[reg+00005560](图09-13)、指针候选364A7F18/08909DD8(图14-21)、手动添加base 0x6a9ec0+偏移0x768/0x5560(图22-24)、重开关卡值为问号/进入后恢复并由指针链解析到新地址(图25-27)、改1000成功(图27-28)、FindWindow标题植物大战僵尸v2.2及区域设置Beta UTF-8(图29-32)，均与原文一致。已修正卡内地址笔误：0x364AD48→0x364AD478(图07/08实际地址)。未验证点：未在本机复跑CE/Python脚本；图22指针对话框底部基址显示需实际CE确认。dedup最高分为卡自身exact自匹配，无同链候选；dup-scan无该卡pair。无组件受影响版本，未set-versions。
---

## 一句话结论

先用 Cheat Engine 对游戏数值（阳光 500→375）做“首次扫描 → 改值再扫”收敛到唯一地址，再通过“找出是什么改写了这个地址”得到字段偏移 0x5560，用 CE 指针扫描找到稳定的模块基址 `0x6a9ec0` 与指针偏移 `0x768`；把 `[base+0x768]+0x5560` 作为多级指针公式，用 Python `win32api/ctypes` 的 `ReadProcessMemory`/`WriteProcessMemory` 即可跨关卡读写阳光值。

## 原理

- **内存数值扫描**：游戏把阳光等数值以 4 字节整数存在进程内存；CE 按精确值扫描，改变数值后再次扫描可快速收敛到唯一地址（本例 500→375 后只剩 `0x364AD478` 一个地址，图07/08）。
- **字段偏移**：对数值地址下“找出是什么改写了这个地址”，得到增加/减少两条写入指令，反汇编中 `[寄存器+0x5560]` 的 0x5560 即该字段在结构体中的偏移；两条指令相同可互相印证。
- **多级指针**：直接地址随关卡/重新分配变化，需要找“指向该地址的指针”。CE 的指针扫描/手动搜索会给出候选指针地址；递归向上找，直到出现绿色地址（模块静态基址，如 `0x6a9ec0`）。本例公式为 `[[base+0x768]+0x5560]`：基址存放一级指针，一级指针 +0x768 指向对象/数组，再 +0x5560 是阳光字段。
- **跨关卡稳定性**：基址属于模块的静态数据区，不随堆/关卡变化；只要游戏版本和对象布局一致，`base + 偏移` 公式在重新进入关卡后仍有效（未进入关卡时值为问号，进入后恢复初始值）。
- **进程读写**：Windows 提供 `OpenProcess` + `ReadProcessMemory`/`WriteProcessMemory`；Python 用 `win32gui.FindWindow` 按窗口标题取句柄、`GetWindowThreadProcessId` 取 pid、`ctypes.c_long` 承载 4 字节数值，逐级解引用后读写。
- **为什么成立**：游戏进程没有反作弊/完整性校验时，同用户权限的进程可以用 `PROCESS_ALL_ACCESS` 直接读写其内存；指针链把“随机堆地址”转换为“静态基址+固定偏移”，从而可编程化。

## 触发条件

- 目标为无内核态反作弊/内存完整性校验的 32 位游戏（本例《植物大战僵尸》杂交版 v2.2）。
- 攻击者与游戏同用户权限，能打开进程 `PROCESS_ALL_ACCESS`。
- 已通过 CE 得到稳定的基址与多级偏移（版本/对象布局需匹配）。
- 窗口标题可用于 `FindWindow`（中文乱码时可关闭系统“Beta: 使用 Unicode UTF-8 提供全球语言支持”或改用 pid/进程名枚举）。

## 利用步骤

1. CE 附加游戏进程，进入关卡记录阳光初值（如 500），首次扫描“精确数值/4 字节”。
2. 种植/拾取阳光使数值变化（如 375），输入新值再次扫描，收敛到唯一地址。
3. 对该地址右键“找出是什么改写了这个地址”，在游戏中让阳光变化，双击命中的写入指令，读取 `[reg+0x5560]` 得到字段偏移。
4. 记录 CE 提示的指针候选地址，在 hex 视图按该值做新的扫描，逐层找指针；筛选偏移一致（如 0x768）的候选，直到出现绿色模块基址（如 0x6a9ec0）。
5. 手动添加地址：基址 `0x6a9ec0` + 偏移 `0x768`、`0x5560`，验证读数与游戏一致；重新进入关卡确认仍有效。
6. 编写 Python 脚本：`FindWindow` → `GetWindowThreadProcessId` → `OpenProcess(PROCESS_ALL_ACCESS)` → 逐级 `ReadProcessMemory` 解引用 → 读写阳光。

## PoC

原文 Python 核心：

```python
import win32gui, win32api, win32process, ctypes
from win32con import PROCESS_ALL_ACCESS

kernel32 = ctypes.windll.LoadLibrary(r"C:\Windows\System32\kernel32.dll")

def GetAddress(handle, BaseAddress, offset=[]):
    value = ctypes.c_long()
    kernel32.ReadProcessMemory(int(handle), BaseAddress, ctypes.byref(value), 4, None)
    for i in range(len(offset) - 1):
        kernel32.ReadProcessMemory(int(handle), value.value + offset[i], ctypes.byref(value), 4, None)
    return value.value + offset[len(offset) - 1]

hwnd = win32gui.FindWindow(0, "植物大战僵尸v2.2 ")
pid = win32process.GetWindowThreadProcessId(hwnd)[1]
handle = win32api.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

showSun = ctypes.c_long()
changeSun = ctypes.c_long()
base_address = 0x6a9ec0
sun_offset = [0x768, 0x5560]

while True:
    address = GetAddress(handle, base_address, sun_offset)
    kernel32.ReadProcessMemory(int(handle), address, ctypes.byref(showSun), 4, None)
    print("当前阳光：", showSun.value)
    changeSun.value = int(input("要修改成多少："))
    if changeSun.value == -1:
        break
    kernel32.WriteProcessMemory(int(handle), address, ctypes.byref(changeSun), 4, None)
```

要点：基址/偏移随游戏版本变化；`FindWindow` 标题需与窗口完全一致，乱码时调整系统区域设置或改用进程枚举。

## 变体与关联

- **同类指针链卡**：`code-analysis-reverse-windows-game-health-pointer-chain`、`code-analysis-reverse-windows-game-state-boolean-pointer-chain`、`code-analysis-reverse-windows-game-control-pointer-chain` 用 CE 初扫 + x32dbg 访问/写断点回溯寄存器来源，适用于更复杂/无稳定指针扫描结果的字段；本卡用 CE 指针扫描 + 静态基址，流程更直接。
- **变体**：数值类型可能是 float/2/8 字节，扫描时需切换；指针链可能是 3 级或更多；也可用 CE 的 Lua 脚本/AutoAssembler 注入代码实现自动修改。
- **反作弊对抗**：有反作弊时可改用驱动/内核读写、DMA 硬件，或转向存档文件修改；本卡仅覆盖用户态无保护场景。

## 检测与防御

- 游戏侧：反作弊/完整性校验（校验关键数值与指针链、检测 `OpenProcess`/`ReadProcessMemory` 句柄、内核回调监控跨进程读写）；服务器权威数值（多人游戏不应信任客户端数值）。
- 工程侧：关键数值不放固定静态基址+可预测偏移，增加指针混淆/加密；对内存读写行为做遥测与封禁。
- 安全研究视角：该技术同样适用于分析无保护 Windows 程序的运行时数据结构；防御方应假定客户端内存可被同权限进程任意读写。
