---
id: code-analysis-reverse-windows-cbdhsvc-clipboard-history-vtable-memory-scan
title: cbdhsvc 剪贴板历史内存提取：CUnicodeTextFormat vtable 扫描 + Unicode 字符串指针解析
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: cbdhsvc-clipboard-history-vtable-memory-scan
aliases:
- Windows 剪贴板历史提取
- cbdhsvc 内存扫描
- ClipboardHistoryBuffer
- CUnicodeTextFormat vtable
- ClipboardStellar
- 25 条剪贴板历史
- svchost ClipboardSvcGroup
tags:
- windows
- clipboard
- cbdhsvc
- winrt
- vtable
- memory-scan
- data-extraction
- reverse
- post-exploitation
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V204
  verified_at: '2026-11-07T02:40:52+08:00'
  notes: 已对照原文与 43 张图片核对；vtable 扫描与 +0x18 字符串指针一致；未在目标机复现
---

## 一句话结论

Windows 10/11 的剪贴板历史（最多 25 条）由 `cbdhsvc` 服务保存在 `svchost.exe -k ClipboardSvcGroup -p -s cbdhsvc` 的进程内存中；在该进程里定位 `Windows.ApplicationModel.DataTransfer.dll` 的 `CUnicodeTextFormat::vftable`，扫描已提交的私有 RW 内存中指向该 vtable 的对象，再读取对象 `+0x18` 处的 Unicode 字符串指针，即可批量还原用户复制过的文本（可能包含口令、令牌、IP、密钥）。

## 原理

- **历史服务与开关**：Windows 10 1809+ 提供剪贴板历史（`Win+V`），默认关闭；开启需要 `HKCU\Software\Microsoft\Clipboard\EnableClipboardHistory = 1` 且组策略 `AllowClipboardHistory`（`Software\Policies\Microsoft\Windows\System`）允许。服务运行在按用户托管的 `cbdhsvc`，其宿主命令行固定为 `svchost.exe -k ClipboardSvcGroup -p -s cbdhsvc`。
- **数据结构**：`ClipboardHistoryBuffer` 对象内维护一个指针向量，反编译中 `this[13]` 为起始指针、`this[14]` 为结束指针，元素个数 `(end − begin) >> 3`；`GetInMemoryItemsCount` 遍历向量，对每个元素调用对象虚表 `+0xA0` 处的虚函数并统计未固定/有效的项。每个历史项对象的首 qword 是虚表指针。
- **CUnicodeTextFormat**：文本项使用 `CUnicodeTextFormat` 虚表（位于 `Windows.ApplicationModel.DataTransfer.dll` 的 `.rdata`，符号 `CUnicodeTextFormat::vftable`，Win11 22000.1 示例偏移 0xAE160）；对象的 `+0x18` 处保存指向 UTF-16 字符串的堆指针。反编译 `CreateHStringFromUnicodeHGlobal` 接收的 `hMem` 正是该字符串/句柄，调用栈可追到 `ClipboardHistoryBuffer::AddHistoryItem`。
- **vtable 扫描**：与其逆向层层嵌套的 `ClipboardHistoryBuffer` 结构，不如在目标进程的可读内存中搜索“等于 `CUnicodeTextFormat::vftable` 的 8 字节值”。每个命中地址都可视为一个 `CUnicodeTextFormat` 对象起点；读取 `+0x18` 得到字符串指针，校验其为用户态规范地址（高字节 `0x7f 0x00 0x00`）后 `ReadProcessMemory` 读取 UTF-16 文本。
- **为什么成立**：C++ 对象的首字段是虚表指针，虚表地址在模块内固定；历史项与当前剪贴板项都用同一格式类，因此内存扫描能同时命中多条历史。历史条数上限 25（固定项不计入淘汰），关机会丢失未固定项。

## 触发条件

- Windows 10 1809+/Windows 11，剪贴板历史已开启（注册表与策略同时允许），且用户已复制过至少一条内容。
- 攻击者/分析者已在目标用户会话获得代码执行，能 `OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION)` 打开 `cbdhsvc` 的 svchost（同用户；受保护进程/跨会话会失败）。
- 能枚举目标进程模块并获得 `Windows.ApplicationModel.DataTransfer.dll` 基址，进而定位 `CUnicodeTextFormat::vftable`（PDB/符号或版本特征）。
- 目标内存可读；字符串指针位于用户态规范地址范围。

## 利用步骤

1. 确认/开启历史：检查 `HKCU\Software\Microsoft\Clipboard\EnableClipboardHistory` 与 `AllowClipboardHistory` 策略；若关闭，可在授权测试中改为 1 并复制测试字符串。
2. 找到服务 PID：`tasklist /svc | findstr cbdhsvc` 或 WMI 查询 `svchost.exe` 且命令行含 `-k ClipboardSvcGroup -p -s cbdhsvc`。
3. `OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid)`；`EnumProcessModules`/`Module32First` 找到 `Windows.ApplicationModel.DataTransfer.dll`，计算加载基址。
4. 从 PDB/符号取得 `CUnicodeTextFormat::vftable` 的 RVA（或按版本特征在 `.rdata` 定位虚表），得到运行时 vtable 地址。
5. `VirtualQueryEx` 遍历目标进程内存：筛选 `MEM_COMMIT`、`MEM_PRIVATE`、`PAGE_READWRITE`（必要时含 `PAGE_EXECUTE_READWRITE`）区域，`ReadProcessMemory` 读入本地缓冲。
6. 以 8 字节对齐扫描：若 qword 等于 vtable 地址，则把该地址视为对象；读取 `*(uint64_t*)(addr + 0x18)` 作为字符串指针；校验指针非空且高字节为 `0x7f,0x00,0x00`（x64 用户态规范地址）。
7. `ReadProcessMemory` 读取该指针处的 UTF-16 字符串（先读固定长度/分块直到 `\0`），去重并输出；与 `Win+V` 面板对照验证。

## PoC

```cpp
// 核心逻辑示意：定位 vtable 后扫描 cbdhsvc 内存
uint64_t vtable = moduleBase + 0xAE160;   // 按目标版本/符号调整
for (uint8_t* p = region; p + 8 <= region + size; p += 8) {
    uint64_t v = *(uint64_t*)p;
    if (v != vtable) continue;
    uint64_t strPtr = *(uint64_t*)(p + 0x18);
    if (!strPtr) continue;
    auto* b = (uint8_t*)&strPtr;
    if (!(b[5] == 0x7f && b[6] == 0x00 && b[7] == 0x00)) continue; // 用户态规范地址
    wchar_t buf[512] = {0};
    SIZE_T read = 0;
    if (ReadProcessMemory(hProc, (LPCVOID)strPtr, buf, sizeof(buf) - 2, &read))
        wprintf(L"%ls\n", buf);
}
```

```text
# 目标：svchost.exe -k ClipboardSvcGroup -p -s cbdhsvc
# 模块：Windows.ApplicationModel.DataTransfer.dll
# 虚表：CUnicodeTextFormat::vftable（Win11 22000.1 示例偏移 0xAE160）
# 实测可提取出 Win+V 面板中的历史条目（如 NULL / remoteStringPtr / LPVOID）
```

## 变体与关联

- 变体：不扫描 vtable 时，可沿 `ClipboardHistoryBuffer` 的向量（`this[13]`/`this[14]`）遍历对象；但结构随版本变化，vtable 扫描更稳。
- 变体：其他格式（图片、HTML、文件列表）有各自的 `C*Format` 虚表；可按相同思路定位并解析对应数据。
- 变体：离线内存镜像（Volatility/WinPmem）中同样可按 vtable 指针扫描 `svchost` 进程，恢复历史字符串。
- 关联：[[code-analysis-reverse-windows-ntuser-getclipboarddata-localmemhandle-read]]（只读当前剪贴板）、[[defense-forensics-terminal-osc52-clipboard-read]]（终端剪贴板读取）。
- 边界：历史默认关闭；受保护进程/跨会话无法打开；vtable 偏移随 Windows 版本/补丁变化，需用 PDB 或特征定位；字符串指针校验过严/过松会影响召回与误报。

## 检测与防御

- 检测：EDR 监控对 `cbdhsvc` 宿主 `svchost.exe` 的 `OpenProcess(PROCESS_VM_READ)`、`ReadProcessMemory` 与模块枚举；异常的跨进程内存扫描（大量 `VirtualQueryEx`/连续读取）可作为告警。
- 防御（用户/企业）：不需要时关闭剪贴板历史与云同步（`AllowClipboardHistory=0`）；定期清除历史；不要把密码/令牌/私钥复制到剪贴板。
- 加固：对敏感进程启用更严格的进程访问控制（如受保护进程/AppContainer 隔离）；EDR 对同用户进程读取服务内存的行为做基线；使用密码管理器与硬件密钥减少剪贴板暴露。
