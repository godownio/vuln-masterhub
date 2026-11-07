---
id: code-analysis-reverse-windows-process-image-masquerade-forensics
title: Section 型进程映像伪装取证：EPROCESS ImageFileName/ImageFilePointer/ImagePathHash 与 image coherency
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: windows-process-image-masquerade-forensics
aliases:
- 进程映像伪装检测
- EPROCESS ImageFileName
- ImageFilePointer 为空
- SeAuditProcessCreationInfo
- ImagePathHash 计算
- image coherency
- Process Doppelgänging 检测
- Process Herpaderping 检测
- Process Ghosting 检测
tags:
- windows
- forensics
- detection
- eprocess
- windbg
- image-coherency
- process-injection
- defense-evasion
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V244
  verified_at: '2026-11-07T13:18:01+08:00'
  notes: 已对照原文与图07-12核对；EPROCESS字段偏移、ImageFilePointer为空异常、SeAudit路径、ImagePathHash算法(修正i/idx笔误)已实测得0xa895e880，System Informer image coherency选项一致；与既有回调分析卡互补
---

## 一句话结论

Process Doppelgänging/Herpaderping/Ghosting 都依赖 `NtCreateProcessEx` 从 Section 创建进程，进程的磁盘映像与内存映像可能不一致甚至不存在；取证时对比 `EPROCESS.ImageFileName`、`ImageFilePointer.FileName`、`SeAuditProcessCreationInfo.ImageFileName` 与 `ImagePathHash`，再结合 System Informer 的 image coherency/数字签名检查，就能发现“字段为空、路径指向替身文件、哈希与磁盘文件不匹配、磁盘映像与内存不一致”等异常，从而识别映像伪装进程。

## 原理

- **`EPROCESS.ImageFileName`（文章环境偏移 +0x450）**：进程映像文件名（如 `notepad.exe`），由创建时的映像信息设置；Doppelgänging/Herpaderping/Ghosting 可能把它设为替身白文件名或保持恶意名，需要与命令行、磁盘路径交叉比对。
- **`EPROCESS.ImageFilePointer`（+0x448）**：指向映像文件的 `FILE_OBJECT`。正常 `CreateProcess` 打开的 notepad 进程该字段指向 `\Windows\System32\notepad.exe`；Section 型进程可能为空（NULL），这是强异常信号。
- **`SeAuditProcessCreationInfo.ImageFileName`**：审计用的进程创建映像名，指向 `OBJECT_NAME_INFORMATION`，可读出完整 NT 路径（如 `\Device\HarddiskVolume3\Users\admin\Desktop\notepad.exe`）。该字段可被进程参数伪装成替身路径，需与 Section/磁盘实际内容比对。
- **`ImagePathHash`（+0x49c）**：`PfCalculateProcessHash` 计算的映像路径哈希；对路径做大写、UTF-16LE 编码后按 `v = byte + 0x25 * v`（64 位回绕）迭代，初值 `0x4CB2F`，取低 32 位（小于等于 1 时置 1）。文章对 `\Device\HarddiskVolume3\Users\admin\Desktop\notepad.exe` 计算出 `0xa895e880`，与内核字段一致。该哈希可用于把内存中的进程与预期路径快速对照。
- **image coherency**：System Informer 的 “Check images for coherency” 会把进程内存中的映像与磁盘文件内容做一致性检查；Doppelgänging/Herpaderping/Ghosting 的磁盘文件在回滚/覆盖/删除后与内存映像不同，检查会失败。“Check images for digital signatures” 则验证映像签名是否与磁盘签名一致。
- **组合判据**：`ImageFilePointer` 为空 + 映像路径 N/A 或指向可写目录 + 命令行与映像名不一致 + `ImagePathHash` 与磁盘文件不匹配 + image coherency 失败，基本可判定为 Section 型映像伪装；正常进程通常这些字段自洽。

## 触发条件

- 具备 Windows 内核调试/EDR/取证能力，能读取 `EPROCESS` 或使用 System Informer/Volatility 等工具。
- 已获得可疑进程的 PID/EPROCESS 地址或内存镜像。
- 目标进程由 `NtCreateProcessEx` + Section 创建，或存在映像文件被回滚/覆盖/删除的痕迹。
- 需要与正常进程基线对比，避免把驱动/受保护进程的正常空字段误判。

## 利用步骤

1. 用 System Informer 打开 “Options → Check images for coherency” 与 “Check images for digital signatures”，观察进程列表中的映像一致性/签名列。
2. 对可疑进程查看属性：Image file name (Win32)、Image file name、Command line、Description、Verified signer、Parent process。
3. 双机内核调试中用 WinDbg 读取 `_EPROCESS`：
   ```text
   dt _EPROCESS <addr> ImageFileName
   dt _EPROCESS <addr> ImageFilePointer
   dx -id 0,0,<addr> -r1 (*((ntkrnlmp!_SE_AUDIT_PROCESS_CREATION_INFO *)<addr+off>))
   dt _EPROCESS <addr> ImagePathHash
   ```
4. 用哈希算法计算预期路径的 `ImagePathHash`，与内核字段比较；不一致说明路径字段被伪装或映像来源异常。
5. 对进程内存做映像 dump，与磁盘文件比对节区/签名；若磁盘文件不存在（Ghosting）或内容为白文件（Herpaderping/Doppelgänging），即可确认。

## PoC

`ImagePathHash` 计算（修正文章脚本中未递增索引的笔误）：

```python
MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1

def calc_hash(path: str) -> int:
    data = path.upper().encode('utf-16le')
    v = 0x4CB2F
    for b in data:
        v = (b + 0x25 * v) & MASK64
    low = v & MASK32
    return low if low > 1 else 1

print(hex(calc_hash(r'\Device\HarddiskVolume3\Users\admin\Desktop\notepad.exe')))
# 0xa895e880
```

WinDbg 字段检查：

```text
1: kd> dt _EPROCESS fffffa205ee7bd080 ImageFileName
   +0x450 ImageFileName : [15] "notepad.exe"

1: kd> dt _EPROCESS fffffa205ee7bd080 ImageFilePointer
   +0x448 ImageFilePointer : 0xfffffa205ec8ecb40 _FILE_OBJECT

1: kd> dx -id 0,0,fffffa205ee7bd080 -r1 (*((ntkrnlmp!_SE_AUDIT_PROCESS_CREATION_INFO *)0xfffffa205ee7bd4e8))
   ImageFileName : 0xfffffa205efde42e0 : "\Device\HarddiskVolume3\Users\admin\Desktop\notepad.exe"

1: kd> dt _EPROCESS fffffa205ee7bd080 ImagePathHash
   +0x49c ImagePathHash : 0xa895e880
```

对照：正常 notepad 的 `ImageFilePointer` 非空并指向 `\Windows\System32\notepad.exe`；Doppelgänging 样本常见 `ImageFilePointer` 为空、`ImageFileName` 与命令行/审计路径不一致。

## 变体与关联

- **字段偏移随 Windows 版本变化**：文章环境为 Windows 10/11 某版本（`ImageFileName` +0x450、`ImageFilePointer` +0x448、`ImagePathHash` +0x49c）；其他版本需重新确认偏移或使用符号。
- **Ghosting**：磁盘文件被删除，`ImageFileName`/路径可能为 N/A，`ImageFilePointer` 为空，无法 dump 到对应文件；需从内存提取映像。
- **Herpaderping**：磁盘文件存在但内容为白文件，签名/描述与命令行不一致；image coherency 失败。
- **Doppelgänging**：磁盘文件为回滚后的白文件或替身文件，`SeAuditProcessCreationInfo` 可能指向替身路径。
- **回调检测**：`PsSetCreateProcessNotifyRoutineEx` 的触发点在初始线程创建时（`PspInsertThread` → `PspCallProcessNotifyRoutines`），仅创建进程不建线程不会触发；可结合回调枚举分析，见 [[code-analysis-reverse-windows-process-notify-callback-analysis]]。
- **攻击技术卡**：[[pentest-c2-windows-process-doppelganging-txf-section]]、[[pentest-c2-windows-process-herpaderping-file-overwrite]]、[[pentest-c2-windows-process-ghosting-delete-on-close-section]]。

## 检测与防御

- 在 EDR/取证流程中加入映像一致性校验：磁盘文件与内存映像哈希/节区对比、数字签名与映像来源对比。
- 采集并关联 `ImageFileName`、`ImageFilePointer`、`SeAuditProcessCreationInfo.ImageFileName`、命令行、父进程、`ImagePathHash`；对“字段为空/不一致”的进程告警。
- 监控 `NtCreateProcessEx`、`NtCreateSection(SEC_IMAGE)`、`NtCreateThreadEx`、TxF 与删除处置的时序组合；对无 `CreateProcess` 前置的进程创建重点排查。
- 限制普通用户对 `%TEMP%` 的执行/写入权限，启用 WDAC/AppLocker、HVCI；定期用 System Informer/Volatility 做基线比对。
