---
id: code-analysis-dynamic-debugging-split-shellcode-file-loader-xor
title: 分片 shellcode 加载器：data_1..9.db 拼接 + 16 字节块 XOR 解密 + error.log 明文回退
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: split-shellcode-file-loader-xor-block-decrypt
aliases:
- 分片 shellcode 加载
- data_1.db
- error.log 明文 shellcode
- 16 字节 XOR 解密
- 多文件 shellcode loader
- ProgramData Sangfor 加载器
tags:
- windows
- malware-analysis
- shellcode
- split-payload
- xor
- loader
- virtualalloc
- debugging
- cobalt-strike
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: orchestrator-fix
  verified_at: '2026-11-05T20:08:05+08:00'
  notes: V91 指出的表述/通道问题已修正：91931（seccomp 实际放行全部 syscall / WaitForSingleObject 条件方向 / %p 泄露走进程 stderr）
---

## 一句话结论

恶意 DLL 把 shellcode 拆成 `data.db` 或 `data_1.db ~ data_9.db` 多个文件放在 `C:\ProgramData\Sangfor`，运行时按顺序读取拼接、按 16 字节块 XOR（原文推测 CBC 模式）解密，再 `VirtualAlloc` + `CreateThread` 执行；如果分片文件缺失，则回退读取 `error.log` 中的明文 shellcode，通过文件映射执行。

## 原理

- **分片存储**：loader 先尝试 `data.db`（完整文件）；不存在则循环构造 `data_%d.db`（1..9），逐个 `CreateFileW`、`GetFileSize`、`VirtualAlloc(0x3000, 0x40)`、`ReadFile` 读入内存并拼接。分片既降低单文件体积/熵特征，也让样本可以按文件数量/顺序变化规避静态规则。
- **16 字节块 XOR**：读取后使用 `strtol(..., 0, 16)` 把十六进制字符串解析成密钥，按 16 字节块调用 `_mm_xor_ps`/`memcpy` 逐块解密；原文从代码形态推测可能带 CBC 链式（前一块影响后一块），需要动态确认具体模式。
- **回退路径**：若找不到 `data_*.db`，loader 打开 `error.log`，用 `CreateFileMappingW` + `MapViewOfFile` 映射文件，直接得到明文 shellcode 并转向 `CreateThread` 执行；两条路径最终都调用 `CreateThread` 并 `WaitForSingleObject` 等待。
- **执行**：`VirtualAlloc(0, size, 0x3000, 0x40)` 分配可执行内存，写入解密后的 shellcode，`CreateThread` 创建线程，`WaitForSingleObject(..., 0x1388u)` 等待上线；若返回非 258（线程已结束）才关闭句柄；返回 258（超时）则保留句柄，shellcode 在后台继续运行。
- **为什么这样设计**：分离式 shellcode 让静态扫描看不到完整 payload，分片进一步降低单文件命中率；`error.log` 作为明文备份提高鲁棒性（某路径缺失仍能上线）。加载器与 payload 解耦，便于替换 C2。
- **分析价值**：理解分片命名/拼接顺序、XOR key 的十六进制来源、CBC 模式与回退分支，才能离线还原 shellcode；也可以直接在 `VirtualAlloc`/`CreateThread` 断点 dump 内存，绕过解密细节。
- **边界**：若分片顺序/数量、密钥或 CBC IV 随样本/配置变化，静态还原需要精确匹配；`error.log` 明文回退只在分片缺失时触发，动态分析时要人为制造条件才能走到该分支。

## 触发条件

- 目标为 Windows，恶意 DLL 已被白程序加载并执行到 loader 函数（示例 `sub_10003620`）。
- `C:\ProgramData\Sangfor`（或类似目录）下存在 `data.db`/`data_1..9.db` 分片，或 `error.log` 明文 shellcode。
- 样本未对文件做额外签名/加密校验；XOR key 以十六进制字符串形式嵌入，或可从代码/配置提取。
- 分析者可静态反编译或动态调试（x64dbg/WinDbg），能在 `VirtualAlloc`/`CreateThread` 下断点。

## 利用步骤

1. 在 IDA 中定位 loader（从 `CreateFileW`/`GetFileSize`/`ReadFile`/`VirtualAlloc` 的 xref 入手），记录分片文件名格式、拼接顺序、密钥来源与 XOR/CBC 逻辑。
2. 收集样本目录中的 `data.db` 或 `data_1..9.db`；按 loader 顺序拼接。
3. 解析十六进制密钥，按 16 字节块 XOR 解密；若为 CBC 模式，需按 loader 的链式逻辑逐块处理（可能需要 IV/前一块密文）。
4. 校验解密结果：开头常见 `MZ`/shellcode 特征，尾部可能含 C2 配置字符串；用 `strings`/CS 配置解析器提取 IOC。
5. 或动态提取：在 `VirtualAlloc` 返回后/`CreateThread` 前下断点，dump 目标内存（示例原文明文 shellcode 约 209KB）。
6. 测试回退路径：临时改名/删除 `data_*.db`，观察是否读取 `error.log` 并映射执行；这也说明样本的鲁棒性设计。

## PoC

原文 loader 逻辑（伪代码，未执行样本）：

```c
// 1) 优先读 data.db
FileW = CreateFileW(L"C:\\ProgramData\\Sangfor\\data.db", GENERIC_READ, ...);
if (FileW != INVALID_HANDLE_VALUE) {
    FileSize = GetFileSize(FileW, 0);
    v31 = VirtualAlloc(0, FileSize, 0x3000, 0x40);
    ReadFile(FileW, v31, FileSize, &read, 0);
}

// 2) 否则循环读 data_1.db ... data_9.db
for (i = 1; i <= 9; i++) {
    wsprintfW(name, L"data_%d.db", i);
    FileW = CreateFileW(name, GENERIC_READ, ...);
    if (FileW == INVALID_HANDLE_VALUE) break;
    size = GetFileSize(FileW, 0);
    v38 = VirtualAlloc(0, size, 0x3000, 0x40);
    ReadFile(FileW, v38, size, &read, 0);
    // 拼接/记录每片大小
}

// 3) 16 字节块 XOR（密钥为十六进制字符串）
key = strtol(hex_key, 0, 16);
for (off = 0; off < total; off += 16) {
    memcpy(&blk, &src[off], 16);
    mm_xor_ps(&blk, &key_vec);   // 可能带 CBC 链式
    memcpy(&dst[off], &blk, 16);
}

// 4) 执行
Thread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)dst, 0, 0, &tid);
WaitForSingleObject(Thread, 0x1388u);

// 5) 回退：error.log 明文 shellcode
FileW = CreateFileW(L"C:\\ProgramData\\Sangfor\\error.log", GENERIC_READ, ...);
hMap = CreateFileMappingW(FileW, 0, PAGE_READONLY, 0, 0, 0);
v15 = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
Thread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)v15, 0, 0, &tid);
```

原文动态验证：在 `VirtualAlloc`/内存执行处断点，dump 得到 `setup_03600000.bin` 解密后的 shellcode（约 209KB，开头 `90 90 90 90 90 90 4D 5A 52 45`）。

## 变体与关联

- **分片数量/命名**：`data_1.db`~`data_9.db`、`partN.bin`、随机名；拼接顺序可能写在配置/注册表。
- **加密方式**：单字节 XOR、重复 16 字节 key、AES、RC4；CBC/ECB 模式需按 loader 确认。
- **回退路径**：`error.log` 明文、其他伪装扩展名（`.log`/`.dat`/`.tmp`）、从资源段读取。
- **执行方式**：`CreateThread`、`NtCreateThreadEx`、APC、纤程、回调；断点位置相应变化。
- **关联**：白加黑投递见 [[pentest-initial-access-hidden-files-lnk-dll-sideload-delivery]]；同类解密/转储见 [[code-analysis-dynamic-debugging-multi-layer-shellcode-decrypt-dump]]；C2 配置见 [[defense-detection-cobaltstrike-domain-fronting-config]]。
- **防御/检测**：监控 ProgramData 下伪装 `.db`/`.log` 文件被读取 + `VirtualAlloc` + `CreateThread`；对分片文件做熵/大小/命名规则检测；EDR 监控进程从非 PE 文件映射执行。

## 检测与防御

- **文件检测**：`C:\ProgramData` 等目录下出现 `data_*.db`、`error.log` 等伪装文件；文件内容高熵/分片命名连续；与白程序同目录或同批次落地。
- **行为检测**：进程读取多个同名前缀文件 → 拼接 → `VirtualAlloc` 可执行内存 → `CreateThread`；`CreateFileMappingW`/`MapViewOfFile` 映射非 PE 文件后创建线程。
- **防御**：限制 ProgramData 下可执行/可映射载荷；EDR 对白程序加载后的文件读取与内存执行链告警；隔离样本并做静态解密。
- **取证**：保存分片文件、密钥、解密后的 shellcode、C2 配置；结合进程链与网络流量还原完整攻击链。
