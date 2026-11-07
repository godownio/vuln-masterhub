---
id: code-analysis-reverse-unpacking-fwrite-static-buffer-embedded-pe
title: fwrite 静态缓冲区释放内嵌 PE：按固定长度从 .data 提取二阶段驱动
type: scenario
domain: code-analysis
path: code-analysis/reverse/unpacking
technique: fwrite-static-buffer-embedded-pe-extraction
aliases:
- fwrite 内嵌 PE
- MZ 提取
- 静态缓冲区
- 驱动释放
- dropper 分析
- .data 内嵌驱动
tags:
- windows
- reverse
- unpacking
- embedded-pe
- fwrite
- driver
- malware
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V193
  verified_at: '2026-11-06T23:52:30+08:00'
  notes: 已对照原文与图50-52核对；fwrite(&unk_140062410,0x8708,1)、C:\AsRockDrv.sys与CreateServiceA一致；未执行样本。
---

## 一句话结论

恶意 dropper 常把二阶段 PE/驱动以静态字节数组形式放在 `.data`，运行时用 `fwrite(&unk_XXXX, <固定长度>, 1, fp)` 落盘。逆向时只要在 IDA 里定位这条 `fwrite`，读取第一个参数指向的缓冲区、按第二个参数的长度 dump，检查开头是否为 `4D 5A`（MZ），就能在**不执行样本**的情况下提取完整二阶段 PE；再结合后续 `CreateServiceA` 等调用判断它是驱动/服务载荷。

## 原理

- **静态内嵌**：编译器把 `unsigned char payload[] = {...}` 或资源放在 `.data`/`.rdata`，运行时 `fwrite` 把内存中的字节原样写到文件。落盘的字节与内存缓冲区完全一致，不需要运行样本就能提取。
- **参数即元数据**：`fwrite(ptr, size, nmemb, stream)` 的第一个参数给出缓冲区地址，第二个参数给出单元素大小，第三个参数给出元素个数；总长度 `size * nmemb` 就是 PE 的 `SizeOfImage`/文件大小。若样本用 `WriteFile`，则看 `lpBuffer` 与 `nNumberOfBytesToWrite`。
- **PE 魔数校验**：合法 PE 以 `4D 5A`（`MZ`）开头，`e_lfanew` 指向 `50 45 00 00`（`PE\0\0`）。dump 后先用这两处校验，避免把填充/加密数据误当 PE。
- **后续行为辅助判断**：示例在 `fwrite` 后用 `OpenSCManagerA`/`CreateServiceA` 注册名为 `AsRockDrv` 的服务，说明落盘的是内核驱动；服务名、路径、启动类型都是 IOC。
- **为什么成立**：dropper 必须把完整 PE 写入磁盘才能让系统加载器加载；静态缓冲区在文件中是可定位的连续字节，且长度由 `fwrite` 参数明确给出。

## 触发条件

- 样本是 PE dropper/loader，导入 `fwrite`/`WriteFile`/`fopen` 等文件写入 API。
- 写入源是静态缓冲区（`.data`/`.rdata` 地址），不是动态解密后的堆内存。
- 写入长度是立即数或可静态求值；目标文件扩展名可能是 `.sys`/`.exe`/`.dll`。
- 缓冲区开头为 `MZ`，或 dump 后可解析出 PE 头。

## 利用步骤

1. 在 IDA 中查看 `main`/入口附近的导入调用，定位 `fwrite`、`WriteFile`、`fopen`、`CreateFileA`。
2. 交叉引用 `fwrite`，确认参数：`ptr` 是 `.data` 地址，`size`/`nmemb` 是固定值，`stream` 来自 `fopen("C:\\...sys","wb")`。
3. 在 IDA 中跳到 `ptr`，读取 `size*nmemb` 字节；或用 IDAPython `ida_bytes.get_bytes(ptr, length)` dump。
4. 保存为文件，检查 `MZ` 与 `PE\0\0`；用 PE 解析器（pefile）确认架构、节表、入口点。
5. 若 dump 后 PE 头正常但节区不完整，检查是否还有解压/解密循环在 `fwrite` 之前；动态解密的情况需在写文件断点处 dump 内存。
6. 继续分析二阶段：导入表（是否 `IoCreateDevice` 等驱动 API）、服务创建参数、C2/配置字符串。
7. 记录 IOC：落盘路径、服务名、PE 哈希、签名/版本信息。

## PoC

IDAPython dump 示例（地址/长度换成实际值）：

```python
import ida_bytes

ea = 0x140062410      # fwrite 的第一个参数
size = 0x8708         # fwrite 的 size * nmemb
data = ida_bytes.get_bytes(ea, size)
open(r"C:\tmp\stage2.bin", "wb").write(data)
print(data[:2])       # b'MZ'
```

pefile 校验：

```python
import pefile
pe = pefile.PE(r"C:\tmp\stage2.bin")
print(hex(pe.OPTIONAL_HEADER.ImageBase), pe.FILE_HEADER.Machine)
```

说明：若样本在 `fwrite` 前对缓冲区做了 XOR/AES 解密，静态 dump 得到的是密文；需在 `fwrite` 调用处下断点，dump 解密后的内存。

## 变体与关联

- 变体：`WriteFile`/`fwrite` 的长度由 `GetFileSize`/资源大小计算，需动态或符号执行求值。
- 变体：payload 放在资源节（`.rsrc`），用 `FindResource`/`LoadResource` 取出；或 Base64 编码后解码写入。
- 变体：不落盘，直接 `VirtualAlloc` + `memcpy` + 跳转执行；此时改为在分配/复制后 dump 内存。
- 关联：[[code-analysis-reverse-unpacking-speakeasy-memory-dump-base64-pe]]（仿真 dump 内存中的 PE）；[[code-analysis-reverse-unpacking-pe-loader-lcg-chacha20]]（PE loader 解密二阶段）；[[code-analysis-reverse-windows-pe-tls-callback-decoy-main-remote-thread-injection]]（TLS 回调注入）。

## 检测与防御

- 检测：静态扫描 `.data`/`.rdata` 中出现 `MZ`/`PE\0\0` 的连续字节；YARA 规则匹配 `fwrite` + `MZ` 组合。
- 检测：监控进程在 `C:\`、`System32\drivers\` 等路径写入 `.sys` 并调用 `CreateService`/`OpenSCManager`；驱动加载事件与签名校验失败。
- 防御：启用驱动签名强制（DSE）、HVCI、WDAC；限制普通用户创建服务/加载驱动。
- 防御：对未签名驱动/服务创建做告警；EDR 关联“文件写入 + 服务创建 + 驱动加载”行为链。
