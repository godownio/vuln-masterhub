---
id: code-analysis-reverse-firmware-qiling-teegris-syscall-emulation
title: 用 qiling 定制 TEEgris 系统调用模拟安全世界：从 libtzsl.so 提取 syscall 表、映射 Linux 实现、伪造 /sys/proc 与快照回放
type: scenario
domain: code-analysis
path: code-analysis/reverse/firmware
technique: qiling-teegris-custom-syscall-emulation
tags:
- firmware
- qiling
- emulation
- tee
- teegris
- arm
- syscall
- reverse
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V545
  verified_at: '2026-11-11T20:51:18+08:00'
  notes: 已对照原文第六节核对：syslog包装mov r7,#0x12;svc 0、extract-syscalls输出（1 thread_create 0xbe70/0xbed4、3 mmap 0x52fc/0x5380、7 open 0x5bf0/0x5c10、8 read 0x6bd0/0x6bdc）、auxv固定顺序、ioctl(fd,0,0)返回文件大小、Qiling.set_syscall/ql_syscall_mapping_function映射代码、Fake_sys_proc、drcov+lighthouse迭代、快照回放均一致。无组件版本。未实际运行模拟器复现。
url: /docs/code-analysis/reverse/firmware/code-analysis-reverse-firmware-qiling-teegris-syscall-emulation/
draft: false
kb_aliases:
- qiling 模拟 TEE
- TEEgris 模拟器
- 安全世界系统调用模拟
- libtzsl.so syscall 表
- QlFsMappedObject 伪造文件
- qiling 快照
---

## 一句话结论

生产设备的安全世界不可调试，但 TEEgris 用户空间的库（`libtzsl.so`）会暴露系统调用约定：包装函数把系统调用号放进 `r7`、参数放 `r0-r6`、执行 `svc #0`。用脚本自动从库中提取 syscall 表（名字、编号、svc 地址），把这些自定义编号经 `Qiling.set_syscall` 映射到 qiling 已实现的 Linux syscall，再处理 TEE 特有的 OS 语义（auxv 顺序、`ioctl(fd,0,0)` 返回文件大小、`QlFsMappedObject` 伪造文件），就能在 qiling 中启动 TEE 用户空间组件、快照并回放，弥补真实设备无法动态调试的空白。

## 原理

- **为什么用 qiling**：纯 Python，便于监控/修改指令与内存，可做真实硬件难以实现的分析（如找未初始化栈变量）；已支持 POSIX 系统调用模拟；支持运行状态快照与恢复，适合反复探索同一条输入路径。
- **系统调用约定**：ARM32 的 TEEgris 用 `r7` 传系统调用号、`r0-r6` 传参、`svc #0` 陷入。查看 `libtzsl.so` 的包装函数（如 `syslog`：`mov r7,#0x12; svc 0`）即可确认。脚本扫描每个导出函数，回溯 `svc #0` 前对 `r7` 的赋值，输出 `sysno -> (name, function_start, svc_addr)` 表（示例：1 thread_create、2 thread_wait、3 mmap、4 munmap、5 epoll_ctl、6 close、7 open、8 read……）。
- **OS 层定制**：模拟器要先支持目标启动所需的最小 syscall（open/mmap 等），再逐步扩展；TEE 内核看似 POSIX 但有特殊语义——例如 `ioctl(fd, 0, 0)` 返回文件大小（等价 `fstat(fd,&st); st.st_size`）。
- **链接器层定制**：动态链接器从辅助向量（auxv）读取启动信息，期望固定的类型顺序；TEEgris 的 auxv 与 Linux 不同时需要在 qiling 的 loader 阶段重排/补齐。
- **syscall 复用**：不重写全部实现，用 `Qiling.set_syscall` 把每个 TEE 系统调用号映射到 qiling 已模拟的 Linux syscall（通过 `ql_syscall_mapping_function` 得到 `ql_syscall_xxx` 名称，再从 `posix_syscall`/`linux_syscall` 取 handler）；需要适配参数时在包装层做转换。
- **伪造文件系统**：用 `add_fs_mapper('sys://proc', Fake_sys_proc())` 挂载假文件；`QlFsMappedObject` 实现 `read/fstat/close` 即可返回固定内容（如 `read` 返回 `b'\x01'`、`fstat` 返回 -1）。需要向 `ioctl` 第三参数（地址）写数据时，`QlFsMappedObject` 接口不够用，应在 syscall handler 中实现。
- **反馈循环**：启动 TA 消息循环后，映射共享输入缓冲区并调用 `TA_InvokeCommandEntryPoint`，跑完后用 drcov 生成覆盖率给 IDA/lighthouse，迭代构造合法请求。

## 触发条件

- 已获取目标 TEE 用户空间文件（TA、`libtzsl.so`、`libteesl.so`、`libtzld.so`，见 TA 提取卡）。
- 具备 qiling 使用经验，能在 ARM32 用户态模拟中挂接自定义 syscall 与文件映射。
- 目标为 TEEgris/TEE 类非标准 POSIX 环境；需要动态观察启动与请求处理路径。
- 仅用于授权测试与自有设备研究。

## 利用步骤

1. 提取 `libtzsl.so`，用脚本扫描导出函数中的 `mov r7, #imm; svc #0` 模式，生成 syscall 表（编号、名字、函数地址、svc 地址）。
2. 在 qiling 中加载 `libtzld.so` + TA/库，先实现启动必需 syscall（open、mmap、read、close），按需补 `ioctl(fd,0,0)` 返回文件大小等特殊语义。
3. 修正 linker 层 auxv 顺序，使动态链接器正常初始化。
4. 用 `Qiling.set_syscall` 把 TEE syscall 号映射到 qiling Linux 实现；对参数语义不同的调用写适配层。
5. 用 `add_fs_mapper` + `QlFsMappedObject` 伪造 `/sys/proc` 等虚拟文件；在 syscall handler 中处理需要写回用户地址的 `ioctl`。
6. 启动 TA 消息循环，映射输入缓冲区、调用 `TA_InvokeCommandEntryPoint`，用 drcov 覆盖率迭代构造请求；保存快照以便反复回放与调试漏洞点。

## PoC

```python
# syscall 映射骨架
self.original_handlers = {}
map_syscall = utils.ql_syscall_mapping_function(self.ostype)
for x in range(1, 400):
    y = map_syscall(self, x)
    if y is None:
        continue
    handler = None
    if y in dir(posix_syscall):
        handler = getattr(posix_syscall, y)
    elif y in dir(linux_syscall):
        handler = getattr(linux_syscall, y)
    assert y.startswith('ql_syscall_')
    name = y[11:]
```

```python
# 伪造 /sys/proc
self.add_fs_mapper('sys://proc', Fake_sys_proc())

class Fake_sys_proc(QlFsMappedObject):
    def read(self, size):
        return b'\x01'
    def fstat(self):
        return -1
    def close(self):
        return 0
```

```text
# libtzsl.so 包装函数示例（r7=sysno, r0-r6 参数, svc #0）
syslog:
  PUSH {R4,R7,R11,LR}
  MOV  R7, #0x12
  SVC  0

# 自动提取结果（节选）
1: ('thread_create', 0xbe70, 0xbed4)
3: ('mmap', 0x52fc, 0x5380)
7: ('open', 0x5bf0, 0x5c10)
8: ('read', 0x6bd0, 0x6bdc)
```

## 变体与关联

- 变体：其他 TEE OS（QSEE、Kinibi、OP-TEE）的 syscall 约定不同（OP-TEE 走 `smc` 的 fast call 而非 `svc`），但“提取包装函数 → 建 syscall 表 → 映射模拟器实现”的方法一致。
- 变体：没有符号表时可按 `svc #0` 指令模式定位包装函数，再回溯 `r7` 常量；遇到寄存器间接赋值需人工补。
- 变体：快照也可用于模糊测试：每次从 clean 快照恢复，喂不同输入，比重新启动快得多。
- 关联：[[code-analysis-reverse-firmware-samsung-teegris-ta-extraction]]（提取要模拟的 TA/库）、[[binary-pwn-stack-teegris-keymst-rsa-pubexp-overflow-secure-world-rop]]（用该模拟器构造溢出输入）、[[code-analysis-reverse-firmware-samsung-sboot-arm64-exception-vector-extract]]（安全内核侧分析）。

## 检测与防御

- 检测：对固件/TA 外泄与克隆的检测；TEE 厂商可在 TA 中加入反模拟/环境探测（检查 syscall 行为、时序、内存布局）；监控异常的 TA 请求构造行为。
- 防御：TEE 文件加密与签名、最小化暴露的调试信息；syscall 参数严格校验；研究侧在隔离环境运行模拟器，避免把真实密钥材料写入假文件系统。
- 说明：本文是为分析 TEEgris 安全世界而定制 qiling 模拟器的方法，severity low（分析基础设施）；仅用于授权测试与自有设备研究。
