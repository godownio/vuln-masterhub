---
id: ctf-reverse-rdma-soft-roce-wqe-selfmodify-atomic-cas
title: RDMA Soft RoCE 逆向：用 rdma-core 调试符号建 IDA Type Library，dump WQE 理解 ATOMIC_FETCH_AND_ADD 自修改 CAS 校验
type: scenario
domain: ctf
path: ctf/reverse
technique: rdma-soft-roce-wqe-self-modify-atomic-cas-reverse
tags:
- ctf
- reverse
- rdma
- ibverbs
- soft-roce
- rxe
- wqe
- atomic
- ida
- type-library
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V483
  verified_at: '2026-11-10T20:58:52+08:00'
  notes: 已对照原文核对：rxe driver_id=14/abi_version=2、rxe_queue_buf、sub_47F6 手工改 WQE、FETCH_AND_ADD 自修改 CAS compare、Correct/Wrong 逻辑、rdma-core 调试符号生成 IDA .til、puts 后 dump 内存投机解均一致；逆向题无脚本可复跑
url: /docs/ctf/reverse/ctf-reverse-rdma-soft-roce-wqe-selfmodify-atomic-cas/
draft: false
kb_aliases:
- RDTMA
- RDMA 逆向
- Soft RoCE 逆向
- rxe WQE
- ibv_post_send 逆向
- WQE 自修改
- ATOMIC_FETCH_AND_ADD 校验
---

## 一句话结论

题目基于 Linux 内核 Soft RoCEv2（rxe）操作 RDMA Work Queue：程序不直接 `ibv_post_send`，而是手工填充 WQE 并敲 doorbell，用 `IBV_WR_ATOMIC_FETCH_AND_ADD` 自修改 `IBV_WR_ATOMIC_CMP_AND_SWP` 的比较值，把 flag 的逐位比较藏在网卡执行的原子操作里；逆向时用 rdma-core 源码构建带调试符号的 `libibverbs.so`/`librxe-rdmav34.so` 生成 IDA Type Library，再在填充完 WQE、敲 doorbell 前 dump 出 WQE 对照 `rxe_send_wqe`，即可还原校验逻辑；投机解法是在 `puts(flag_buffer)` 后断下 dump 进程内存，直接 strings 找明文 flag。

## 原理

- **Soft RoCE（rxe）**：Linux 内核用软件实现 RoCEv2，用户态通过 libibverbs 操作队列；设备和 provider 可用 `dev->sysfs->driver_id == RDMA_DRIVER_RXE`（14）与 `abi_version == 2` 识别。
- **WQ 共享内存**：`qp->sq.queue` 指向内核映射到用户态的队列缓冲区，布局见 `rdma/rdma_user_rxe.h` 的 `struct rxe_queue_buf`：`log2_elem_size`、`index_mask`、`producer_index`、`consumer_index` 与 `data[]`；WQE 元素布局由 `struct rxe_send_wqe` 定义。
- **手工提交**：正常流程由 libibverbs 把 `ibv_send_wr` 转成 WQE 并更新 producer_index、写 doorbell；题目反其道而行，自己构造“比 `ibv_send_wr` 多一点字段”的结构，在 `sub_47F6` 里直接改 `qp->sq.queue` 的 WQE 字段，最后 `write` 敲 doorbell。
- **自修改 WQE**：`IBV_WR_ATOMIC_FETCH_AND_ADD` 会把返回值写到指定地址，若把目标设为另一条 WQE 的 `atomic.compare_add` 字段，就能在网卡执行过程中动态改写下一条 CAS 的比较值；多条 WQE 串联后实现“按顺序比较/改写 flag 字节”的效果。
- **校验逻辑**：CAS 比较 flag 某位置，成功则把该位置改 0，再把 `"Correct\0"` 写到 flag buffer 开头；随后把各次比较结果按 4 字节一组通过自修改加进 verb operand 并求和，若为 0 则保持 Correct，否则用 `"Wrong:("` 覆盖。由于每次 add 的常数固定，手工累加各位置对应的值即可反推 flag。
- **IDS 类型库技巧**：直接逆 libibverbs 内部结构很痛苦；用 rdma-core 源码构建带完整调试符号的库，在 IDA 分析后导出 `.til` Type Info Library 并加载到题目 idb，即可直接使用 `struct rxe_wq`、`rxe_send_wqe` 等类型，大幅降低难度。
- **投机解法依据**：flag 是明文比较且 WQE 执行完不擦除，进程内存中残留明文 flag；在 `puts(flag_buffer)` 后断下 dump 内存即可 strings 找到。

## 触发条件

- 目标程序依赖 libibverbs 与 rxe 驱动，运行环境需有 Soft RoCE 设备（或可加载 rdma_rxe 模块）。
- 能获取或构建与目标版本接近的 rdma-core 调试符号。
- 有 IDA/Ghidra 与动态调试能力（可在 doorbell 前下断）。
- 若走投机解法，需能在 `puts` 后暂停并 dump 进程内存。

## 利用步骤

1. 静态分析主逻辑：`ibv_get_device_list` 按 `driver_id==14 && abi_version==2` 找 rxe 设备；创建两组 QP 并连接；读 flag；注册 flag/栈缓冲区为 MR。
2. 构建 rdma-core 调试库：
   `git clone https://github.com/linux-rdma/rdma-core`，编译出带符号的 `libibverbs.so` 与 `librxe-rdmav34.so`。
3. 在 IDA 中加载库并保存，按导出 C 类型的方法生成 `.til`，加载到题目 idb，恢复 `rxe_queue_buf`/`rxe_send_wqe` 等结构。
4. 在 `sub_47F6` 填充完 WQE、更新 producer_index 或写 doorbell 之前下断，dump 出 `qp->sq.queue->data` 的 WQE 内容。
5. 对照 `rxe_send_wqe` 解析各字段，确认 FETCH_AND_ADD 的目标地址与 CAS 的 compare/swap 值如何串联。
6. 按顺序提取每个 flag 位置对应的固定加数，手工/脚本累加得到各字节，拼出 flag；或直接采用投机解法。
7. 投机解法：在 `puts(flag_buffer)` 后断下，dump 整个进程内存，`strings` 搜索 `aliyunctf` 及其后内容拼出 flag。

## PoC

无完整利用脚本（本题为逆向题）。关键逆向环境命令：

```bash
git clone https://github.com/linux-rdma/rdma-core
# 构建带调试符号的 libibverbs.so / librxe-rdmav34.so
# IDA 加载库 → 保存 → 导出 .til → 题目 idb 加载 Type Library
# 在填充 WQE 后、doorbell 前下断，dump qp->sq.queue->data
```

## 变体与关联

- 变体：若题目静态链接 libibverbs，仍可用相同结构体布局对照；rxe 的 `rxe_queue_buf` 布局在多个 rdma-core 大版本中稳定。
- 变体：投机解法可推广到“校验用明文且事后不擦除”的其他硬件/协议题：在比较后 dump 内存或抓包。
- 关联：IDA 中导入源码结构体并清理反编译的通用方法见 [[tools-ida-kernel-source-struct-import-decompiler-cleanup]]；硬件协议题的内存分析可参考 [[ctf-reverse-fjm-rv32-state-machine]]。
- 边界：需要真实 rxe 设备或可加载内核模块；原文未给出完整解题脚本，flag 由手工累加/内存 dump 得到。

## 检测与防御

- 本题为 CTF 逆向题，防御侧无直接对应；若作为真实系统，应避免把校验逻辑与明文/密钥放在同一进程内存，校验后及时擦除敏感数据，并使用硬件信任根。
- 检测：进程内长时间残留明文 flag；异常 WQE 自修改/手工 doorbell 行为。
