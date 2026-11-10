---
id: smc-xor-function-decrypt-disasm-filter
title: SMC 函数级单字节 XOR 加密的密钥恢复（反汇编合法性筛选爆破）
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: 自修改代码密钥恢复
aliases:
- SMC 密钥爆破
- capstone 反汇编筛选
tags:
- smc
- xor
- capstone
- deobfuscation
- reverse
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-20
  verified_at: '2026-11-08T12:53:20+08:00'
  notes: 已对照原文核对：SMC mprotect RW→XOR→RX、逐函数单字节字符集爆破+Capstone 反汇编合法性筛选、Function 24 t/w 语义对比、尾字节 ret 推首函数密钥均与原文一致，逐函数候选密钥输出截图证实；与 base58-xor-bruteforce/EEPROM 爆破等卡链路不同(本卡核心是反汇编合法性约束)，--force 合理；未验证点：flag 最终值未独立复算
---

# SMC 函数级单字节 XOR 加密的密钥恢复（反汇编合法性筛选爆破）

## 一句话结论

当程序运行时用输入的每个字符对一组函数做单字节 XOR 自修改（SMC，mprotect 改 RW→异或→改 RX）来"按需解密"代码时，密钥（即输入）可逐函数用字符集爆破恢复：对每个候选密钥解密后用 Capstone 反汇编，按"合法函数必不含 ud2/hlt/int3/retf 等指令、首指令合法（push/mov/lea/xor 等）、结尾是 ret"过滤，即可把每个函数的候选密钥缩到 1~3 个。

## 原理

SMC 加密的对象是编译器生成的机器码，而合法 x86-64 函数有强结构先验：函数序言几乎只用 push/mov/sub/lea 等少数指令开头，中段不会出现 ud2（编译器仅在 UB/反调试处插入）、hlt/cli/in/out（内核态特权指令）、retf/cmpsd/lodsb（用户态编译器不会生成），且以 ret 收尾。单字节 XOR 的密钥空间只有字符集大小（本题 0-9a-zA-Z_ 共 63 个），逐候选解密+反汇编+规则过滤相当于用"编译器代码风格"当 Known-Plaintext 约束。附加已知明文：若部分函数保留最后一字节未加密（如 ret 0xC3），可用它对未知函数推密钥（密钥 = 0xC3 ^ 密文尾字节）。另一种辅助观察：密文中连续重复字节意味着对应明文字节与密钥相同（XOR 不变性质），可直接目测密钥。

## 触发条件

- 目标二进制存在 mprotect( RW )→XOR→mprotect( RX ) 的 SMC 循环，密钥为逐函数单字节且来自有限字符集；
- 加密数据（函数字节序列与长度表）可从 .data/.rodata 提取（IDA ida_bytes.get_qword/get_dword/get_byte 脚本化）；
- 密文函数长度 ≥ 数字节（太短约束不足）。

## 利用步骤

1. IDA 脚本提取函数指针数组 fun_list[50]、长度数组 xor_number_array[50]，按指针逐字节 dump 密文。
2. 对每个函数 i、每个候选字符 c：解密（注意若实现只加密前 len-1 字节，尾字节保持原样）→ Capstone `Cs(CS_ARCH_X86, CS_MODE_64)` 反汇编 → 校验首指令 ∈ {push,mov,sub,cmp,xor,lea,imul,...}、全程不含禁用指令、末条为 ret。
3. 通过筛选的候选即密钥候选；多候选时人工比对反汇编语义（如 `xor edi,0x2a; lea eax,[rdi+0x123]; ret` 合理 vs `mov es,[rax+riz-0x7ffcfcfe]` 段寄存器 load 明显非法）。
4. 无法满足约束的首函数用尾字节已知明文（ret）推：key = 0x73 ^ cipher[-1]。
5. 全部密钥按序拼接即输入/flag。

## PoC

无 PoC（Capstone 爆破脚本要点如上；原文验证：50 个函数中 48 个直接唯一/少量候选定位，Function 24 的 t/w 候选经语义对比取 t，配合尾字节推首函数得到完整 flag）。

## 变体与关联

- 变体：多字节 XOR 时可按滑动窗口逐位爆破（用同样反汇编约束）；密钥非字符集时可扩为全字节空间 256（约束不变）；非 SMC 的"按位异或加密代码段"提取还原同思路。
- 关联：花指令/指令替换还原（同目录，处理解密后的脏代码）；VM 保护还原（本题 SMC 之后接伪 VM 解释器，密钥恢复是进入 VM 分析的前置）。
- 检测/防御：SMC 本身即强特征（RWX 抖动、mprotect 频繁调用）——EDR 对 user-space mprotect→exec 序列告警；编译器层面无通用解，分析侧成本随密钥长度增长。

## 检测与防御

- 检测：进程内 mprotect 高频调用且区间在代码段、代码段页权限频繁 RW↔RX 切换、解密后内存执行（ ETW/EDR 内存扫描可对解密后代码做特征匹配）。
- 防御：服务端校验（拒绝不可信输入）、白盒密码/密钥分片提升 SMC 密钥恢复成本、反调试与完整性自检增加动态分析难度。
