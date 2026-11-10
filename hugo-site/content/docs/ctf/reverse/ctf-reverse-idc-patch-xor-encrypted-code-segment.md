---
id: ctf-reverse-idc-patch-xor-encrypted-code-segment
title: 按调用点反堆栈取异或键，用 IDC PatchByte 批量还原被 XOR 加密的代码段
type: scenario
domain: ctf
path: ctf/reverse
technique: idc-patch-xor-encrypted-code-segment
tags:
- ctf
- reverse
- ida
- idc
- patch
- xor
- self-decrypt
- code-segment
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W3
  verified_at: '2026-11-08T12:44:53+08:00'
  notes: 已对照原文核对；0x43/0x44 两个区间 PatchByte 地址(0x155f-0x176d、0x12cb-0x155f)与原文 IDC 脚本一致；confidence=medium 合理（反堆栈动机来自原文截图推断）；未运行 IDC 脚本
url: /docs/ctf/reverse/ctf-reverse-idc-patch-xor-encrypted-code-segment/
draft: false
kb_aliases:
- IDC PatchByte 还原代码段
- XOR 加密代码段还原
- 反堆栈取异或键
- 按区间原地解密
- 函数体恢复
---

## 一句话结论

样本把某个函数的机器码在静态文件里以「整段逐字节 XOR」的形式存储，运行时才由调用方先写入密钥再跳进去执行；逆向时不必模拟执行，只要在调用点回溯压栈/传参的常量（原文是反堆"函数调用前对栈的操作"）确定异或键，用 IDC 的 `PatchByte(addr+i, Byte(addr+i) ^ key)` 按已知字节区间原地还原，IDA 立刻能把这段从"垃圾字节"反编译成正常函数体，后续分析（以及爆破用的 patch）才有落点。

## 原理

- **静态密文 + 运行时解密**：样本里可见一堆看似随机的 `db` 字节（原文字节形态 `0B 0B 0B 0B 8D 87`、`FE BB BB BB` 等），入口处先有一条 `jmp` 到"解密桩"，或调用方在 `call` 之前把常量压栈/写寄存器，解密桩据此逐字节 XOR 回可执行代码。
- **密钥来自调用约定**：既然是"调用前先对栈操作"，那密钥一定能在调用点附近以立即数/常量形式读到；原文的做法是从调用点向上反推栈布局（`sub`/`add` 调整栈指针、`mov`/`push` 写常量），确定 XOR 键（本例为 0x43 与 0x44 两个区间用不同键）。
- **区间边界怎么定**：密文是连续的一段（原文 `0x12CB`→`0x155F`、`0x155F`→`0x176D`），边界可由 `jmp` 目标、`ret` 前的 `int 3`/`nop` 填充、或"解密后首字节应当是可识别的函数序言（`55 48 89 E5`/`sub rsp, X`）"来校验。
- **PatchByte 为何有效**：IDC 的 `PatchByte` 直接改 IDA 数据库里的字节，不修改原始文件；对"静态密文"这种目标，还原后 IDA 的自动分析/反编译会把该区间重新识别为代码，等价于"离线解密"，无需真正运行样本。
- **风险与校验**：区间/键错一个就会把可执行代码写成乱码；因此必须先 `GetManyBytes` dump 原始字节备份，再逐区间 patch，并立刻用 `create_insn`/反编译确认序言是否恢复。

## 触发条件

- 目标为 IDA 可加载的 PE/ELF，存在"静态为随机字节、运行时被解密"的函数段；
- 调用点能回溯出解密用的常量键（压栈/寄存器写入/紧邻的 `mov`）；
- 已知或可推断的区间起止（`jmp` 目标、填充、函数边界）；
- 需要在 IDA 里继续静态分析（或据此 patch 出可运行副本）。

## 利用步骤

1. 加载样本，定位入口处的 `jmp`/`call` 与"看起来是随机字节"的区间，记下候选起止地址。
2. 在调用点回溯：看 `sub rsp`/`add rsp`、`mov [rsp+X], imm`、`push imm` 等，找出写进解密逻辑的常量（原文得到 0x43、0x44 两个键）。
3. 先备份：`GetManyBytes(start, end-start, 0)` dump 到文件，便于出错回滚。
4. 用 IDC 按区间 patch：
   ```c
   #include <idc.idc>
   static main() {
       auto des = 0x176d, addr = 0x155f, i;
       for (i = 0; addr + i != des; ++i) PatchByte(addr + i, Byte(addr + i) ^ 0x43);
       des = 0x155f; addr = 0x12CB;
       for (i = 0; addr + i != des; ++i) PatchByte(addr + i, Byte(addr + i) ^ 0x44);
   }
   ```
5. 让 IDA 重新分析该区间（`create_insn` 或 `C`/`U` 后重定义），按 F5 反编译；若序言不对，换键或换边界重试。
6. 还原成功后即可继续分析校验逻辑（例如把失败分支 `exit(1)` patch 成 `exit(i)` 做返回码爆破）。

## PoC

```c
#include <idc.idc>

static main()
{
    auto des = 0x176d;
    auto addr = 0x155f;
    auto i;
    for (i = 0; addr + i != des; ++i) {
        PatchByte(addr + i, Byte(addr + i) ^ 0x43);
    }
}

static main2()
{
    auto des = 0x155f;
    auto addr = 0x12CB;
    auto i;
    for (i = 0; addr + i != des; ++i) {
        PatchByte(addr + i, Byte(addr + i) ^ 0x44);
    }
}
```

（地址与键按目标替换；两段用不同键时分别跑两次 `main`。）

## 变体与关联

- 变体：key 不是常量而是运行时算出来的（与文件名/时间/环境相关）时，需改为在调试器里到解密桩之后下断，dump 已解密内存再 patch 回 IDA（`rebase`/`patch_bytes` 批量导入）。
- 变体：解密不是纯 XOR 而是 `add`/`rol`/字节置换，则需按对应逆变换写 patch（与 UPX 自定义 VM 的 rol/xor/ror 求逆同类）。
- 变体：区间很长时用 IDAPython 批量 `ida_bytes.patch_bytes(addr, decrypted_bytes)` 一次写入，比逐字节 `PatchByte` 快。
- 关联：[[ctf-reverse-exit-code-index-oracle-byte-brute]]（本卡是它的前置步骤：先还原代码段，才能定位比较与 exit 并 patch）。
- 关联：[[ctf-reverse-upx-custom-vm-unreachable-decrypt-rol-xor-ror-inverse]]（同为"静态密文 + 运行时解密"，但那条要处理不可达解密路径的逆运算）。
- 关联：[[binary-pwn-sandbox-escape-python-generator-frame-builtins-recovery]]（无直接关系，仅提示"运行时才成立的状态需在运行态取"这一共性问题）。
- 边界：区间/键错会破坏 IDA 数据库（需先备份）；若解密依赖运行时状态无法静态复现，只能动态 dump；`PatchByte` 只改数据库不改文件，若要产出可执行 patched 样本需再 `ApplyPatchesToFile` 或另存。

## 检测与防御

- CTF/逆向：优先在调用点回溯常量键，比逐字节试错更快；patch 前先 dump 备份。
- 软件保护（防守视角）：静态密文 + 常量密钥只能抬高分析成本；更强的做法是把解密键与运行时状态绑定（环境、时间、校验和），并对代码段做完整性校验，防止离线 patch。
