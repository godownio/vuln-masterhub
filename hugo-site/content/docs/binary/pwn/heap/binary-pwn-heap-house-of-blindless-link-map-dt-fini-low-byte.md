---
id: binary-pwn-heap-house-of-blindless-link-map-dt-fini-low-byte
title: House of Blindless：无泄露相对写改 link_map，低位覆盖 DT_FINI 指针经 _dl_fini 调 system@plt
type: scenario
domain: binary
path: binary/pwn/heap
technique: house-of-blindless-link-map-dt-fini-low-byte
tags:
- pwn
- heap
- glibc
- link-map
- dl-fini
- exit
- arbitrary-write
- low-byte-overwrite
- brainfuck
- mmap
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V684
  verified_at: '2026-11-13T14:08:46+08:00'
  notes: 已对照原文与全部22图核对：无上限 malloc 触发 mmap 紧邻 libc/ld（img03 vmmap）、data=mmap_base+0x10、Brainfuck @/>/+/. 相对写语义、_rtld_global+2312(0x908) 写 /bin/sh（img07 显示 0x68732f2f6e69622f）、l_info[13] 指针 0xb8->0xa8 改指 DT_INIT（img13/14）、l_addr 低字节 0x00->0xe0 使 l_addr+0x1000=system@plt、l_info[26]=0 跳过 FINI_ARRAY、exit→__run_exit_handlers→_dl_fini 且 _dl_fini+555 call rax 时 rax=system@plt、rdi=_rtld_global+2312（img21）、最终 flag 回显（img22）均与原文一致；l_info 偏移(0x40 起/项 8 字节, [13]=+0xa8, [26]=+0x110)正确。修正卡内两处：删除无出处的『mov rdi, r15』表述，改为按截图可证的锁调用遗留 rdi；dt_load_lock 拼写改为 dl_load_lock。原文未显式标记受影响版本（仅测试环境 libc-2.31），不设 affected_versions；frontmatter 无 sources/source_url。dedup_review 成立：与同赛题 exit_hook 卡（改 _dl_rtld_lock_recursive、需 3 nibble 爆破）及 House of Banana（伪造 link_map 链走 DT_FINI_ARRAY、需泄露+large bin attack）目标字段与前置条件均不同，非同一利用链，均保留；dup-scan 无本篇 pair。exp 未本机复跑。
url: /docs/binary/pwn/heap/binary-pwn-heap-house-of-blindless-link-map-dt-fini-low-byte/
draft: false
kb_aliases:
- House of Blindless
- house_of_blindless
- 盲写 _dl_fini
- link_map DT_FINI 低位覆盖
- 无泄露 exit 劫持
- _rtld_global+2312
- WMCTF2023 blindless house of blindless
---

## 一句话结论

House of Blindless 是在**没有任何地址泄露**的前提下，利用“相对任意写”（示例为大块 `malloc` 触发 mmap、数据区紧邻 ld/libc，再用解释器指令做相对偏移写）修改 glibc 动态链接器里的主程序 `link_map`：把 `l->l_info[DT_FINI]` 指针低位改成指向 `DT_INIT` 的 `Elf64_Dyn`、把 `l->l_addr` 低位调整到 `system@plt - DT_INIT.d_ptr`、把 `l_info[DT_FINI_ARRAY]` 清零，并往 `_rtld_global+0x908` 写入 `/bin/sh`；程序正常 `exit()` 进入 `_dl_fini` 时即调用 `system("/bin/sh")`。全部修改都只动低位/相对偏移，因此不需要泄露 libc 或 PIE 基址，也不依赖 ASLR 爆破。

## 原理

- **`_dl_fini` 的 DT_FINI 调用链**：程序 `exit()` 或从 `main` 返回后走 `__libc_start_main → exit → __run_exit_handlers → _dl_fini`。`_dl_fini` 遍历 `link_map`，对 `l_init_called` 为真的对象检查：
  ```c
  if (l->l_info[DT_FINI_ARRAY] != NULL) { ... 调用 fini array ... }
  /* Next try the old-style destructor. */
  if (l->l_info[DT_FINI] != NULL)
      DL_CALL_DT_FINI (l, l->l_addr + l->l_info[DT_FINI]->d_un.d_ptr);
  ```
  最终调用地址由 `l->l_addr` 与 `l_info[DT_FINI]` 指向的 `Elf64_Dyn.d_un.d_ptr` 相加得到，二者都在可写的 ld 数据区/由攻击者可控，因此是劫持点。
- **link_map 就在可写的 ld 数据区**：`_rtld_global._dl_ns[0]._ns_loaded` 指向主程序的 `link_map`；其 `l_addr` 字段存放 PIE 基址，`l_info[12]`/`l_info[13]` 分别指向 `.dynamic` 中的 `DT_INIT`/`DT_FINI` 两个 `Elf64_Dyn`（x86-64 布局下 `l_info` 自 `link_map+0x40` 起、每项 8 字节，故 `l_info[13]` 在 `link_map+0xa8`、`l_info[26]` 在 `link_map+0x110`）。
- **低位覆盖（partial overwrite）**：`DT_INIT` 与 `DT_FINI` 两个 `Elf64_Dyn` 在 `.dynamic` 中相邻（示例 0x3da8 与 0x3db8），`l_info[13]` 存的是 `elf_base+0x3db8`。只改其最低字节 `0xb8→0xa8`，指针就改为指向 `DT_INIT` 的 `Elf64_Dyn`，其 `d_un.d_ptr = 0x1000`（示例二进制）。ASLR 只影响高位，低位覆盖后指针其余字节仍合法。
- **l_addr 低位微调**：`l_addr` 存 PIE 基址（页对齐，最低字节 0x00）。把 `link_map+0x0` 的最低字节改成 `0xe0`，则 `l_addr = elf_base+0xe0`。于是 `_dl_fini` 计算的调用地址 = `(elf_base+0xe0) + 0x1000 = elf_base+0x10e0`，正好是该 PIE 二进制自身的 `system@plt`（示例偏移 0x10e0）。因为目标是程序自己的 PLT，不需要 libc 基址。
- **为什么先清 DT_FINI_ARRAY**：`l_info[DT_FINI_ARRAY]`（`link_map+0x110`）原本非空，`_dl_fini` 会先走 array 分支，而 array 地址同样由 `l->l_addr + d_ptr` 计算——`l_addr` 已被改，算出的地址会错位崩溃；把它清零即可跳过 array 分支，直接进入 DT_FINI 分支。
- **rdi 的来源**：该 libc-2.31 构建的 `_dl_fini` 在进入 fini 循环前调用 `__rtld_lock_lock_recursive(GL(dl_load_lock))`，调试截图 `_dl_fini+113` 处可见 `lea rdi, [rip+...] <_rtld_global+2312>`（`_rtld_global+0x908` 即 `dl_load_lock` 字段）；到 DT_FINI 回调处（截图 `_dl_fini+555` 的 `call rax`）rdi 仍为该地址。把该地址内容写成 `/bin/sh\0`，回调 `system` 时 rdi 即指向该字符串。原文即以“控制 `_rtld_global+2312` 为 rdi”概括此点。
- **无泄露的原因**：mmap 大块数据区到 ld.so/libc 的相对距离在同一 libc/ld/内核与同样的分配大小下是常量（大块 mmap 自顶向下分配，固定落在 ld/libc 下方），可本地量出偏移；而 link_map 指针、l_info 指针、l_addr 中已含真实基址，只需改最低字节。整个利用只用相对偏移 + 低位覆盖，因此“blind”也能一次打通。
- **与 exit_hook 的区别**：exit_hook 改的是 `_rtld_global` 里的 `_dl_rtld_lock_recursive`/`_dl_rtld_unlock_recursive` 函数指针（需要知道 system 完整地址，常需爆破）；本技术改的是 `link_map` 的 `DT_FINI` 元数据并经 `l_addr+d_ptr` 计算目标，system 用 PLT 条目，无需泄露/爆破。

## 触发条件

- 存在**无泄露的相对任意写**：能对 ld/libc 区域按已知相对偏移写（示例为无上限 `malloc` 触发 mmap 得到紧邻 ld 的数据区，再用解释器 `@`/`>`/`+`/`.` 指令相对移动并逐字节写）。
- 程序能正常结束：显式调用 `exit()`，或由 `__libc_start_main` 启动且 `main` 可正常返回（必须经过 `__run_exit_handlers → _dl_fini`，不能是 `_exit`/`syscall`）。
- 目标 libc/ld 的 `_dl_fini` 实现、`link_map` 字段偏移（`l_info` 起始、`l_info[13]`/`l_info[26]` 位置）、`dl_load_lock` 相对 `_rtld_global` 的偏移与本地一致（示例为 glibc-2.31；不同版本需重新量偏移）。
- 二进制存在可利用的 `system@plt`（或其它满足 `l_addr + d_ptr` 计算的可调用地址）；`DT_INIT.d_ptr` 与目标函数偏移之差要能用低位覆盖表达（本例只差 `0xe0` 一个字节）。
- 大块 mmap 分配后的内存布局稳定（相同分配大小、无其他穿插映射）。

## 利用步骤

1. **本地量偏移**（同 libc/ld 环境）：启动程序，触发同样大小的 mmap 分配，gdb 中记录 `data`（示例 `mmap_base+0x10`）到下列目标的相对偏移：
   - `_rtld_global+0x908`（放 `/bin/sh` 的 rdi 目标，示例偏移 0x33d968）；
   - 主程序 `link_map` 起始（示例偏移 0x33e190）；
   - `link_map+0xa8`（`l_info[DT_FINI]` 指针）、`link_map+0x110`（`l_info[DT_FINI_ARRAY]`）。
2. **写 `/bin/sh`**：用相对写把 `/bin/sh\0` 写到 `_rtld_global+0x908`。
3. **改 `l_addr` 最低字节**：在 `link_map+0x0` 把 PIE 基址最低字节 `0x00` 改成 `0xe0`（使 `l_addr+d_ptr` 指向 `system@plt`）。
4. **改 `l_info[DT_FINI]` 最低字节**：在 `link_map+0xa8` 把指针 `elf_base+0x3db8` 的最低字节 `0xb8` 改成 `0xa8`，令其指向 `DT_INIT` 的 `Elf64_Dyn`（`d_un.d_ptr=0x1000`）。
5. **清 `l_info[DT_FINI_ARRAY]`**：在 `link_map+0x110` 写 8 字节 0。
6. **触发退出**：结束解释器输入/让 `main` 返回，进入 `_dl_fini`；实际调用 `system@plt`，rdi 指向 `/bin/sh`，获得 shell。
7. **调试断点**：在 `_dl_fini` 的 DT_FINI 调用处（示例 `_dl_fini+555` 的 `call rax`）与 `lea rdi, <_rtld_global+2312>` 处断下，核对 rax 是否为 `system@plt`、rdi 内容是否为 `/bin/sh`。

## PoC

原文针对 WMCTF2023 blindless 的 exp 核心（偏移按本地 libc/ld 与二进制重算；未在本机复跑）：

```python
def write(content):
    res = b''
    for i in range(len(content)):
        res += b'.' + p8(content[i]) + b'>'   # '.' 写 code[i+1]，'>' 使 data+=1
    return res

ru('size\n'); sl(str(0x100000))   # 超大 malloc -> mmap，data 紧邻 ld/libc
ru('size\n'); sl(str(0x100))
ru('code\n')

argv0         = 0x33d968          # _rtld_global+0x908 相对 mmap_base
l_addr        = 0x33e190          # 主程序 link_map 相对 mmap_base
dt_fini       = l_addr + 0xa8     # &l_info[DT_FINI]
dt_fini_array = l_addr + 0x110    # &l_info[DT_FINI_ARRAY]

payload  = b'@' + p32(argv0 - 0x10) + write(b'/bin/sh\x00')      # rdi 目标
payload += b'@' + p32(l_addr - argv0 - 8) + write(p8(0xe0))      # l_addr 低位 -> 0xe0
payload += b'@' + p32(dt_fini - l_addr - 1) + write(p8(0xa8))    # DT_FINI 指针低位 -> 0xa8
payload += b'@' + p32(dt_fini_array - dt_fini - 1) + write(p64(0))  # DT_FINI_ARRAY=0
payload += b'q'                                                    # 结束解释器 -> exit
sl(payload)
itr()
```

`executeBrainfuck` 的写原语：`@` 读 code 后 4 字节加到全局 `data` 指针（`data += *(uint*)(code+i+1)`，`i+=5`）；`>` 使 `data+=1`；`+` 使 `data+=8`；`.` 把 `code[i+1]` 写入 `*data`；`q` 结束循环。每写 1 字节 data 自动前移 1，因此偏移计算里要扣掉已写长度（如 `-8`、`-1`）。

## 变体与关联

- **House of Banana**（[[binary-pwn-heap-house-of-banana-link-map-dl-fini]]）：同样走 `exit → _dl_fini`，但它伪造整条 link_map 链并用 `DT_FINI_ARRAY` 调用任意函数指针，需要泄露 libc/堆地址并用 large bin attack 写入；本技术不伪造节点、不需要泄露，直接改真实 link_map 的 DT_FINI 元数据，二者触发条件与写原语完全不同。
- **exit_hook**（[[binary-pwn-format-string-exit-hook-rtld-global]]、[[binary-pwn-heap-exit-hook-onegadget-negative-size-arbitrary-write]]、[[binary-pwn-heap-wmctf2023-blindless-brainfuck-relative-write-exit-hook-bruteforce]]）：改 `_rtld_global` 锁函数指针；其中同一赛题的 blindless exit_hook 卡与本卡共享 mmap/Brainfuck 写原语，但最终劫持对象是锁函数指针并依赖 ASLR 爆破，本卡改为 DT_FINI 计算链，一次成型。
- **变体**：若 ELF 段也可写，可直接改 `l_info[DT_FINI]->d_un.d_ptr` 或 `.dynamic` 中 `DT_FINI` 的值，无需低位覆盖；若可改两个字节，可适应更大的 `system_offset - DT_INIT.d_ptr` 差值；也可选择其他 `Elf64_Dyn`（如 `DT_INIT_ARRAY` 等）组合出目标地址。
- **通用化**：任何“相对任意写 + 程序正常退出 + 目标 glibc 的 link_map 可写”的场景都可用；写原语不限 Brainfuck，任意堆越界/相对写均可。

## 检测与防御

- **加固**：使用会校验 `_dl_fini` 元数据/限制可写性的较新 glibc 并核对 `_dl_fini` 实现变化；CET/CFI 提高间接调用门槛；避免让 ld 数据区与用户可控的大块 mmap 分配形成固定相对布局（限制分配大小上限，禁止超大 malloc）。
- **程序侧**：校验 `malloc`/`readInt` 的 size 上限，禁止无界分配；解释器类组件对指针偏移与写指令做边界检查或沙箱化（源码审计把“data 指针可加减 + 任意写”视为高危原语）。
- **检测（CTF/样本）**：进程退出前对 ld/libc 区域（`_rtld_global`、主程序 `link_map`）的异常写入；超大 malloc 后紧跟大量 `@`/`.` 类相对写指令；`_dl_fini` 中 DT_FINI 调用目标落在主程序 PLT（而非正常 fini 函数）等异常迹象。
